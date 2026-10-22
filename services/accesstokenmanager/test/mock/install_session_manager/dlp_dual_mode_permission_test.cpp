/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// UT design principle: every case drives the grant/revoke chain through the
// service entries AccessTokenManagerService::GrantPermission /
// RevokePermission on a dual-mode DLP bundle (one bundle installed with a DLP
// clone in both DEFAULT_OR_MAIN_MODE and SUB_MODE), so the DLP type gate in
// UpdateTokenPermissionStateCheck, the same-mode clone sync
// (GetRelatedSandBoxHapList) and the cross-mode isolation are all covered on
// the real path. Each case asserts the three observable layers of one
// grant/revoke: the return code, the memory verify result (VerifyAccessToken)
// and the persisted db row (grant_state of the perm state table).

#include "dlp_dual_mode_permission_test.h"

#include <map>
#include <string>
#include <vector>

#define private public
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_manager_service.h"
#include "delete_bundle_manager.h"
#include "install_session_manager.h"
#undef private
#include "access_token.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "dlp_permission_set_manager.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "token_field_const.h"
#include "tokenid_attributes.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
// local aggregate of SignInfoQueryFlag: query every section in one call
constexpr uint32_t QUERY_ALL_SIGN_INFO = QUERY_PROFILE | QUERY_MODULE_INFO | QUERY_SHARED_FILES;
static constexpr int32_t TEST_USER_ID = 100;
// instIndex layout of one dual-mode bundle:
// main-mode original app 0 / main-mode clone app 1 (DLP or common);
// sub-mode original app 10000 / sub-mode clone app 10001 ([10000, 20000) is sub mode)
static constexpr int32_t MAIN_MODE_CLONE_INDEX = 1;
static constexpr int32_t SUB_MODE_MAIN_INDEX = 10000;
static constexpr int32_t SUB_MODE_CLONE_INDEX = 10001;
static std::shared_ptr<AccessTokenManagerService> atManagerService_;
static InstallSessionManager* g_installSessionManager = nullptr;
static std::map<std::string, std::string> g_modulePathMap;
// bundle names used by this suite, cleaned in SetUp for cross-case isolation
const std::vector<std::string> G_TEST_BUNDLES = {
    "DlpDualModeGrant001",
    "DlpDualModeGrant002",
    "DlpDualModeGrant003",
    "DlpDualModeGateRead004",
    "DlpDualModeGateFull004",
    "CommonCloneNoSync001",
};

// This branch folds the DeleteIdentity chain into DeleteBundleManager, so the
// former DeleteIdentityCore entry maps onto DeleteIdentityWithDfx.
int32_t DeleteIdentityCore(AccessTokenID tokenID, const std::string& bundleName,
    ReservedType reservedType, int32_t& sceneCode)
{
    DeleteDfxInfo deleteDfx = {};
    int32_t ret = DeleteBundleManager::GetInstance().DeleteIdentityWithDfx(
        tokenID, bundleName, reservedType, deleteDfx);
    sceneCode = deleteDfx.sceneCode;
    return ret;
}

BundlePolicy CommonBundlePolicy()
{
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    return bundlePolicy;
}

// Full four-stage install with an explicit install mode.
void InstallHapWithMode(const std::vector<std::string>& hapPaths, const HapBaseInfo& baseInfo,
    const BundlePolicy& bundlePolicy, Identity& identity, MultipleMode mode)
{
    BundleHapList hapList;
    hapList.hapPaths = hapPaths;
    hapList.isPreInstalled = false;
    hapList.userIdForEnterpriseSign = baseInfo.userID;
    identity.uid = -1;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, mode, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity.uid);
    EXPECT_NE(0, identity.tokenId);

    std::map<std::string, std::string> modulePathMap;
    for (auto& path : hapPaths) {
        modulePathMap[path] = path;
    }
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);
}

// Full four-stage install of one token with an explicit install mode.
AccessTokenID InstallAppWithMode(const std::string& path, const std::string& bundleName,
    int32_t userId, int32_t instIndex, MultipleMode mode)
{
    HapBaseInfo baseInfo;
    baseInfo.userID = userId;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = instIndex;
    Identity identity = {0, -1};
    InstallHapWithMode({path}, baseInfo, CommonBundlePolicy(), identity, mode);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    EXPECT_NE(INVALID_TOKENID, tokenId);
    return tokenId;
}

// Clone base info for the auto-session install path.
HapBaseInfo MakeCloneInfo(const std::string& bundleName, int32_t userId, int32_t instIndex)
{
    HapBaseInfo baseInfo;
    baseInfo.userID = userId;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = instIndex;
    return baseInfo;
}

// Install a token for the given (userId, bundleName, instIndex) via the auto
// session path (PrepareHapIdentity sessionId=0 + FinishInstall). Used for the
// DLP clones of an already installed bundle.
AccessTokenID InstallBundleCloneToken(const HapBaseInfo& baseInfo, const BundlePolicy& bundlePolicy)
{
    int32_t sessionId = 0;
    Identity identity = {0, -1};
    EXPECT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(
        sessionId, baseInfo, bundlePolicy, nullptr, identity));
    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    EXPECT_NE(INVALID_TOKENID, tokenId);
    return tokenId;
}

// The four tokens of one dual-mode DLP bundle: the original app and its DLP
// clone in both the main mode and the sub mode.
struct DualModeDlpBundle {
    AccessTokenID tokenMain;    // main-mode original app, instIndex 0
    AccessTokenID tokenDlpMain; // main-mode DLP app, instIndex 1
    AccessTokenID tokenSub;     // sub-mode original app, instIndex 10000
    AccessTokenID tokenDlpSub;  // sub-mode DLP app, instIndex 10001
};

// Install a full dual-mode DLP bundle: cam/mic are two user-grant permissions
// starting denied, so every grant/revoke below observes a real state change.
// Order matters: each DLP clone inherits the perm state of its mode-domain
// main app, so the main app of a mode must precede that mode's DLP clone.
DualModeDlpBundle InstallDualModeDlpBundle(const std::string& bundleName, DlpType dlpType)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic]/acl:[]/Module001/" + bundleName;
    BundlePolicy dlpPolicy = CommonBundlePolicy();
    dlpPolicy.dlpType = dlpType;

    DualModeDlpBundle bundle;
    bundle.tokenMain = InstallAppWithMode(path, bundleName, TEST_USER_ID, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);
    bundle.tokenDlpMain = InstallBundleCloneToken(
        MakeCloneInfo(bundleName, TEST_USER_ID, MAIN_MODE_CLONE_INDEX), dlpPolicy);
    bundle.tokenSub = InstallAppWithMode(path, bundleName, TEST_USER_ID, SUB_MODE_MAIN_INDEX,
        MultipleMode::SUB_MODE);
    bundle.tokenDlpSub = InstallBundleCloneToken(
        MakeCloneInfo(bundleName, TEST_USER_ID, SUB_MODE_CLONE_INDEX), dlpPolicy);

    // sanity of the dual-mode DLP layout: the dlp flag sits on both DLP
    // tokens, never on the mode-domain original apps
    EXPECT_EQ(1, TokenIDAttributes::GetTokenIdDlpFlag(bundle.tokenDlpMain));
    EXPECT_EQ(1, TokenIDAttributes::GetTokenIdDlpFlag(bundle.tokenDlpSub));
    EXPECT_EQ(0, TokenIDAttributes::GetTokenIdDlpFlag(bundle.tokenMain));
    EXPECT_EQ(0, TokenIDAttributes::GetTokenIdDlpFlag(bundle.tokenSub));
    return bundle;
}

// The four tokens of one dual-mode clone bundle: the mode-domain main app and
// its clone (instIndex != 0, non-DLP) in both modes. The clone is the control
// group of the DLP clone: same index layout, no dlp flag.
struct DualModeCloneBundle {
    AccessTokenID tokenMain;      // main-mode original app, instIndex 0
    AccessTokenID tokenCloneMain; // main-mode clone app, instIndex 1
    AccessTokenID tokenSub;       // sub-mode original app, instIndex 10000
    AccessTokenID tokenCloneSub;  // sub-mode clone app, instIndex 10001
};

// Install a full dual-mode clone bundle. A non-DLP clone initializes its
// permission list from the sign info (not from the main app), so every token
// starts with cam/mic denied and each grant below is a fresh state change.
DualModeCloneBundle InstallDualModeCloneBundle(const std::string& bundleName)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic]/acl:[]/Module001/" + bundleName;
    BundlePolicy clonePolicy = CommonBundlePolicy();

    DualModeCloneBundle bundle;
    bundle.tokenMain = InstallAppWithMode(path, bundleName, TEST_USER_ID, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);
    bundle.tokenCloneMain = InstallBundleCloneToken(
        MakeCloneInfo(bundleName, TEST_USER_ID, MAIN_MODE_CLONE_INDEX), clonePolicy);
    bundle.tokenSub = InstallAppWithMode(path, bundleName, TEST_USER_ID, SUB_MODE_MAIN_INDEX,
        MultipleMode::SUB_MODE);
    bundle.tokenCloneSub = InstallBundleCloneToken(
        MakeCloneInfo(bundleName, TEST_USER_ID, SUB_MODE_CLONE_INDEX), clonePolicy);

    // sanity of the dual-mode clone layout: the clone flag sits on both clone
    // tokens (index != 0), never on the mode-domain main apps; no token
    // carries the dlp flag
    EXPECT_EQ(1, TokenIDAttributes::GetTokenIdCloneFlag(bundle.tokenCloneMain));
    EXPECT_EQ(1, TokenIDAttributes::GetTokenIdCloneFlag(bundle.tokenCloneSub));
    EXPECT_EQ(0, TokenIDAttributes::GetTokenIdCloneFlag(bundle.tokenMain));
    EXPECT_EQ(0, TokenIDAttributes::GetTokenIdCloneFlag(bundle.tokenSub));
    EXPECT_EQ(0, TokenIDAttributes::GetTokenIdDlpFlag(bundle.tokenCloneMain));
    EXPECT_EQ(0, TokenIDAttributes::GetTokenIdDlpFlag(bundle.tokenCloneSub));
    return bundle;
}

// Grant state of one (tokenId, permissionName) row of the perm state table;
// -1 when the row is absent, so callers assert != PERMISSION_GRANTED for a
// denied expectation regardless of the row's presence.
int32_t QueryPermGrantState(AccessTokenID tokenId, const std::string& permissionName)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    condition.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
    std::vector<GenericValues> rows;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition, rows));
    if (rows.size() != 1) {
        return -1;
    }
    return rows[0].GetInt(TokenFiledConst::FIELD_GRANT_STATE);
}

void CleanAllTestData()
{
    for (const auto& bundleName : G_TEST_BUNDLES) {
        int32_t sceneCode = 0;
        DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode);
    }
}
} // namespace

void DlpDualModePermissionTest::SetUpTestCase()
{
    atManagerService_ = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    g_installSessionManager = &InstallSessionManager::GetInstance();

    uint32_t nativeSize = 0;
    uint32_t pefDefSize = 0;
    uint32_t dlpSize = 0;
    AccessTokenInfoManager::GetInstance().Init(nativeSize, pefDefSize, dlpSize);
    g_installSessionManager->SetMigrationDone();
    AccessTokenIDManager::GetInstance().SetMigrationDone();
}

void DlpDualModePermissionTest::TearDownTestCase()
{
    g_installSessionManager = nullptr;
    DelayedSingleton<AccessTokenManagerService>::DestroyInstance();
    atManagerService_ = nullptr;
}

void DlpDualModePermissionTest::SetUp()
{
    CleanAllTestData();
}

void DlpDualModePermissionTest::TearDown()
{
    // Clean up session cache
    std::vector<int32_t> sessionList;
    for (auto it : g_installSessionManager->sessionToInstallCache) {
        sessionList.emplace_back(it.first);
    }
    for (auto session : sessionList) {
        g_installSessionManager->FinishInstall(session, false, g_modulePathMap);
    }
}

/**
 * @tc.name: DlpDualModeGrantRevokeTest001
 * @tc.desc: Grant/Revoke on the main-mode DLP app: the grant succeeds, syncs
 *           to the same-mode original app in both cache and db row, and never
 *           crosses into the sub mode; the revoke mirrors the grant.
 * @tc.type: FUNC
 */
HWTEST_F(DlpDualModePermissionTest, DlpDualModeGrantRevokeTest001, TestSize.Level1)
{
    std::string bundleName = "DlpDualModeGrant001";
    DualModeDlpBundle bundle = InstallDualModeDlpBundle(bundleName, DLP_FULL_CONTROL);

    // every token starts with CAMERA denied (user-grant permission)
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenDlpMain, "ohos.permission.CAMERA"));

    // grant on the main-mode DLP app: succeeds ...
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        bundle.tokenDlpMain, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    // ... reaches the DLP app and its same-mode original app (cache + db row) ...
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenDlpMain, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenMain, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_GRANTED, QueryPermGrantState(bundle.tokenDlpMain, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_GRANTED, QueryPermGrantState(bundle.tokenMain, "ohos.permission.CAMERA"));
    // ... and never crosses into the sub mode (state + db rows)
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenSub, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenDlpSub, "ohos.permission.CAMERA"));
    EXPECT_NE(PERMISSION_GRANTED, QueryPermGrantState(bundle.tokenSub, "ohos.permission.CAMERA"));
    EXPECT_NE(PERMISSION_GRANTED, QueryPermGrantState(bundle.tokenDlpSub, "ohos.permission.CAMERA"));

    // revoke on the main-mode DLP app mirrors the grant: both same-mode tokens lose it
    ASSERT_EQ(ERR_OK, atManagerService_->RevokePermission(
        bundle.tokenDlpMain, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM, false));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenDlpMain, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenMain, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_DENIED, QueryPermGrantState(bundle.tokenDlpMain, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_DENIED, QueryPermGrantState(bundle.tokenMain, "ohos.permission.CAMERA"));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: DlpDualModeGrantRevokeTest002
 * @tc.desc: Grant/Revoke on the sub-mode DLP app: the grant syncs to the
 *           sub-mode original app only and leaves both main-mode tokens
 *           untouched; the revoke mirrors the grant.
 * @tc.type: FUNC
 */
HWTEST_F(DlpDualModePermissionTest, DlpDualModeGrantRevokeTest002, TestSize.Level1)
{
    std::string bundleName = "DlpDualModeGrant002";
    DualModeDlpBundle bundle = InstallDualModeDlpBundle(bundleName, DLP_FULL_CONTROL);

    // grant on the sub-mode DLP app: succeeds and syncs inside the sub mode
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        bundle.tokenDlpSub, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenDlpSub, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenSub, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_GRANTED, QueryPermGrantState(bundle.tokenDlpSub, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_GRANTED, QueryPermGrantState(bundle.tokenSub, "ohos.permission.CAMERA"));

    // main-mode tokens keep the denied state and their db rows
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenMain, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenDlpMain, "ohos.permission.CAMERA"));
    EXPECT_NE(PERMISSION_GRANTED, QueryPermGrantState(bundle.tokenMain, "ohos.permission.CAMERA"));
    EXPECT_NE(PERMISSION_GRANTED, QueryPermGrantState(bundle.tokenDlpMain, "ohos.permission.CAMERA"));

    // revoke on the sub-mode DLP app: both sub-mode tokens lose it
    ASSERT_EQ(ERR_OK, atManagerService_->RevokePermission(
        bundle.tokenDlpSub, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM, false));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenDlpSub, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenSub, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_DENIED, QueryPermGrantState(bundle.tokenDlpSub, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_DENIED, QueryPermGrantState(bundle.tokenSub, "ohos.permission.CAMERA"));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: DlpDualModeGrantRevokeTest003
 * @tc.desc: Reverse sync direction: granting/revoking on the mode-domain
 *           original app reaches that mode's DLP clone only (main mode via
 *           CAMERA, sub mode via MICROPHONE), so both directions of the
 *           "dlp app <-> main app" sharing rule are observed in both modes.
 * @tc.type: FUNC
 */
HWTEST_F(DlpDualModePermissionTest, DlpDualModeGrantRevokeTest003, TestSize.Level1)
{
    std::string bundleName = "DlpDualModeGrant003";
    DualModeDlpBundle bundle = InstallDualModeDlpBundle(bundleName, DLP_FULL_CONTROL);

    // main-mode direction: grant on the main app reaches the main-mode DLP app only
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        bundle.tokenMain, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenMain, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenDlpMain, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_GRANTED, QueryPermGrantState(bundle.tokenDlpMain, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenDlpSub, "ohos.permission.CAMERA"));

    // sub-mode direction: grant on the sub app reaches the sub-mode DLP app only
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        bundle.tokenSub, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenSub, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenDlpSub, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PERMISSION_GRANTED, QueryPermGrantState(bundle.tokenDlpSub, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenDlpMain, "ohos.permission.MICROPHONE"));

    // revoke on each original app drops the same permission on its DLP clone
    ASSERT_EQ(ERR_OK, atManagerService_->RevokePermission(
        bundle.tokenMain, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM, false));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenMain, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenDlpMain, "ohos.permission.CAMERA"));
    ASSERT_EQ(ERR_OK, atManagerService_->RevokePermission(
        bundle.tokenSub, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM, false));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenSub, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenDlpSub, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PERMISSION_DENIED, QueryPermGrantState(bundle.tokenDlpSub, "ohos.permission.MICROPHONE"));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: DlpDualModeGrantRevokeTest004
 * @tc.desc: The DLP type gate of the grant/revoke chain: a full-control-only
 *           DLP permission (dlpMode injected as DLP_PERM_FULL_CONTROL) is
 *           rejected with ERR_IDENTITY_CHECK_FAILED on the DLP_READ app in
 *           both modes - the failed grant changes no state and syncs nothing -
 *           while the DLP_FULL_CONTROL app passes the gate in both modes and
 *           syncs as usual. The shared check also guards the revoke direction.
 * @tc.type: FUNC
 */
HWTEST_F(DlpDualModePermissionTest, DlpDualModeGrantRevokeTest004, TestSize.Level1)
{
    // MICROPHONE becomes a full-control-only DLP permission for this process
    PermissionDlpMode restrictedPerm;
    restrictedPerm.permissionName = "ohos.permission.MICROPHONE";
    restrictedPerm.dlpMode = DLP_PERM_FULL_CONTROL;
    std::vector<PermissionDlpMode> dlpPerms = { restrictedPerm };
    DlpPermissionSetManager::GetInstance().ProcessDlpPermInfos(dlpPerms);

    std::string readBundleName = "DlpDualModeGateRead004";
    std::string fullBundleName = "DlpDualModeGateFull004";
    DualModeDlpBundle readBundle = InstallDualModeDlpBundle(readBundleName, DLP_READ);
    DualModeDlpBundle fullBundle = InstallDualModeDlpBundle(fullBundleName, DLP_FULL_CONTROL);

    // the gate rejects the restricted permission on the DLP_READ app in both modes
    EXPECT_EQ(AccessTokenError::ERR_IDENTITY_CHECK_FAILED, atManagerService_->GrantPermission(
        readBundle.tokenDlpMain, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM));
    EXPECT_EQ(AccessTokenError::ERR_IDENTITY_CHECK_FAILED, atManagerService_->GrantPermission(
        readBundle.tokenDlpSub, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM));
    // the failed grant changed no state and synced nothing
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(readBundle.tokenDlpMain, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(readBundle.tokenDlpSub, "ohos.permission.MICROPHONE"));
    EXPECT_NE(PERMISSION_GRANTED, QueryPermGrantState(readBundle.tokenDlpMain, "ohos.permission.MICROPHONE"));
    EXPECT_NE(PERMISSION_GRANTED, QueryPermGrantState(readBundle.tokenMain, "ohos.permission.MICROPHONE"));
    EXPECT_NE(PERMISSION_GRANTED, QueryPermGrantState(readBundle.tokenDlpSub, "ohos.permission.MICROPHONE"));
    EXPECT_NE(PERMISSION_GRANTED, QueryPermGrantState(readBundle.tokenSub, "ohos.permission.MICROPHONE"));

    // the same shared check guards the revoke direction (documented behavior)
    EXPECT_EQ(AccessTokenError::ERR_IDENTITY_CHECK_FAILED, atManagerService_->RevokePermission(
        readBundle.tokenDlpMain, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM, false));

    // the full-control DLP type passes the gate in both modes and syncs as usual
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        fullBundle.tokenDlpMain, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(fullBundle.tokenDlpMain, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(fullBundle.tokenMain, "ohos.permission.MICROPHONE"));
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        fullBundle.tokenDlpSub, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(fullBundle.tokenDlpSub, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(fullBundle.tokenSub, "ohos.permission.MICROPHONE"));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, readBundleName, ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, fullBundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: CommonClonePermNoSyncTest001
 * @tc.desc: Control group of the DLP clone sync: a non-DLP app whose
 *           instIndex is not 0 (a clone) manages its permissions
 *           independently in both modes - the clone's own sync list is empty
 *           and the clone is excluded from the main app's sync list, so
 *           grant/revoke on either side never crosses over (the DLP clone
 *           of the same index layout syncs instead, see Test001-003).
 * @tc.type: FUNC
 */
HWTEST_F(DlpDualModePermissionTest, CommonClonePermNoSyncTest001, TestSize.Level1)
{
    std::string bundleName = "CommonCloneNoSync001";
    DualModeCloneBundle bundle = InstallDualModeCloneBundle(bundleName);

    // the clone's own sync list is empty in both modes (non-DLP, index != 0)
    std::vector<AccessTokenID> relatedOfClone;
    AccessTokenInfoManager::GetInstance().GetRelatedSandBoxHapList(bundle.tokenCloneMain, relatedOfClone);
    EXPECT_TRUE(relatedOfClone.empty());
    relatedOfClone.clear();
    AccessTokenInfoManager::GetInstance().GetRelatedSandBoxHapList(bundle.tokenCloneSub, relatedOfClone);
    EXPECT_TRUE(relatedOfClone.empty());

    // main mode: grant on the clone changes the clone only - the same-mode
    // main app keeps the denied state in cache and db row
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        bundle.tokenCloneMain, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenCloneMain, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenMain, "ohos.permission.CAMERA"));
    EXPECT_NE(PERMISSION_GRANTED, QueryPermGrantState(bundle.tokenMain, "ohos.permission.CAMERA"));

    // main mode: grant on the main app never reaches the clone (mic untouched)
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        bundle.tokenMain, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenMain, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenCloneMain, "ohos.permission.MICROPHONE"));
    EXPECT_NE(PERMISSION_GRANTED, QueryPermGrantState(bundle.tokenCloneMain, "ohos.permission.MICROPHONE"));

    // sub mode mirrors both directions: grant on the sub clone stays local ...
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        bundle.tokenCloneSub, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenCloneSub, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenSub, "ohos.permission.CAMERA"));
    // ... and grant on the sub app never reaches the sub clone
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        bundle.tokenSub, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenSub, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenCloneSub, "ohos.permission.MICROPHONE"));

    // cross-mode isolation: the main-mode states survive all sub-mode operations
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenCloneMain, "ohos.permission.CAMERA"));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenMain, "ohos.permission.MICROPHONE"));

    // revoke no-sync (main mode): both sides hold an independent mic grant;
    // dropping the main app's mic leaves the clone's own grant untouched
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        bundle.tokenCloneMain, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM));
    ASSERT_EQ(ERR_OK, atManagerService_->RevokePermission(
        bundle.tokenMain, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM, false));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenMain, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenCloneMain, "ohos.permission.MICROPHONE"));
    // dropping the clone's grants stays local as well
    ASSERT_EQ(ERR_OK, atManagerService_->RevokePermission(
        bundle.tokenCloneMain, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM, false));
    ASSERT_EQ(ERR_OK, atManagerService_->RevokePermission(
        bundle.tokenCloneMain, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM, false));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenCloneMain, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenCloneMain, "ohos.permission.CAMERA"));

    // revoke no-sync (sub mode): the sub clone keeps its own mic grant while
    // the sub app's mic drops, then the sub clone's grants drop locally too
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        bundle.tokenCloneSub, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM));
    ASSERT_EQ(ERR_OK, atManagerService_->RevokePermission(
        bundle.tokenSub, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM, false));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenSub, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(bundle.tokenCloneSub, "ohos.permission.MICROPHONE"));
    ASSERT_EQ(ERR_OK, atManagerService_->RevokePermission(
        bundle.tokenCloneSub, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM, false));
    ASSERT_EQ(ERR_OK, atManagerService_->RevokePermission(
        bundle.tokenCloneSub, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM, false));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenCloneSub, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(bundle.tokenCloneSub, "ohos.permission.CAMERA"));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
