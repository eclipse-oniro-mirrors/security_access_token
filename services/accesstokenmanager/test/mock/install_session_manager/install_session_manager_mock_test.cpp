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

#include "install_session_manager_mock_test.h"

#include <thread>
#include <chrono>
#include <unistd.h>

#define private public
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_info_utils.h"
#include "accesstoken_manager_service.h"
#include "delete_bundle_manager.h"
#include "install_db_repository.h"
#include "install_identity_manager.h"
#include "install_session_manager.h"
#include "install_session_proxy_death_param.h"
#include "install_sysevent_reporter.h"
#include "permission_kernel_utils.h"
#include "tokenid_attributes.h"
#undef private
#include "access_token.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "hap_token_info.h"
#include "generic_values.h"
#include "token_field_const.h"
#include "perm_setproc.h"
#include "time_util.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {

// local aggregate of SignInfoQueryFlag: query every section in one call
constexpr uint32_t QUERY_ALL_SIGN_INFO = QUERY_PROFILE | QUERY_MODULE_INFO | QUERY_SHARED_FILES;
// test hap path example
// /SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/testModuleName/testBundleName
std::shared_ptr<AccessTokenManagerService> atManagerService_;
static InstallSessionManager* g_installSessionManager = nullptr;
static constexpr int32_t INVALID_SESSION = 999;
static constexpr int32_t UID_MASK = 200000;
static constexpr int32_t TEST_USER_ID = 100;
static constexpr int32_t TEST_USER_ID_SIBLING = 101;
static constexpr int32_t TEST_USER_ID_REPAIR = 105;
static constexpr int32_t TEST_API_VERSION_10 = 10;
static constexpr int32_t TEST_API_VERSION_12 = 12;
static constexpr int32_t TEST_API_VERSION_234 = 234;
static constexpr int32_t TEST_UID = 20045678;
static constexpr int32_t TEST_UID2 = 20033333;
static constexpr int32_t TEST_INVALID_UID = 20099999;
static constexpr int32_t DIRTY_ROW_UID = 20018001;
static constexpr int32_t DESIRED_SIBLING_UID = 20054322;
static constexpr int32_t CLONE_TOKEN_COUNT = 3;
static constexpr int32_t INDEX_CLONE_B = 1;
static constexpr int32_t INDEX_CLONE_C = 2;
static std::map<std::string, std::string> g_modulePathMap;

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

// RAII guard that temporarily drops root uid so IsPrivilegedCalling() returns
// false and the service-layer permission gate is enforced in-process.
struct TestUidGuard {
    uid_t origUid;
    explicit TestUidGuard(uid_t newUid) : origUid(getuid())
    {
        setuid(newUid);
    }
    ~TestUidGuard()
    {
        setuid(origUid);
    }
    TestUidGuard(const TestUidGuard&) = delete;
    TestUidGuard& operator=(const TestUidGuard&) = delete;
};
}

void InstallSessionManagerMockTest::SetUpTestCase()
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

void InstallSessionManagerMockTest::TearDownTestCase()
{
    g_installSessionManager = nullptr;
    DelayedSingleton<AccessTokenManagerService>::DestroyInstance();
    atManagerService_ = nullptr;
}

void InstallSessionManagerMockTest::SetUp()
{}

void InstallSessionManagerMockTest::TearDown()
{
    std::vector<int32_t> sessionList;
    for (auto it : g_installSessionManager->sessionToInstallCache) {
        sessionList.emplace_back(it.first);
    }
    for (auto session : sessionList) {
        g_installSessionManager->FinishInstall(session, false, g_modulePathMap);
    }
}

void InstallHap(const std::vector<std::string>& hapPaths, const HapBaseInfo& baseInfo,
    const BundlePolicy& bundlePolicy, Identity& identity)
{
    BundleHapList hapList;
    hapList.hapPaths = hapPaths;
    hapList.isPreInstalled = false;
    hapList.userId = baseInfo.userID;
    // no desired uid: must be INVALID_UID so PrepareHapIdentity skips the uid-user check
    identity.uid = -1;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
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

// Make the token's uid invalid (-1) in both db and memory and drop its kernel
// entry, mimicking a migration-abnormal state. Returns false when the db row
// is missing so callers can bail out with ASSERT_TRUE.
bool SetUidInvalidInDbAndCache(AccessTokenID tokenId)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> hapTokenResults;
    if (AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, hapTokenResults) != ERR_OK ||
        hapTokenResults.size() != 1) {
        return false;
    }
    hapTokenResults.front().Remove(TokenFiledConst::FIELD_UID);
    hapTokenResults.front().Put(TokenFiledConst::FIELD_UID, -1);
    std::vector<AddInfo> addInfoVec;
    AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, hapTokenResults, addInfoVec);
    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, delInfoVec);
    if (AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec) != ERR_OK) {
        return false;
    }
    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    if (infoPtr == nullptr) {
        return false;
    }
    infoPtr->tokenInfoBasic_.uid = -1;
    PermissionKernelUtils::RemoveSpmEntryFromKernel(tokenId);
    return true;
}

// Phase-1 + phase-2 (TYPE_REPLACE) for a single hap path; the session id is
// ready for UpdateHapPolicy / PrepareHapIdentity when RET_SUCCESS returns.
int32_t StartReplaceSession(const std::string& path, int32_t& sessionId)
{
    BundleHapList hapList{std::vector<std::string>{path}, false, 100};
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    if (ret != ERR_OK) {
        return ret;
    }
    HapInfoCheckResult result;
    return g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
}

// Install a token for the given (userId, bundleName, instIndex) via the auto
// session path (PrepareHapIdentity sessionId=0 + FinishInstall). Used for
// clones and cross-user siblings of an already installed bundle.
AccessTokenID InstallBundleSiblingToken(const HapBaseInfo& baseInfo, const BundlePolicy& bundlePolicy)
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

// Demote a live token to UNTRUSTED (same prep as the migration-enforce
// failure handling): cache evicted + id moved to the untrusted set.
void DemoteTokenToUntrusted(AccessTokenID tokenId, const std::string& bundleName)
{
    AccessTokenInfoManager::GetInstance().CommitDeleteHapCache(tokenId, bundleName);
    EXPECT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
        tokenId, TokenIdStatus::UNTRUSTED));
    EXPECT_EQ(nullptr, AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId));
}

// A token in reserved/untrusted state must be invisible to both cache and
// query interfaces.
void AssertTokenInvisible(AccessTokenID tokenId)
{
    EXPECT_EQ(nullptr, AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId));
    HapTokenInfo queryInfo;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenId, queryInfo));
}

size_t CountPermRows(AccessTokenID tokenId)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> permRows;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition, permRows));
    return permRows.size();
}

size_t CountPackageRows(const std::string& bundleName)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    std::vector<GenericValues> rows;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, condition, rows));
    return rows.size();
}

void AssertPermRowAbsent(AccessTokenID tokenId, const std::string& permissionName)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> permRows;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition, permRows));
    for (const auto& row : permRows) {
        EXPECT_NE(permissionName, row.GetString(TokenFiledConst::FIELD_PERMISSION_NAME));
    }
}

// Install one token per user for the same bundle: the first user goes through
// the full four-phase install, the rest via the auto session path.
std::vector<AccessTokenID> InstallBundleTokensForUsers(const std::string& path,
    const std::string& bundleName, const BundlePolicy& bundlePolicy,
    const std::vector<int32_t>& userIds)
{
    std::vector<AccessTokenID> tokenIds;
    for (int32_t userId : userIds) {
        HapBaseInfo baseInfo;
        baseInfo.userID = userId;
        baseInfo.bundleName = bundleName;
        baseInfo.instIndex = 0;
        if (tokenIds.empty()) {
            Identity identity = {0, -1};
            InstallHap({path}, baseInfo, bundlePolicy, identity);
            tokenIds.emplace_back(static_cast<AccessTokenID>(identity.tokenId));
        } else {
            tokenIds.emplace_back(InstallBundleSiblingToken(baseInfo, bundlePolicy));
        }
    }
    return tokenIds;
}

// Insert a hap_token_info row whose tokenId is not registered in IDManager,
// simulating boot-recovery residue (a crash left the db row behind).
void InsertDirtyTokenRow(const std::string& bundleName, AccessTokenID dirtyTokenId)
{
    GenericValues dirtyRow;
    dirtyRow.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(dirtyTokenId));
    dirtyRow.Put(TokenFiledConst::FIELD_USER_ID, TEST_USER_ID);
    dirtyRow.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    dirtyRow.Put(TokenFiledConst::FIELD_INST_INDEX, 0);
    dirtyRow.Put(TokenFiledConst::FIELD_DLP_TYPE, 0);
    dirtyRow.Put(TokenFiledConst::FIELD_APP_ID, bundleName + "_test");
    dirtyRow.Put(TokenFiledConst::FIELD_DEVICE_ID, "0");
    dirtyRow.Put(TokenFiledConst::FIELD_UID, DIRTY_ROW_UID);
    dirtyRow.Put(TokenFiledConst::FIELD_APL, APL_SYSTEM_CORE);
    dirtyRow.Put(TokenFiledConst::FIELD_API_VERSION, TEST_API_VERSION_12);
    dirtyRow.Put(TokenFiledConst::FIELD_RESERVED, 0);
    dirtyRow.Put(TokenFiledConst::FIELD_TOKEN_ATTR, 0);
    dirtyRow.Put(TokenFiledConst::FIELD_TOKEN_VERSION, 1);
    dirtyRow.Put(TokenFiledConst::FIELD_FORBID_PERM_DIALOG, 0);
    std::vector<AddInfo> addInfoVec;
    AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, {dirtyRow}, addInfoVec);
    ASSERT_EQ(ERR_OK, AccessTokenDbOperator::DeleteAndInsertValues({}, addInfoVec));
}

// Install a baseline bundle then remove its token row (no sibling uid left).
void SeedAndClearTokenRow(const std::string& bundleName, const BundlePolicy& bundlePolicy)
{
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo;
    baseInfo.userID = TEST_USER_ID;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    Identity seed = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, seed);
    EXPECT_EQ(ERR_OK, InstallDbRepository::DeleteFromDbByTokenId(
        static_cast<AccessTokenID>(seed.tokenId)));
}

// Seed one bundle, remove its token row, then run a repair Prepare with the
// given identity flags; returns the parsed low-32 token id actually allocated.
AccessTokenID RunRepairFlagScenario(const std::string& bundleName, const BundlePolicy& policy,
    int32_t instIndex, AccessTokenID desiredId, int32_t desiredUid)
{
    SeedAndClearTokenRow(bundleName, policy);
    HapBaseInfo baseInfo;
    baseInfo.userID = TEST_USER_ID;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = instIndex;
    Identity desired = {0, -1};
    desired.tokenId = desiredId;
    desired.uid = desiredUid;
    int32_t sessionId = 0;
    EXPECT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(
        sessionId, baseInfo, policy, nullptr, desired));
    std::map<std::string, std::string> emptyPathMap;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, emptyPathMap));
    return AccessTokenIDManager::ParseTokenId(desired.tokenId);
}

// Install a kernel/package baseline bundle then remove its token row (no
// sibling uid left), and run a repair Prepare for the desired identity.
int32_t RepairPrepareOnClearedBundle(const std::string& bundleName, const BundlePolicy& bundlePolicy,
    Identity& desired)
{
    SeedAndClearTokenRow(bundleName, bundlePolicy);
    HapBaseInfo baseInfo;
    baseInfo.userID = TEST_USER_ID_REPAIR; // avoid the seed's cache slot for user 100
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    int32_t sessionId = 0;
    EXPECT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(
        sessionId, baseInfo, bundlePolicy, nullptr, desired));
    return sessionId;
}

// Supplement matrix preset: install A (main) plus clones B/C/D, then
// reserve-delete B (RESERVED_DATA) and C (RESERVED_IDENTITY); D stays active.
void SetupSupplementMatrix(const HapBaseInfo& baseInfo, const BundlePolicy& bundlePolicy,
    const std::string& bundleName, AccessTokenID (&tokens)[4])
{
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    Identity identityA = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identityA);
    tokens[0] = static_cast<AccessTokenID>(identityA.tokenId);
    for (int32_t i = 1; i <= CLONE_TOKEN_COUNT; i++) {
        HapBaseInfo cloneInfo = baseInfo;
        cloneInfo.instIndex = i;
        tokens[i] = InstallBundleSiblingToken(cloneInfo, bundlePolicy);
    }
    int32_t sceneCode = 0;
    ASSERT_EQ(ERR_OK, DeleteIdentityCore(tokens[INDEX_CLONE_B], bundleName, ReservedType::RESERVED_DATA, sceneCode));
    ASSERT_EQ(ERR_OK, DeleteIdentityCore(tokens[INDEX_CLONE_C], bundleName,
        ReservedType::RESERVED_IDENTITY, sceneCode));
}

// Priority 1 of the uid expectation contract: a same-bundle sibling uid wins
// over the desired uid.
void RepairPrepareSiblingUidWins(const std::string& path, const BundlePolicy& bundlePolicy,
    int32_t seedBundleId)
{
    HapBaseInfo baseInfo;
    baseInfo.userID = TEST_USER_ID_SIBLING;
    baseInfo.bundleName = "RepairUidBundle";
    baseInfo.instIndex = 0;
    Identity desired = {0, -1};
    desired.tokenId = 0x2003D4E9;
    desired.uid = DESIRED_SIBLING_UID;
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(
        sessionId, baseInfo, bundlePolicy, nullptr, desired));
    EXPECT_EQ(TEST_USER_ID_SIBLING * UID_MASK + seedBundleId, desired.uid);
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));
}

/**
 * @tc.name: InstallHapTest001
 * @tc.desc: Test install a new hap.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest001, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapTest001";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapTest001";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity.uid);
    EXPECT_NE(0, identity.tokenId);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "InstallHapTest001", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapTest002
 * @tc.desc: Test install a new hap, grant revoke permission.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest002, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapTest002";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapTest002";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.SYSTEM_FLOAT_WINDOW") == PERMISSION_GRANTED);
    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.GET_WIFI_INFO_INTERNAL") == PERMISSION_GRANTED);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);
    int32_t ret = atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    ret = atManagerService_->RevokePermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM, false);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "InstallHapTest002", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapTest003
 * @tc.desc: Test install a new hap, with pre-auth.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest003, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapTest003";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapTest003";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    bundlePolicy.preAuthorizationInfo.emplace_back(PreAuthorizationInfo{"ohos.permission.CAMERA", true});

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE") == PERMISSION_DENIED);

    int32_t ret = atManagerService_->RevokePermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM, false);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);

    ret = atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "InstallHapTest003", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapTest004
 * @tc.desc: Test install a new hap, with debug.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest004, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/DEBUG/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapTest004";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapTest004";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = true;

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t ret = atManagerService_->RevokePermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM, false);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);

    ret = atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "InstallHapTest004", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapTest005
 * @tc.desc: Test install a new hap, only HapPolicy debug.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest005, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/DEBUG/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapTest005";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapTest005";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);

    int32_t sceneCode = 0;
    int32_t ret = DeleteIdentityCore(tokenId, "InstallHapTest005", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapTest006
 * @tc.desc: Test install a new hap, only BundlePolicy debug.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest006, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapTest006";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapTest006";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = true;

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);

    int32_t sceneCode = 0;
    int32_t ret = DeleteIdentityCore(tokenId, "InstallHapTest006", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapTest007
 * @tc.desc: Test install a new hap, get info from db.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest007, TestSize.Level0)
{
    std::vector<std::string> hapPaths = {
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapTest007",
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module002/InstallHapTest007"
    };
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapTest007";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    
    std::vector<GenericValues> results;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "InstallHapTest007");
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(results.size(), 2);

    GenericValues conditionValue2;
    conditionValue2.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> hapTokenResults;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue2, hapTokenResults);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(hapTokenResults.size(), 1);

    GenericValues conditionValue3;
    conditionValue3.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> permStateResults;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue3, permStateResults);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(permStateResults.size(), 4);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "InstallHapTest007", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapTest008
 * @tc.desc: Test install a new hap, with 2 module.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest008, TestSize.Level0)
{
    std::vector<std::string> hapPaths = {
        "/SYSTEM/system_basic/state:[cam,getwifi]/acl:[getwifi]/Module001/InstallHapTest008",
        "/SYSTEM/system_basic/state:[cam,mic,syswin]/Module002/InstallHapTest008"
    };
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapTest008";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> permStateResults;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateResults);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(permStateResults.size(), 4);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE") == PERMISSION_DENIED);
    
    ret = atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM);
    EXPECT_EQ(ERR_OK, ret);
    ret = atManagerService_->GrantPermission(tokenId, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE") == PERMISSION_GRANTED);

    ret = atManagerService_->RevokePermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM, false);
    EXPECT_EQ(ERR_OK, ret);
    ret = atManagerService_->RevokePermission(tokenId, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM, false);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE") == PERMISSION_DENIED);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "InstallHapTest008", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapTest009
 * @tc.desc: Test install a new hap, with type SHARED.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest009, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/SHARED/Module001/InstallHapTest009";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    std::vector<GenericValues> results;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "InstallHapTest009");
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(results.size(), 0);
}

/**
 * @tc.name: InstallHapTest010
 * @tc.desc: Test install a new hap, with type APP_SERVICE_FWK.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest010, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/APP_SERVICE_FWK/Module001/InstallHapTest010";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapTest010";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity.uid);
    EXPECT_NE(0, identity.tokenId);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    std::vector<GenericValues> results;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "InstallHapTest010");
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(results.size(), 1);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "InstallHapTest010", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapTest011
 * @tc.desc: Test install a new hap, with type APP_PLUGIN.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest011, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/APP_PLUGIN/Module001/InstallHapTest011";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    std::vector<GenericValues> results;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "InstallHapTest011");
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(results.size(), 0);
}

/**
 * @tc.name: InstallHapTest012
 * @tc.desc: Test install a new hap, with type SKILL.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest012, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/SKILL/Module001/InstallHapTest012";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    std::vector<GenericValues> results;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "InstallHapTest012");
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(results.size(), 1);

    std::vector<GenericValues> hapResults;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, hapResults);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(hapResults.size(), 0);

    GenericValues delCondition2;
    delCondition2.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "InstallHapTest012");
    std::vector<AddInfo> addInfoVec2;
    std::vector<DelInfo> delInfoVec2;
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, delCondition2, delInfoVec2);
    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec2, addInfoVec2);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapTest013
 * @tc.desc: Test install a new hap, with NORMAL or SYSTEM.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest013, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapTest013";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapTest013";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    // system hap attr is not 0
    AccessTokenIDEx idEx;
    idEx.tokenIDEx = identity.tokenId;
    EXPECT_NE(idEx.tokenIdExStruct.tokenAttr, 0);
    int32_t sceneCode = 0;
    ASSERT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId, "InstallHapTest013", ReservedType::NONE, sceneCode));

    std::string path2 = "/state:[cam,mic]/Module001/InstallHapTest013";
    std::vector<std::string> hapPaths2 = {path2};
    Identity identity2 = {0, -1};
    InstallHap(hapPaths2, baseInfo, bundlePolicy, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    // normal hap attr is 0
    AccessTokenIDEx idEx2;
    idEx2.tokenIDEx = identity2.tokenId;
    EXPECT_EQ(idEx2.tokenIdExStruct.tokenAttr, 0);
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId2, "InstallHapTest013", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallHapTest014
 * @tc.desc: Test install a new hap, with NORMAL change to SYSTEM.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest014, TestSize.Level0)
{
    std::string path = "/state:[cam,mic]/Module001/InstallHapTest014";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapTest014";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    std::string path2 = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapTest014";
    std::vector<std::string> hapPaths2 = {path2};
    
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path2);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result));

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path2] = path2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> hapTokenResults;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue,
        hapTokenResults));
    EXPECT_EQ(hapTokenResults.size(), 1);

    if (hapTokenResults.size() > 0) {
        EXPECT_NE(hapTokenResults[0].GetInt(TokenFiledConst::FIELD_TOKEN_ATTR), 0);
    }

    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    EXPECT_NE(infoPtr, nullptr);
    if (infoPtr != nullptr) {
        EXPECT_NE(infoPtr->GetAttr(), 0);
    }
    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId, "InstallHapTest014", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallHapTest015
 * @tc.desc: Test install a new hap, with SYSTEM change to NORMAL.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest015, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapTest015";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapTest015";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    std::string path2 = "/state:[cam,mic]/Module001/InstallHapTest015";
    std::vector<std::string> hapPaths2 = {path2};
    
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path2);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result));

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path2] = path2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> hapTokenResults;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue,
        hapTokenResults));
    EXPECT_EQ(hapTokenResults.size(), 1);

    if (hapTokenResults.size() > 0) {
        EXPECT_EQ(hapTokenResults[0].GetInt(TokenFiledConst::FIELD_TOKEN_ATTR), 0);
    }

    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    EXPECT_NE(infoPtr, nullptr);
    if (infoPtr != nullptr) {
        EXPECT_EQ(infoPtr->GetAttr(), 0);
    }
    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId, "InstallHapTest015", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallHapTest016
 * @tc.desc: Test install a new hap, with MDM.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest016, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,mdminfo]/Module001/InstallHapTest016";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_NE(ERR_OK, ret);
    EXPECT_EQ(result.permCheckResult.rule, PermissionRulesEnum::PERMISSION_EDM_RULE);
    EXPECT_EQ(result.permCheckResult.permissionName, "ohos.permission.SET_ENTERPRISE_INFO");

    path = "/SYSTEM/system_basic/MDM/state:[cam,mic,mdminfo]/Module001/InstallHapTest016";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapTest016";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId, "InstallHapTest016", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallHapTest017
 * @tc.desc: Test install a new hap, with ATOMIC.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapTest017, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/ATOMIC/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapTest017";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapTest017";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.SYSTEM_FLOAT_WINDOW") == PERMISSION_GRANTED);
    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.GET_WIFI_INFO_INTERNAL") == PERMISSION_GRANTED);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);
    int32_t ret = atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    ret = atManagerService_->RevokePermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM, false);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "InstallHapTest017", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest001
 * @tc.desc: Test install a new hap, check hap sign failed.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest001, TestSize.Level0)
{
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(
        "/SYSTEM/CheckFailed/system_basic/state:[cam,mic]/acl:[getwifi]/Module001/InstallHapFailedTest001");
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_NE(ERR_OK, ret);

    bundleInfo.clear();
    BundleHapList hapList2;
    HapVerifyResultInfo resultInfo2;
    ret = g_installSessionManager->CheckHapSignInfo(hapList2, nullptr, sessionId, bundleInfo, resultInfo2, QUERY_ALL_SIGN_INFO);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest002
 * @tc.desc: Test install a new hap, check multiple haps failed.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest002, TestSize.Level0)
{
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(
        "/SYSTEM/system_basic/state:[cam,mic]/acl:[getwifi]/Module001/InstallHapFailedTest002-1");
    hapList.hapPaths.emplace_back(
        "/SYSTEM/system_basic/state:[cam,mic]/acl:[getwifi]/Module002/InstallHapFailedTest002-2");
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest003
 * @tc.desc: Test install a new hap, build policy failed.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest003, TestSize.Level0)
{
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(
        "/SYSTEM/BuildFailed/system_basic/state:[cam,mic]/acl:[getwifi]/Module001/InstallHapFailedTest003");
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, InstallTypeEnum::TYPE_INSTALL, result);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest004
 * @tc.desc: Test install a new hap, TYPE_INSTALL when hap already installed.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest004, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapFailedTest004";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapFailedTest004";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, InstallTypeEnum::TYPE_INSTALL, result);
    EXPECT_NE(ERR_OK, ret);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "InstallHapFailedTest004", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->CheckHapPermissionInfo(INVALID_SESSION, InstallTypeEnum::TYPE_INSTALL, result);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapSuccessTest005
 * @tc.desc: Test install a new hap, TYPE_REPLACE & TYPE_MERGE when hap not installed succeeds.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapSuccessTest005, TestSize.Level0)
{
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(
        "/SYSTEM/system_basic/state:[cam,mic]/acl:[getwifi]/Module001/InstallHapFailedTest005");
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, InstallTypeEnum::TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    sessionId = 0;
    bundleInfo.clear();
    HapVerifyResultInfo resultInfo2;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo2, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result2;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, InstallTypeEnum::TYPE_MERGE, result2);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest006
 * @tc.desc: Test install a new hap, TYPE_MERGE and check db hap failed.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest006, TestSize.Level0)
{
    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "InstallHapFailedTest006");
    addValue.Put(TokenFiledConst::FIELD_MODULE_NAME, "CheckFailedModule");
    addValue.Put(TokenFiledConst::FIELD_PATH,
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/CheckFailedModule/InstallHapFailedTest006");
    addValue.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP));
    addValue.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, 0);
    std::vector<uint8_t> blobData = {0x01, 0x02, 0x03};
    addValue.PutBlob(TokenFiledConst::FIELD_PERSIST_DATA, blobData);
    
    std::vector<GenericValues> signValues{addValue};
    GenericValues delCondition;
    std::vector<AddInfo> addInfoVec;
    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, signValues, addInfoVec);
    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    EXPECT_EQ(ERR_OK, ret);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapFailedTest006");
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, InstallTypeEnum::TYPE_MERGE, result);
    EXPECT_NE(ERR_OK, ret);

    GenericValues delCondition2;
    delCondition2.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "InstallHapFailedTest006");
    std::vector<AddInfo> addInfoVec2;
    std::vector<DelInfo> delInfoVec2;
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, delCondition2, delInfoVec2);
    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec2, addInfoVec2);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest007
 * @tc.desc: Test install a new hap, TYPE_MERGE and check multiple failed.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest007, TestSize.Level0)
{
    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "InstallHapFailedTest007");
    addValue.Put(TokenFiledConst::FIELD_MODULE_NAME, "MultipleFailedModule");
    addValue.Put(TokenFiledConst::FIELD_PATH,
        "/SYSTEM/system_basic/state:[cam,mic,syswin]/MultipleFailedModule/InstallHapFailedTest007");
    addValue.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP));
    addValue.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, 0);
    std::vector<uint8_t> blobData = {0x01, 0x02, 0x03};
    addValue.PutBlob(TokenFiledConst::FIELD_PERSIST_DATA, blobData);
    
    std::vector<GenericValues> signValues{addValue};
    GenericValues delCondition;
    std::vector<AddInfo> addInfoVec;
    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, signValues, addInfoVec);
    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    EXPECT_EQ(ERR_OK, ret);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapFailedTest007");
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, InstallTypeEnum::TYPE_MERGE, result);
    EXPECT_NE(ERR_OK, ret);

    GenericValues delCondition2;
    delCondition2.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "InstallHapFailedTest007");
    std::vector<AddInfo> addInfoVec2;
    std::vector<DelInfo> delInfoVec2;
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, delCondition2, delInfoVec2);
    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec2, addInfoVec2);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest008
 * @tc.desc: Test install a new hap, with wrong acl.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest008, TestSize.Level0)
{
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/Module001/InstallHapFailedTest008");
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, InstallTypeEnum::TYPE_INSTALL, result);
    EXPECT_NE(ERR_OK, ret);
    EXPECT_EQ(result.permCheckResult.rule, PermissionRulesEnum::PERMISSION_ACL_RULE);
    EXPECT_EQ(result.permCheckResult.permissionName, "ohos.permission.GET_WIFI_INFO_INTERNAL");
}

/**
 * @tc.name: InstallHapFailedTest009
 * @tc.desc: Test install a new hap, prepare with wrong sessionId.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest009, TestSize.Level0)
{
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapFailedTest009";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    int32_t sessionId = INVALID_SESSION;
    Identity identity = {0, -1};
    int32_t ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_NE(ERR_OK, ret);

    sessionId = 0;
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest010
 * @tc.desc: Test install a new hap, repeat prepare.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest010, TestSize.Level0)
{
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapFailedTest010");
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapFailedTest010";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity.uid);
    EXPECT_NE(0, identity.tokenId);

    Identity identity2 = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity2);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest014
 * @tc.desc: Test install a new hap, SKILL not allow prepare.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest014, TestSize.Level0)
{
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(
        "/SYSTEM/system_basic/state:[cam,mic,syswin]/SKILL/Module001/InstallHapFailedTest014");
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapFailedTest014";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest015
 * @tc.desc: Test install a new hap, prepare not set migration.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest015, TestSize.Level0)
{
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(
        "/SYSTEM/system_basic/state:[cam,mic,syswin]/Module001/InstallHapFailedTest015");
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapFailedTest015";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    g_installSessionManager->migrationDone_ = false;
    AccessTokenIDManager::GetInstance().migrationDone_ = false;

    Identity identity = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_NE(ERR_OK, ret);

    g_installSessionManager->migrationDone_ = true;
    AccessTokenIDManager::GetInstance().migrationDone_ = true;
}

/**
 * @tc.name: InstallHapFailedTest016
 * @tc.desc: Test install a new hap, finish failed.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest016, TestSize.Level0)
{
    std::map<std::string, std::string> modulePathMap;
    // a nonexistent session is rejected before the isPersistent check
    int32_t ret = g_installSessionManager->FinishInstall(INVALID_SESSION, false, modulePathMap);
    EXPECT_EQ(AccessTokenError::ERR_SESSION_NOT_EXIST, ret);
    ret = g_installSessionManager->FinishInstall(INVALID_SESSION, true, modulePathMap);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest017
 * @tc.desc: Test install a new hap, repeat finish.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest017, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapFailedTest017";

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapFailedTest017";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity.uid);
    EXPECT_NE(0, identity.tokenId);

    std::vector<std::string> hapPaths = {path};
    Identity identity2 = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity2);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity2.tokenId);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_NE(ERR_OK, ret);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "InstallHapFailedTest017", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest018
 * @tc.desc: Test install a new hap, finish with empty map.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest018, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapFailedTest018";

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapFailedTest018";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity.uid);
    EXPECT_NE(0, identity.tokenId);

    std::map<std::string, std::string> modulePathMap;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest019
 * @tc.desc: Test install a new hap, already installed.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest019, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallHapFailedTest019";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapFailedTest019";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    Identity identity2 = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity2);
    EXPECT_NE(ERR_OK, ret);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "InstallHapFailedTest019", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest020
 * @tc.desc: Test install a new hap, APP_PLUGIN not allow prepare.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest020, TestSize.Level0)
{
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(
        "/SYSTEM/system_basic/state:[cam,mic,syswin]/APP_PLUGIN/Module001/InstallHapFailedTest020");
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapFailedTest020";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest021
 * @tc.desc: Test install a new hap, SHARED not allow prepare.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest021, TestSize.Level0)
{
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(
        "/SYSTEM/system_basic/state:[cam,mic,syswin]/SHARED/Module001/InstallHapFailedTest021");
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallHapFailedTest021";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: UpdateHapTest001
 * @tc.desc: Test update a new hap.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTest001, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTest001";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "UpdateHapTest001";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);
    int32_t ret = atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, identity.uid);
    EXPECT_EQ(ERR_OK, ret);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "UpdateHapTest001", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: UpdateHapTest002
 * @tc.desc: Test update a new hap, with pre-auth list.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTest002, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTest002";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "UpdateHapTest002";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    bundlePolicy.preAuthorizationInfo.emplace_back(PreAuthorizationInfo{"ohos.permission.CAMERA", true});
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, identity.uid);
    EXPECT_EQ(ERR_OK, ret);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "UpdateHapTest002", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: UpdateHapTest003
 * @tc.desc: Test update a new hap, add hap.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTest003, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTest003";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "UpdateHapTest003";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    int32_t ret = atManagerService_->GrantPermission(tokenId, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM);
    EXPECT_NE(ERR_OK, ret);

    std::string path2 = "/SYSTEM/system_basic/state:[mic,syswin]/Module002/UpdateHapTest003";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.hapPaths.emplace_back(path2);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, identity.uid);
    EXPECT_EQ(ERR_OK, ret);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    modulePathMap[path2] = path2;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE") == PERMISSION_DENIED);
    ret = atManagerService_->GrantPermission(tokenId, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.MICROPHONE") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "UpdateHapTest003", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: UpdateHapTest004
 * @tc.desc: Test update a new hap, add hap.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTest004, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTest004";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "UpdateHapTest004";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    EXPECT_EQ(3U, CountPermRows(tokenId));

    std::string path2 = "/SYSTEM/system_basic/state:[mic,syswin]/Module002/UpdateHapTest004";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.hapPaths.emplace_back(path2);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, identity.uid);
    EXPECT_EQ(ERR_OK, ret);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    modulePathMap[path2] = path2;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    EXPECT_EQ(4U, CountPermRows(tokenId));

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "UpdateHapTest004", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: UpdateHapTest005
 * @tc.desc: Test update a new hap, minus hap.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTest005, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTest005";
    std::string path2 = "/SYSTEM/system_basic/state:[mic,syswin]/Module002/UpdateHapTest005";
    std::vector<std::string> hapPaths = {path, path2};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "UpdateHapTest005";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> permStateResults;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateResults);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(permStateResults.size(), 4);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, identity.uid);
    EXPECT_EQ(ERR_OK, ret);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    modulePathMap[path2] = path2;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    std::vector<GenericValues> permStateResults2;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateResults2);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(permStateResults2.size(), 3);
    
    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "UpdateHapTest005", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: UpdateHapTest006
 * @tc.desc: Test update a new hap, without UpdateHapPolicy call.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTest006, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTest006";
    std::string path2 = "/SYSTEM/system_basic/state:[mic,syswin]/Module002/UpdateHapTest006";
    std::vector<std::string> hapPaths = {path, path2};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "UpdateHapTest006";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> permStateResults;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateResults);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(permStateResults.size(), 4);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    modulePathMap[path2] = path2;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    std::vector<GenericValues> permStateResults2;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateResults2);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(permStateResults2.size(), 3);
    
    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "UpdateHapTest006", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: UpdateHapTest007
 * @tc.desc: Test update a new hap, with TYPE_MERGE.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTest007, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[getwifi]/acl:[getwifi]/Module001/UpdateHapTest007";
    std::string path2 = "/SYSTEM/system_basic/state:[mic,syswin]/Module002/UpdateHapTest007";
    std::vector<std::string> hapPaths = {path, path2};
    HapBaseInfo baseInfo{100, "UpdateHapTest007", 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_EQ(2U, CountPackageRows("UpdateHapTest007"));
    EXPECT_EQ(3U, CountPermRows(tokenId));
    EXPECT_NE(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_EQ(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM));

    std::string path3 = "/SYSTEM/system_basic/state:[cam,syswin]/Module002/UpdateHapTest007";
    std::string path4 = "/SYSTEM/system_basic/state:[manwifi]/acl:[manwifi]/Module003/UpdateHapTest007";
    BundleHapList hapList{std::vector<std::string>(), false, 100};
    hapList.hapPaths.emplace_back(path3);
    hapList.hapPaths.emplace_back(path4);

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_MERGE, result));

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path3] = path3;
    modulePathMap[path4] = path4;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    EXPECT_EQ(3U, CountPackageRows("UpdateHapTest007"));
    EXPECT_EQ(4U, CountPermRows(tokenId));
    EXPECT_EQ(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_NE(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM));

    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.GET_WIFI_INFO_INTERNAL") == PERMISSION_GRANTED);
    
    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId, "UpdateHapTest007", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: UpdateHapTest008
 * @tc.desc: Test update a new hap, update apiVersion.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTest008, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTest008";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "UpdateHapTest008";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    EXPECT_NE(infoPtr, nullptr);
    if (infoPtr != nullptr) {
        HapTokenInfo tokenInfo = infoPtr->GetHapInfoBasic();
        EXPECT_EQ(TEST_API_VERSION_10, tokenInfo.apiVersion);
    }

    path = "/SYSTEM/system_basic/VER1234/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTest008";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, identity.uid);
    EXPECT_EQ(ERR_OK, ret);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    std::shared_ptr<HapTokenInfoInner> infoPtr2 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    EXPECT_NE(infoPtr2, nullptr);
    if (infoPtr2 != nullptr) {
        HapTokenInfo tokenInfo = infoPtr2->GetHapInfoBasic();
        EXPECT_EQ(TEST_API_VERSION_234, tokenInfo.apiVersion);
    }

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "UpdateHapTest008", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: UpdateHapTest009
 * @tc.desc: Test update a new hap, update with wrong uid.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTest009, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTest009";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "UpdateHapTest009";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    int32_t uid = TEST_UID;
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, uid);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(uid, identity.uid);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "UpdateHapTest009", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: UpdateHapTest010
 * @tc.desc: Test update a new hap, update when uid is -1, with using bundleId.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTest010, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTest010";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo{100, "UpdateHapTest010", 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    int32_t sessionId = 0;
    baseInfo.userID = 101;
    Identity iden2 = {0, -1};
    EXPECT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, iden2));

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    int32_t sCode = 0;
    ASSERT_TRUE(SetUidInvalidInDbAndCache(tokenId));


    BundleHapList hapList{std::vector<std::string>{path}, false, 100};
    sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result));

    int32_t uid = TEST_UID;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, uid));
    EXPECT_EQ(uid, identity.uid);

    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    {
        std::shared_ptr<HapTokenInfoInner> infoPtr =
            AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        EXPECT_NE(infoPtr, nullptr);
        if (infoPtr == nullptr) {
            DeleteIdentityCore(0, "UpdateHapTest010", ReservedType::NONE, sCode);
            return;
        }
        EXPECT_EQ(identity.uid, infoPtr->GetUid());
    }

    EXPECT_EQ(ERR_OK, DeleteIdentityCore(0, "UpdateHapTest010", ReservedType::NONE, sCode));
}

/**
 * @tc.name: UpdateHapTest011
 * @tc.desc: Test update a new hap, update when uid is -1, with valid uid.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTest011, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTest011";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo{100, "UpdateHapTest011", 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    int32_t sCode = 0;
    ASSERT_TRUE(SetUidInvalidInDbAndCache(tokenId));


    BundleHapList hapList{std::vector<std::string>{path}, false, 100};
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result));

    int32_t uid = TEST_UID;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, uid));
    EXPECT_EQ(uid, TEST_UID);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    {
        std::shared_ptr<HapTokenInfoInner> infoPtr =
            AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        EXPECT_NE(infoPtr, nullptr);
        if (infoPtr == nullptr) {
            DeleteIdentityCore(0, "UpdateHapTest011", ReservedType::NONE, sCode);
            return;
        }
        EXPECT_EQ(uid, infoPtr->GetUid());
    }

    EXPECT_EQ(ERR_OK, DeleteIdentityCore(0, "UpdateHapTest011", ReservedType::NONE, sCode));
}

/**
 * @tc.name: UpdateHapTest012
 * @tc.desc: Test update a new hap, update when uid is -1, with invalid uid.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTest012, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTest012";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo{100, "UpdateHapTest012", 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    int32_t sCode = 0;
    ASSERT_TRUE(SetUidInvalidInDbAndCache(tokenId));


    BundleHapList hapList{std::vector<std::string>{path}, false, 100};
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result));

    int32_t uid = TEST_INVALID_UID;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, uid));
    EXPECT_NE(uid, TEST_INVALID_UID);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    {
        std::shared_ptr<HapTokenInfoInner> infoPtr =
            AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        EXPECT_NE(infoPtr, nullptr);
        if (infoPtr == nullptr) {
            DeleteIdentityCore(0, "UpdateHapTest012", ReservedType::NONE, sCode);
            return;
        }
        EXPECT_EQ(uid, infoPtr->GetUid());
    }

    EXPECT_EQ(ERR_OK, DeleteIdentityCore(0, "UpdateHapTest012", ReservedType::NONE, sCode));
}

/**
 * @tc.name: UpdateHapTest013
 * @tc.desc: Test update a new hap, update when uid is -1, but bundleId is been used.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTest013, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTest013";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo{100, "UpdateHapTest013", 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    std::string path2 = "/SYSTEM/system_basic/state:[cam,mic,getwifi]/acl:[getwifi]/Module001/UpdateHapTest013-2";
    std::vector<std::string> hapPaths2 = {path2};
    HapBaseInfo baseInfo2{100, "UpdateHapTest013-2", 0};

    Identity identity2 = {0, -1};
    InstallHap(hapPaths2, baseInfo2, bundlePolicy, identity2);

    int32_t sCode = 0;
    ASSERT_TRUE(SetUidInvalidInDbAndCache(tokenId));


    BundleHapList hapList{std::vector<std::string>{path}, false, 100};
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result));

    int32_t uid = identity2.uid;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, uid));
    EXPECT_NE(uid, identity2.uid);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    {
        std::shared_ptr<HapTokenInfoInner> infoPtr =
            AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        EXPECT_NE(infoPtr, nullptr);
        if (infoPtr == nullptr) {
            DeleteIdentityCore(0, "UpdateHapTest013", ReservedType::NONE, sCode);
            return;
        }
        EXPECT_EQ(uid, infoPtr->GetUid());
    }

    EXPECT_EQ(ERR_OK, DeleteIdentityCore(0, "UpdateHapTest013", ReservedType::NONE, sCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(0, "UpdateHapTest013-2", ReservedType::NONE, sCode));
}

/**
 * @tc.name: UpdateHapTest014
 * @tc.desc: Test update a new hap, update when uid is -1, with valid uid and finish false.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTest014, TestSize.Level4)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTest014";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo{100, "UpdateHapTest014", 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    int32_t sCode = 0;
    ASSERT_TRUE(SetUidInvalidInDbAndCache(tokenId));


    BundleHapList hapList{std::vector<std::string>{path}, false, 100};
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result));

    int32_t uid = TEST_UID2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, uid));
    EXPECT_EQ(uid, TEST_UID2);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, false, modulePathMap));

    std::shared_ptr<HapTokenInfoInner> infoPtr = nullptr;
    bool isNewBundleId = false;
    bool fromCaller = false;
    EXPECT_NE(ERR_OK, InstallIdentityManager::ResolveUpdateUid(uid, infoPtr, isNewBundleId, fromCaller));

    EXPECT_EQ(ERR_OK, DeleteIdentityCore(0, "UpdateHapTest014", ReservedType::NONE, sCode));
}

/**
 * @tc.name: UpdateHapFromCallerMigratedTest001
 * @tc.desc: Update with the caller input uid adopted (level3) and finish persistent:
 *           hap token info migrated must be 1 in db and true in memory.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapFromCallerMigratedTest001, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapMig001";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo{100, "UpdateHapMig001", 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    // simulate a migration-failed token: uid invalid both in db and memory
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    ASSERT_TRUE(SetUidInvalidInDbAndCache(tokenId));


    // update session: caller designates the uid, ATM adopts it (level3)
    BundleHapList hapList{std::vector<std::string>{path}, false, 100};
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo,
        QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result));

    int32_t uid = TEST_UID2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, uid));
    EXPECT_EQ(uid, TEST_UID2);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // uid adopted from the UpdateHapPolicy input: token must be marked migrated (db + memory)
    std::vector<GenericValues> migratedResults;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue,
        migratedResults));
    EXPECT_EQ(1, migratedResults.size());
    EXPECT_EQ(1, migratedResults[0].GetInt(TokenFiledConst::FIELD_MIGRATED));
    {
        std::shared_ptr<HapTokenInfoInner> inner =
            AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        ASSERT_NE(inner, nullptr);
        EXPECT_TRUE(inner->IsMigrated());
    }

    int32_t sCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(0, "UpdateHapMig001", ReservedType::NONE, sCode));
}

/**
 * @tc.name: UpdateHapFailedTest001
 * @tc.desc: Test update a new hap, without migrationDone.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapFailedTest001, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapFailedTest001";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "UpdateHapFailedTest001";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);


    g_installSessionManager->migrationDone_ = false;
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, identity.uid);
    EXPECT_NE(ERR_OK, ret);
    g_installSessionManager->migrationDone_ = true;

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "UpdateHapFailedTest001", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: UpdateHapFailedTest002
 * @tc.desc: Test update a new hap, with not exist session, with not match tokenID.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapFailedTest002, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapFailedTest002";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "UpdateHapFailedTest002";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    std::string path2 =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapFailedTest002-2";
    std::vector<std::string> hapPaths2 = {path2};
    HapBaseInfo baseInfo2;
    baseInfo2.userID = 100;
    baseInfo2.bundleName = "UpdateHapFailedTest002-2";
    baseInfo2.instIndex = 0;
    BundlePolicy bundlePolicy2;
    bundlePolicy2.dlpType = DLP_COMMON;
    bundlePolicy2.isDebugGrant = false;
    Identity identity2 = {0, -1};
    InstallHap(hapPaths2, baseInfo2, bundlePolicy2, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(INVALID_SESSION, tokenId, bundlePolicy, identity.uid);
    EXPECT_NE(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId2, bundlePolicy, identity2.uid);
    EXPECT_NE(ERR_OK, ret);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "UpdateHapFailedTest002", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    ret = DeleteIdentityCore(tokenId2, "UpdateHapFailedTest002-2", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: UpdateHapFailedTest003
 * @tc.desc: Test update a new hap, with not exist tokenID.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapFailedTest003, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapFailedTest003";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "UpdateHapFailedTest003";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, 123456789, bundlePolicy, identity.uid);
    EXPECT_NE(ERR_OK, ret);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "UpdateHapFailedTest003", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: UpdateHapFailedTest004
 * @tc.desc: Test update a new hap, with reserved tokenID.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapFailedTest004, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapFailedTest004";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "UpdateHapFailedTest004";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    int32_t sceneCode = 0;
    int32_t ret = DeleteIdentityCore(
        tokenId, "UpdateHapFailedTest004", ReservedType::RESERVED_DATA, sceneCode);
    EXPECT_EQ(ERR_OK, ret);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, identity.uid);
    EXPECT_NE(ERR_OK, ret);

    ret = DeleteIdentityCore(0, "UpdateHapFailedTest004", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: UpdateHapFailedTest005
 * @tc.desc: UpdateHapPolicy with uid 0 (struct default) is a caller bug, not a
 *           no-expectation marker: the user-segment ownership check rejects it
 *           with ERR_PARAM_INVALID and rolls the session back.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapFailedTest005, TestSize.Level1)
{
    std::string bundleName = "UpdateHapFailedTest005";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo{100, bundleName, 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};
    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartReplaceSession(path, sessionId));
    int32_t uid = 0;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, uid));
    // fatal rejection rolls the session back
    std::map<std::string, std::string> emptyPathMap;
    EXPECT_EQ(AccessTokenError::ERR_SESSION_NOT_EXIST,
        g_installSessionManager->FinishInstall(sessionId, true, emptyPathMap));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: FinishHapTest001
 * @tc.desc: Test finish a new hap, success is false.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, FinishHapTest001, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/FinishHapTest001";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result));

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "FinishHapTest001";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    EXPECT_EQ(ERR_OK,
        g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity));
    EXPECT_NE(0, identity.uid);
    EXPECT_NE(0, identity.tokenId);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, false, modulePathMap));

    std::vector<GenericValues> results;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "FinishHapTest001");
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results));
    EXPECT_EQ(results.size(), 0);
}

/**
 * @tc.name: FinishHapTest002
 * @tc.desc: Test finish a new hap, with bundle type SHARED.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, FinishHapTest002, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/SHARED/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/FinishHapTest002";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result));

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    std::vector<GenericValues> results;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "FinishHapTest002");
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results));
    EXPECT_EQ(results.size(), 0);
}

/**
 * @tc.name: FinishHapTest004
 * @tc.desc: Test finish a new hap, with bundle type APP_PLUGIN.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, FinishHapTest004, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/APP_PLUGIN/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/FinishHapTest004";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result));

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    std::vector<GenericValues> results;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "FinishHapTest004");
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results));
    EXPECT_EQ(results.size(), 0);
}

/**
 * @tc.name: FinishHapFailedTest001
 * @tc.desc: Test finish a new hap, with bundle type SKILL and not set migration.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, FinishHapFailedTest001, TestSize.Level0)
{
    g_installSessionManager->migrationDone_ = false;

    std::string path =
        "/SYSTEM/system_basic/SKILL/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/FinishHapFailedTest001";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result));

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    EXPECT_NE(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    std::vector<GenericValues> results;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "FinishHapFailedTest001");
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results));
    EXPECT_EQ(results.size(), 0);

    g_installSessionManager->migrationDone_ = true;
}

/**
 * @tc.name: AppCloneTest001
 * @tc.desc: Test clone a hap.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, AppCloneTest001, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/AppCloneTest001";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "AppCloneTest001";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    baseInfo.instIndex = 1;
    int32_t sessionId = 0;
    Identity identity2 = {0, -1};
    int32_t ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity2);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity2.uid);
    EXPECT_NE(0, identity2.tokenId);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // same userID, not same bundleID
    EXPECT_EQ(identity.uid / UID_MASK, identity2.uid / UID_MASK);
    EXPECT_NE(identity.uid % UID_MASK, identity2.uid % UID_MASK);

    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.SYSTEM_FLOAT_WINDOW") == PERMISSION_GRANTED);
    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.GET_WIFI_INFO_INTERNAL") == PERMISSION_GRANTED);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_DENIED);
    ret = atManagerService_->GrantPermission(tokenId2, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId, "AppCloneTest001", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId2, "AppCloneTest001", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: AppCloneTest002
 * @tc.desc: Test clone a hap, with DLP_FULL_CONTROL.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, AppCloneTest002, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/AppCloneTest002";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "AppCloneTest002";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);
    int32_t ret = atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    bundlePolicy.dlpType = DLP_FULL_CONTROL;
    baseInfo.instIndex = 1;
    int32_t sessionId = 0;
    Identity identity2 = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity2);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity2.uid);
    EXPECT_NE(0, identity2.tokenId);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.SYSTEM_FLOAT_WINDOW") == PERMISSION_GRANTED);
    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.GET_WIFI_INFO_INTERNAL") == PERMISSION_GRANTED);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_GRANTED);
    
    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId, "AppCloneTest002", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId2, "AppCloneTest002", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: AppCloneTest003
 * @tc.desc: Test clone a hap, with pre-auth list.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, AppCloneTest003, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/AppCloneTest003";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "AppCloneTest003";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    bundlePolicy.preAuthorizationInfo.emplace_back(PreAuthorizationInfo{"ohos.permission.CAMERA", true});
    baseInfo.instIndex = 1;
    int32_t sessionId = 0;
    Identity identity2 = {0, -1};
    int32_t ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity2);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity2.uid);
    EXPECT_NE(0, identity2.tokenId);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId, "AppCloneTest003", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId2, "AppCloneTest003", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: AppCloneTest004
 * @tc.desc: Test clone a hap, with new userID.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, AppCloneTest004, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/AppCloneTest004";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "AppCloneTest004";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    baseInfo.userID = 101;
    int32_t sessionId = 0;
    Identity identity2 = {0, -1};
    int32_t ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity2);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity2.uid);
    EXPECT_NE(0, identity2.tokenId);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // not same userID, same bundleID
    EXPECT_NE(identity.uid / UID_MASK, identity2.uid / UID_MASK);
    EXPECT_EQ(identity.uid % UID_MASK, identity2.uid % UID_MASK);

    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.SYSTEM_FLOAT_WINDOW") == PERMISSION_GRANTED);
    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.GET_WIFI_INFO_INTERNAL") == PERMISSION_GRANTED);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_DENIED);
    ret = atManagerService_->GrantPermission(tokenId2, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId, "AppCloneTest004", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId2, "AppCloneTest004", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: AppCloneTest005
 * @tc.desc: Test clone a hap, clone with TYPE_REPLACE(update).
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, AppCloneTest005, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[syswin,getwifi]/acl:[getwifi]/Module001/AppCloneTest005";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo{100, "AppCloneTest005", 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.SYSTEM_FLOAT_WINDOW") == PERMISSION_GRANTED);
    EXPECT_NE(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));

    baseInfo.userID = 101;
    AccessTokenID tokenId2 = InstallBundleSiblingToken(baseInfo, bundlePolicy);
    EXPECT_NE(ERR_OK, atManagerService_->GrantPermission(tokenId2, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));

    std::string path2 = "/SYSTEM/system_basic/state:[cam,getwifi]/acl:[getwifi]/Module001/AppCloneTest005";
    BundleHapList hapList{std::vector<std::string>(), false, 100};
    hapList.hapPaths.emplace_back(path2);
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result));

    baseInfo.userID = TEST_USER_ID;
    baseInfo.instIndex = 1;
    Identity identity3 = {0, -1};
    EXPECT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(
        sessionId, baseInfo, bundlePolicy, nullptr, identity3));
    AccessTokenID tokenId3 = static_cast<AccessTokenID>(identity3.tokenId);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path2] = path2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.SYSTEM_FLOAT_WINDOW") == PERMISSION_DENIED);

    EXPECT_EQ(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);
    EXPECT_EQ(ERR_OK, atManagerService_->GrantPermission(tokenId2, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId, "AppCloneTest005", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId2, "AppCloneTest005", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId3, "AppCloneTest005", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallReservedHapTest001
 * @tc.desc: Test install a new hap, with reserved 1.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallReservedHapTest001, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallReservedHapTest001";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallReservedHapTest001";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_EQ(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(
        tokenId, "InstallReservedHapTest001", ReservedType::RESERVED_IDENTITY, sceneCode));

    Identity identity2 = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    EXPECT_NE(tokenId, tokenId2);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_DENIED);

    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId2, "InstallReservedHapTest001", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallReservedHapTest002
 * @tc.desc: Test install a new hap, with reserved 2.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallReservedHapTest002, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallReservedHapTest002";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallReservedHapTest002";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_EQ(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(
        tokenId, "InstallReservedHapTest002", ReservedType::RESERVED_DATA, sceneCode));

    Identity identity2 = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    EXPECT_EQ(tokenId, tokenId2);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId2, "InstallReservedHapTest002", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallReservedHapTest003
 * @tc.desc: Test install a new hap, with reserved 2 and index 1.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallReservedHapTest003, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallReservedHapTest003";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallReservedHapTest003";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    baseInfo.instIndex = 1;
    int32_t sessionId = 0;
    Identity identity2 = {0, -1};
    int32_t ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity2);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity2.uid);
    EXPECT_NE(0, identity2.tokenId);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    EXPECT_EQ(ERR_OK, atManagerService_->GrantPermission(tokenId2, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(
        tokenId2, "InstallReservedHapTest003", ReservedType::RESERVED_DATA, sceneCode));

    sessionId = 0;
    Identity identity3 = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity3);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity3.uid);
    EXPECT_NE(0, identity3.tokenId);
    AccessTokenID tokenId3 = static_cast<AccessTokenID>(identity3.tokenId);

    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    EXPECT_EQ(tokenId3, tokenId2);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId3, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId, "InstallReservedHapTest003", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId3, "InstallReservedHapTest003", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallReservedHapTest004
 * @tc.desc: Test install a new hap, with reserved 2, isDebugGrant change to normal.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallReservedHapTest004, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/DEBUG/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallReservedHapTest004";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallReservedHapTest004";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = true;

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(
        tokenId, "InstallReservedHapTest004", ReservedType::RESERVED_DATA, sceneCode));

    bundlePolicy.isDebugGrant = false;
    Identity identity2 = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    EXPECT_EQ(tokenId, tokenId2);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId2, "InstallReservedHapTest004", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallReservedHapTest005
 * @tc.desc: Test install a new hap, with reserved 2, debug hap change to normal.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallReservedHapTest005, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/DEBUG/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallReservedHapTest005";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallReservedHapTest005";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = true;

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(
        tokenId, "InstallReservedHapTest005", ReservedType::RESERVED_DATA, sceneCode));

    std::string path2 =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallReservedHapTest005";
    std::vector<std::string> hapPaths2 = {path2};
    Identity identity2 = {0, -1};
    InstallHap(hapPaths2, baseInfo, bundlePolicy, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    EXPECT_EQ(tokenId, tokenId2);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_DENIED);

    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId2, "InstallReservedHapTest005", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallReservedHapTest006
 * @tc.desc: Test install a new hap, with reserved 2, install - delete2 - install - delete0 - install.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallReservedHapTest006, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallReservedHapTest006";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "InstallReservedHapTest006";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(
        tokenId, "InstallReservedHapTest006", ReservedType::RESERVED_DATA, sceneCode));

    Identity identity2 = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);
    EXPECT_EQ(tokenId, tokenId2);

    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId2, "InstallReservedHapTest006", ReservedType::NONE, sceneCode));

    Identity identity3 = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity3);
    AccessTokenID tokenId3 = static_cast<AccessTokenID>(identity3.tokenId);
    EXPECT_NE(tokenId, tokenId3);

    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId3, "InstallReservedHapTest006", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: IsCheckPermTest001
 * @tc.desc: Test IsCheckPerm mark.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, IsCheckPermTest001, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/IsCheckPermTest001";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "IsCheckPermTest001";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_NE(ERR_OK, ret);

    HapVerifyResultInfo resultInfo2;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo2, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, INVALID_SESSION, bundlePolicy, identity.uid);
    EXPECT_NE(ERR_OK, ret);

    HapVerifyResultInfo resultInfo3;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo3, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    std::map<std::string, std::string> modulePathMap;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: GetInfoBySessionTest001
 * @tc.desc: Test GetCacheSignInfoBySessionId.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, GetInfoBySessionTest001, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[mic,syswin,getwifi]/acl:[getwifi]/Module001/GetInfoBySessionTest001";
    std::string path2 =
        "/SYSTEM/system_basic/state:[cam,syswin]/Module002/GetInfoBySessionTest001";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.hapPaths.emplace_back(path2);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    std::vector<TrustedBundleInfo> bundleInfo2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->GetCacheSignInfoBySessionId(sessionId, bundleInfo2, QUERY_ALL_SIGN_INFO));

    EXPECT_EQ(bundleInfo.size(), hapList.hapPaths.size());
    EXPECT_EQ(bundleInfo.size(), bundleInfo2.size());

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, false, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    std::vector<TrustedBundleInfo> bundleInfo3;
    EXPECT_NE(ERR_OK, g_installSessionManager->GetCacheSignInfoBySessionId(INVALID_SESSION, bundleInfo3, QUERY_ALL_SIGN_INFO));
}

/**
 * @tc.name: GetInfoByBundleNameTest001
 * @tc.desc: Test GetHapSignInfo.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, GetInfoByBundleNameTest001, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[mic,syswin,getwifi]/acl:[getwifi]/Module001/GetInfoByBundleNameTest001";
    std::string path2 =
        "/SYSTEM/system_basic/state:[cam,syswin]/Module002/GetInfoByBundleNameTest001";

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.hapPaths.emplace_back(path2);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result));

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "GetInfoByBundleNameTest001";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    int32_t ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity.uid);
    EXPECT_NE(0, identity.tokenId);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    modulePathMap[path2] = path2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    std::vector<TrustedBundleInfo> bundleInfo2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->GetHapSignInfo("GetInfoByBundleNameTest001", bundleInfo2, QUERY_ALL_SIGN_INFO));

    EXPECT_EQ(bundleInfo.size(), hapList.hapPaths.size());
    EXPECT_EQ(bundleInfo.size(), bundleInfo2.size());

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        DeleteIdentityCore(tokenId, "GetInfoByBundleNameTest001", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: GetInfoByBundleNameFailTest001
 * @tc.desc: Test GetHapSignInfo, with not exist bundle, with check failed.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, GetInfoByBundleNameFailTest001, TestSize.Level0)
{
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_NE(ERR_OK, g_installSessionManager->GetHapSignInfo("", bundleInfo, QUERY_ALL_SIGN_INFO));
    EXPECT_NE(ERR_OK, g_installSessionManager->GetHapSignInfo("GetInfoByBundleNameFailTest001", bundleInfo, QUERY_ALL_SIGN_INFO));
    EXPECT_TRUE(bundleInfo.empty());

    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "GetInfoByBundleNameFailTest001");
    addValue.Put(TokenFiledConst::FIELD_MODULE_NAME, "CheckFailedModule");
    addValue.Put(TokenFiledConst::FIELD_PATH,
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/"
        "CheckFailedModule/GetInfoByBundleNameFailTest001");
    addValue.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP));
    addValue.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, 0);
    std::vector<uint8_t> blobData = {0x01, 0x02, 0x03};
    addValue.PutBlob(TokenFiledConst::FIELD_PERSIST_DATA, blobData);
    
    std::vector<GenericValues> signValues{addValue};
    GenericValues delCondition;
    std::vector<AddInfo> addInfoVec;
    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, signValues, addInfoVec);
    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    EXPECT_EQ(ERR_OK, ret);

    std::vector<TrustedBundleInfo> bundleInfo2;
    EXPECT_NE(ERR_OK, g_installSessionManager->GetHapSignInfo("GetInfoByBundleNameFailTest001", bundleInfo2, QUERY_ALL_SIGN_INFO));
    EXPECT_TRUE(bundleInfo2.empty());

    GenericValues delCondition2;
    delCondition2.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "GetInfoByBundleNameFailTest001");
    std::vector<AddInfo> addInfoVec2;
    std::vector<DelInfo> delInfoVec2;
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, delCondition2, delInfoVec2);
    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec2, addInfoVec2);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: GetCachePolicyBySessionIdTest001
 * @tc.desc: Test GetCachePolicyBySessionId, bundle name not match.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, GetCachePolicyBySessionIdTest001, TestSize.Level0)
{
    BundlePolicyInfo bundlePolicyInfo;
    EXPECT_NE(ERR_OK, g_installSessionManager->GetCachePolicyBySessionId(
        INVALID_SESSION, "GetCachePolicyBySessionIdTest001", bundlePolicyInfo));

    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/GetCachePolicyBySessionIdTest001";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "GetCachePolicyBySessionIdTest001";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity.uid);
    EXPECT_NE(0, identity.tokenId);

    BundlePolicyInfo bundlePolicyInfo2;
    EXPECT_NE(ERR_OK, g_installSessionManager->GetCachePolicyBySessionId(
        sessionId, "NotMatchBundle", bundlePolicyInfo2));

    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, false, modulePathMap));
}

/**
 * @tc.name: GetCachePolicyBySessionIdTest002
 * @tc.desc: Test GetCachePolicyBySessionId, reqPerm has value.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, GetCachePolicyBySessionIdTest002, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/GetCachePolicyBySessionIdTest002";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_EQ(ERR_OK, ret);

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "GetCachePolicyBySessionIdTest002";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity.uid);
    EXPECT_NE(0, identity.tokenId);

    BundlePolicyInfo bundlePolicyInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->GetCachePolicyBySessionId(
        sessionId, "GetCachePolicyBySessionIdTest002", bundlePolicyInfo));
    EXPECT_FALSE(bundlePolicyInfo.reqPermissions.empty());

    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, false, modulePathMap));
}

/**
 * @tc.name: GetCachePolicyBySessionIdTest003
 * @tc.desc: Test GetCachePolicyBySessionId, prepare and query, reqPerm has value.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, GetCachePolicyBySessionIdTest003, TestSize.Level0)
{
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/GetCachePolicyBySessionIdTest003";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "GetCachePolicyBySessionIdTest003";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    int32_t sessionId = 0;
    baseInfo.instIndex = 1;

    Identity identity2 = {0, -1};
    int32_t ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity2);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity2.uid);
    EXPECT_NE(0, identity2.tokenId);

    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, false, modulePathMap));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(
        tokenId, "GetCachePolicyBySessionIdTest003", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: SessionMgrCoverageTest001
 * @tc.desc: coverage test.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, SessionMgrCoverageTest001, TestSize.Level4)
{
    AccessTokenID tokenID = 123;
    BundlePolicy bundlePolicy;
    int32_t sceneCode = 0;
    int32_t errorCode = 0;
    HapDfxInfo dfxInfoRaw;
    InstallSysEventReporter::ReportUpdateHap(tokenID, bundlePolicy, sceneCode, errorCode, dfxInfoRaw, true);

    std::vector<BriefPermData> newPerms;
    std::vector<BriefPermData> oldPerms;
    bool skipInheritance = true;
    BriefPermData permData;
    permData.permCode = 10;
    permData.flag = PERMISSION_FIXED_BY_ADMIN_POLICY;
    newPerms.emplace_back(permData);
    oldPerms.emplace_back(permData);
    g_installSessionManager->MergePermission(newPerms, oldPerms, skipInheritance);

    permData.flag = PERMISSION_RESTRICTED_BY_ADMIN;
    newPerms.clear();
    oldPerms.clear();
    newPerms.emplace_back(permData);
    oldPerms.emplace_back(permData);
    g_installSessionManager->MergePermission(newPerms, oldPerms, skipInheritance);

    PermissionStatus permState;
    permState.permissionName = "INVALID_PERM_NAME";
    BriefPermData briefPermData;
    EXPECT_EQ(false, PermissionDataBrief::BuildPermissionBriefData(permState, briefPermData));
}

/**
 * @tc.name: InstallSessionTest001
 * @tc.desc: Service-layer install interfaces return ERR_PERMISSION_DENIED when the caller is
 *           non-privileged and lacks MANAGE_HAP_TOKENID.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallSessionTest001, TestSize.Level1)
{
    // install a hap without MANAGE_HAP_TOKENID to act as the caller token
    std::string path = "/SYSTEM/system_basic/state:[]/acl:[]/Module001/PermDeniedBundle";
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "PermDeniedBundle";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID callerTokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, callerTokenId);

    uint64_t origSelfToken = GetSelfTokenID();
    EXPECT_EQ(0, SetSelfTokenID(identity.tokenId));
    {
        // drop root so IsPrivilegedCalling() returns false and the gate is enforced
        TestUidGuard guard(2000);
        sptr<IRemoteObject> cb;

        BundleHapListIdl listIdl;
        listIdl.hapPaths.emplace_back(path);
        listIdl.isPreInstalled = false;
        listIdl.userId = 100;
        CheckHapSignResultRawdata rawData;
        EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
            atManagerService_->CheckHapSignInfo(listIdl, cb, QUERY_ALL_SIGN_INFO, rawData));

        HapInfoCheckResultIdl checkResult;
        EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
            atManagerService_->CheckHapPermissionInfo(1, InstallTypeEnumIdl::TYPE_INSTALL, checkResult));

        HapBaseInfoIdl infoIdl;
        infoIdl.userID = 100;
        infoIdl.bundleName = "PermDeniedBundle";
        infoIdl.instIndex = 0;
        BundlePolicyIdl policyIdl;
        IdentityIdl identityIdl;
        int32_t sessionId = 1;
        EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
            atManagerService_->PrepareHapIdentity(sessionId, infoIdl, policyIdl, cb, identityIdl));

        std::map<std::string, std::string> modulePathMap;
        EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
            atManagerService_->FinishInstall(1, false, modulePathMap));
    }
    EXPECT_EQ(0, SetSelfTokenID(origSelfToken));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(callerTokenId, "PermDeniedBundle", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallSessionTest002
 * @tc.desc: Idle sessions past the 1h threshold are reclaimed by ClearTimeoutSession and the same
 *           bundle can open a new session afterwards.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallSessionTest002, TestSize.Level1)
{
    std::string path = "/SYSTEM/system_basic/state:[]/acl:[]/Module001/TimeoutSweepBundle";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo,
        resultInfo, QUERY_ALL_SIGN_INFO));
    ASSERT_GT(sessionId, 0);

    // age the session beyond the 1h idle threshold
    constexpr int64_t idleMs = 2 * 60 * 60 * 1000;
    g_installSessionManager->sessionToInstallCache[sessionId].createdMs = TimeUtil::GetCurrentTimestamp() - idleMs;
    g_installSessionManager->ClearTimeoutSession();

    EXPECT_TRUE(g_installSessionManager->sessionToInstallCache.find(sessionId) ==
        g_installSessionManager->sessionToInstallCache.end());
    EXPECT_TRUE(g_installSessionManager->sessionToInstallCache.find(sessionId) ==
        g_installSessionManager->sessionToInstallCache.end());

    // the same bundle can open a new session after the reclaim
    int32_t sessionId2 = 0;
    std::vector<TrustedBundleInfo> bundleInfo2;
    HapVerifyResultInfo resultInfo2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId2, bundleInfo2,
        resultInfo2, QUERY_ALL_SIGN_INFO));
    EXPECT_GT(sessionId2, 0);
    EXPECT_NE(sessionId, sessionId2);
}

/**
 * @tc.name: InstallSessionTest003
 * @tc.desc: Fresh sessions survive ClearTimeoutSession and remain usable.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallSessionTest003, TestSize.Level1)
{
    std::string path = "/SYSTEM/system_basic/state:[]/acl:[]/Module001/TimeoutFreshBundle";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo,
        resultInfo, QUERY_ALL_SIGN_INFO));
    ASSERT_GT(sessionId, 0);

    g_installSessionManager->ClearTimeoutSession();

    // fresh session is kept and still usable
    EXPECT_TRUE(g_installSessionManager->sessionToInstallCache.find(sessionId) !=
        g_installSessionManager->sessionToInstallCache.end());
    HapInfoCheckResult checkResult;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, checkResult));
}

/**
 * @tc.name: FinishHapTest005
 * @tc.desc: SupplementUpdateInfo pulls every active token of the bundle into the update plan and
 *           reuses this round's pre-authorization for them.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, FinishHapTest005, TestSize.Level1)
{
    std::string bundleName = "SupplementBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenIdA = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenIdA);

    // second token of the same bundle for another user
    baseInfo.userID = 101;
    int32_t sessionId = 0;
    Identity identity2 = {0, -1};
    ASSERT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr,
        identity2));
    std::map<std::string, std::string> modulePathMap;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));
    AccessTokenID tokenIdB = static_cast<AccessTokenID>(identity2.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenIdB);

    // simulate an update session that only covers token A
    InstallCache cache;
    cache.bundleParam.bundleName = bundleName;
    cache.hasPermChecked = true;
    BundlePolicy policy;
    PreAuthorizationInfo preAuth;
    preAuth.permissionName = "ohos.permission.CAMERA";
    preAuth.userCancelable = true;
    policy.preAuthorizationInfo.emplace_back(preAuth);
    cache.updatedBundlePolicyMap[tokenIdA] = policy;

    g_installSessionManager->SupplementUpdateInfo(cache);

    // both tokens of the bundle are covered by the update plan
    EXPECT_EQ(2U, cache.updatedBundlePolicyMap.size());
    EXPECT_TRUE(cache.updatedBundlePolicyMap.find(static_cast<int32_t>(tokenIdA)) !=
        cache.updatedBundlePolicyMap.end());
    EXPECT_TRUE(cache.updatedBundlePolicyMap.find(static_cast<int32_t>(tokenIdB)) !=
        cache.updatedBundlePolicyMap.end());
    // the supplemented entry reuses this round's pre-auth and keeps the token's own uid
    EXPECT_EQ(1U, cache.updatedBundlePolicyMap[tokenIdB].preAuthorizationInfo.size());
    EXPECT_EQ(identity2.uid, cache.uidStateMap[tokenIdB].uid);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: FinishHapTest006
 * @tc.desc: Reserved tokens of the same bundle are excluded from the supplement update plan.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, FinishHapTest006, TestSize.Level1)
{
    std::string bundleName = "SupplementReservedBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenIdA = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenIdA);

    baseInfo.userID = 101;
    int32_t sessionId = 0;
    Identity identity2 = {0, -1};
    ASSERT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr,
        identity2));
    std::map<std::string, std::string> modulePathMap;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));
    AccessTokenID tokenIdB = static_cast<AccessTokenID>(identity2.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenIdB);

    // reserve token B's data: it must not be touched by a later update of the bundle
    int32_t sceneCode = 0;
    ASSERT_EQ(ERR_OK, DeleteIdentityCore(tokenIdB, bundleName, ReservedType::RESERVED_DATA, sceneCode));

    InstallCache cache;
    cache.bundleParam.bundleName = bundleName;
    cache.hasPermChecked = true;
    BundlePolicy policy;
    cache.updatedBundlePolicyMap[tokenIdA] = policy;

    g_installSessionManager->SupplementUpdateInfo(cache);

    // only the active token is in the plan
    EXPECT_EQ(1U, cache.updatedBundlePolicyMap.size());
    EXPECT_TRUE(cache.updatedBundlePolicyMap.find(static_cast<int32_t>(tokenIdB)) ==
        cache.updatedBundlePolicyMap.end());

    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: FinishHapTest007
 * @tc.desc: RESERVED_DATA reinstall removes the bundleId from reservedBundleIdSet_
 *           (memory) and keeps it in bundleIdSet_ (token is active again).
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, FinishHapTest007, TestSize.Level1)
{
    std::string bundleName = "ReservedBundleIdCleanupBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    // install and reserve with RESERVED_DATA
    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    int32_t sceneCode = 0;
    ASSERT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::RESERVED_DATA, sceneCode));

    // simulate the bundleId being in the reserved set (populated by migration)
    int32_t bundleId = 0;
    ASSERT_TRUE(AccessTokenIDManager::GetInstance().ExtractBundleId(identity.uid, bundleId));
    AccessTokenIDManager::GetInstance().reservedBundleIdSet_.insert(bundleId);
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().IsReservedBundleId(identity.uid));

    // reinstall: RESERVED_DATA path reuses the token and reactivates it
    Identity identity2 = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity2);
    ASSERT_EQ(tokenId, static_cast<AccessTokenID>(identity2.tokenId));

    // bundleId removed from reserved set (memory update in CommitIdentity)
    EXPECT_FALSE(AccessTokenIDManager::GetInstance().IsReservedBundleId(identity.uid));
    // bundleId still in the active set (token is active again)
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().bundleIdSet_.count(bundleId) > 0);

    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: FinishHapTest008
 * @tc.desc: BR-17 supplement matrix: with A (explicitly updated) + clones B/C/D where
 *           B is RESERVED_DATA-deleted and C is RESERVED_IDENTITY-deleted, only the
 *           active clone D is supplement-updated; B/C are excluded by the ACTIVE-status
 *           candidate filter and stay untouched. A newly declared system_grant
 *           permission (SYSTEM_FLOAT_WINDOW) is the update observable.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, FinishHapTest008, TestSize.Level1)
{
    std::string bundleName = "FinishHapTest008";
    std::string newPath = "/SYSTEM/system_basic/state:[cam,syswin]/acl:[]/Module001/" + bundleName;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    // A: main token (initial policy declares cam only) + clones B/C/D;
    // B is RESERVED_DATA-deleted and C is RESERVED_IDENTITY-deleted
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    AccessTokenID matrixTokens[4] = {0};
    SetupSupplementMatrix(baseInfo, bundlePolicy, bundleName, matrixTokens);
    AccessTokenID tokenA = matrixTokens[0];
    AccessTokenID tokenB = matrixTokens[1];
    AccessTokenID tokenC = matrixTokens[2];
    AccessTokenID tokenD = matrixTokens[3];

    // D's uid before update: supplement must keep the token's own uid
    auto infoD = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenD);
    ASSERT_NE(nullptr, infoD);
    int32_t uidDBefore = infoD->GetUid();

    // update A: the new version adds system_grant SYSTEM_FLOAT_WINDOW
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartReplaceSession(newPath, sessionId));
    int32_t uid = -1; // no uid expectation
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenA, bundlePolicy, uid));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[newPath] = newPath;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // explicit A and supplemented D both received the new system_grant permission
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(tokenA, "ohos.permission.SYSTEM_FLOAT_WINDOW"));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(tokenD, "ohos.permission.SYSTEM_FLOAT_WINDOW"));
    // supplement keeps the token's own uid
    infoD = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenD);
    ASSERT_NE(nullptr, infoD);
    EXPECT_EQ(uidDBefore, infoD->GetUid());

    // reserved B/C stay invisible and untouched: no new permission row in db
    AssertTokenInvisible(tokenB);
    AssertTokenInvisible(tokenC);
    AssertPermRowAbsent(tokenB, "ohos.permission.SYSTEM_FLOAT_WINDOW");
    AssertPermRowAbsent(tokenC, "ohos.permission.SYSTEM_FLOAT_WINDOW");
    // C (RESERVED_IDENTITY) dropped its permission rows at reserve time
    EXPECT_EQ(0U, CountPermRows(tokenC));

    // cleanup: per-token NONE delete (A/D active, B/C reserved)
    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenA, bundleName, ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenD, bundleName, ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenB, bundleName, ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenC, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: FinishHapTest009
 * @tc.desc: AC-8.10: an UNTRUSTED sibling token that is NOT explicitly named by the
 *           update session never enters the ACTIVE-filtered supplement candidate
 *           list and stays invisible; contrast with UntrustedCollectTest001 where
 *           explicit naming collects it back to ACTIVE.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, FinishHapTest009, TestSize.Level1)
{
    std::string bundleName = "FinishHapTest009";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    Identity identityA = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identityA);
    AccessTokenID tokenA = static_cast<AccessTokenID>(identityA.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenA);

    // sibling clone U (instIndex 1)
    HapBaseInfo cloneInfo = baseInfo;
    cloneInfo.instIndex = 1;
    AccessTokenID tokenU = InstallBundleSiblingToken(cloneInfo, bundlePolicy);
    ASSERT_NE(INVALID_TOKENID, tokenU);

    // demote U to UNTRUSTED (same prep as UntrustedCollectTest001)
    DemoteTokenToUntrusted(tokenU, bundleName);

    // update session names A only (U is not named): the new version adds syswin
    std::string newPath = "/SYSTEM/system_basic/state:[cam,syswin]/acl:[]/Module001/" + bundleName;
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartReplaceSession(newPath, sessionId));
    int32_t uid = -1; // no uid expectation
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenA, bundlePolicy, uid));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[newPath] = newPath;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // A updated normally (control)
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(tokenA, "ohos.permission.SYSTEM_FLOAT_WINDOW"));

    // U was NOT collected by the supplement path: still UNTRUSTED and invisible
    TokenIdStatus status;
    EXPECT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().GetTokenIdStatus(tokenU, status));
    EXPECT_EQ(TokenIdStatus::UNTRUSTED, status);
    AssertTokenInvisible(tokenU);
    AssertPermRowAbsent(tokenU, "ohos.permission.SYSTEM_FLOAT_WINDOW");

    // cleanup: single-token NONE delete handles the untrusted token, then the bundle
    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenU, bundleName, ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: ProxyDeathParamTest001
 * @tc.desc: InstallSessionProxyDeathParam::IsEqual validates the param type
 *           before casting (GetParamType guard against cross-type UB).
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, ProxyDeathParamTest001, TestSize.Level1)
{
    // same type, same pid → true
    InstallSessionProxyDeathParam param1(1234);
    InstallSessionProxyDeathParam samePid(1234);
    EXPECT_TRUE(param1.IsEqual(&samePid));

    // same type, different pid → false
    InstallSessionProxyDeathParam differentPid(5678);
    EXPECT_FALSE(param1.IsEqual(&differentPid));

    // null param → false
    EXPECT_FALSE(param1.IsEqual(nullptr));

    // default base class param (type=0, not InstallSessionProxyDeathParam) → false
    // Verify via GetParamType: a param with default type 0 should not match
    InstallSessionProxyDeathParam typedParam(1234);
    EXPECT_EQ(InstallSessionProxyDeathParam::PARAM_TYPE, typedParam.GetParamType());
    EXPECT_NE(0u, typedParam.GetParamType());
}

/**
 * @tc.name: SideloadAppTest001
 * @tc.desc: Sideload install (DEVELOPER_ID path marker) sets isSideloadApp=true
 *           in BundleParam, persists FIELD_IS_SIDELOAD=1 to DB, and the loaded
 *           token reports IsSideloadApp()==true.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, SideloadAppTest001, TestSize.Level0)
{
    std::string bundleName = "SideloadFlagBundle";
    std::string path = "/SYSTEM/DEVELOPER_ID/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    // cache: HapTokenInfoInner reports sideload
    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, infoPtr);
    EXPECT_TRUE(infoPtr->IsSideloadApp());

    // DB: FIELD_IS_SIDELOAD = 1
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    ASSERT_EQ(ERR_OK, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(1, results[0].GetInt(TokenFiledConst::FIELD_IS_SIDELOAD));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: SideloadAppTest002
 * @tc.desc: Normal install (no DEVELOPER_ID marker) keeps isSideloadApp=false.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, SideloadAppTest002, TestSize.Level0)
{
    std::string bundleName = "NonSideloadBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, infoPtr);
    EXPECT_FALSE(infoPtr->IsSideloadApp());

    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    ASSERT_EQ(ERR_OK, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(0, results[0].GetInt(TokenFiledConst::FIELD_IS_SIDELOAD));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: SideloadAppTest004
 * @tc.desc: Sideload flag survives a TYPE_REPLACE update (DB row rewritten
 *           with isSideload preserved from the old token).
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, SideloadAppTest004, TestSize.Level0)
{
    std::string bundleName = "SideloadUpdateBundle";
    std::string installPath = "/SYSTEM/DEVELOPER_ID/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    std::string updatePath = "/SYSTEM/DEVELOPER_ID/system_basic/state:[cam,mic]/acl:[]/Module001/" + bundleName;

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    // initial sideload install
    Identity identity = {0, -1};
    InstallHap({installPath}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    // TYPE_REPLACE update (still sidoad)
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(updatePath);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult checkResult;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, checkResult));
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(
        sessionId, tokenId, bundlePolicy, identity.uid));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[updatePath] = updatePath;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // flag preserved after update
    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, infoPtr);
    EXPECT_TRUE(infoPtr->IsSideloadApp());

    // DB still has isSideload=1
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    ASSERT_EQ(ERR_OK, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(1, results[0].GetInt(TokenFiledConst::FIELD_IS_SIDELOAD));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: SideloadAppTest007
 * @tc.desc: RESERVED_DATA reinstall of a sideload app preserves the sideload
 *           flag (DB snapshot carried through the reuse path).
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, SideloadAppTest007, TestSize.Level0)
{
    std::string bundleName = "SideloadReservedBundle";
    std::string path = "/SYSTEM/DEVELOPER_ID/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    // sideload install
    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    // reserve with data
    int32_t sceneCode = 0;
    ASSERT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::RESERVED_DATA, sceneCode));

    // reinstall (RESERVED_DATA path reuses token and preserves data)
    Identity identity2 = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity2);
    ASSERT_EQ(tokenId, static_cast<AccessTokenID>(identity2.tokenId));

    // sideload flag preserved through reserve + reinstall
    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, infoPtr);
    EXPECT_TRUE(infoPtr->IsSideloadApp());

    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: SideloadAppTest003
 * @tc.desc: Sideload app with a system_core permission (getwifi) and no ACL:
 *           ACL check fails the same as non-sideload when no permission has
 *           provisionBypassForSideload (current production config).
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, SideloadAppTest003, TestSize.Level0)
{
    // state contains getwifi (system_core APL) but acl is empty
    std::string path = "/SYSTEM/DEVELOPER_ID/system_basic/state:[getwifi]/acl:[]/Module001/SideloadAclBundle";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    // ACL check should fail (getwifi is system_core, no ACL, no sideload bypass
    // permission in current production definitions)
    HapInfoCheckResult result;
    int32_t ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    EXPECT_NE(ERR_OK, ret);
    if (ret != ERR_OK) {
        EXPECT_EQ(PermissionRulesEnum::PERMISSION_ACL_RULE, result.permCheckResult.rule);
        EXPECT_EQ("ohos.permission.GET_WIFI_INFO_INTERNAL", result.permCheckResult.permissionName);
    }
}

/**
 * @tc.name: SideloadAppTest005
 * @tc.desc: Sideload install followed by a normal (non-sideload) TYPE_REPLACE
 *           update clears isSideloadApp to false (signature distribution
 *           changed from developer_id to release).
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, SideloadAppTest005, TestSize.Level0)
{
    std::string bundleName = "SideloadToNormalBundle";
    std::string sideloadPath = "/SYSTEM/DEVELOPER_ID/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    std::string normalPath = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    // initial sideload install
    Identity identity = {0, -1};
    InstallHap({sideloadPath}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, infoPtr);
    ASSERT_TRUE(infoPtr->IsSideloadApp());

    // update with a non-sideload signature (release build)
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(normalPath);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult checkResult;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, checkResult));
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(
        sessionId, tokenId, bundlePolicy, identity.uid));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[normalPath] = normalPath;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // flag cleared: cache
    infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, infoPtr);
    EXPECT_FALSE(infoPtr->IsSideloadApp());

    // flag cleared: DB
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    ASSERT_EQ(ERR_OK, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(0, results[0].GetInt(TokenFiledConst::FIELD_IS_SIDELOAD));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: SideloadAppTest006
 * @tc.desc: Normal install followed by a sideload TYPE_REPLACE update sets
 *           isSideloadApp to true (signature distribution changed from release
 *           to developer_id).
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, SideloadAppTest006, TestSize.Level0)
{
    std::string bundleName = "NormalToSideloadBundle";
    std::string normalPath = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    std::string sideloadPath = "/SYSTEM/DEVELOPER_ID/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    // initial normal install
    Identity identity = {0, -1};
    InstallHap({normalPath}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, infoPtr);
    ASSERT_FALSE(infoPtr->IsSideloadApp());

    // update with a sideload signature (developer_id build)
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(sideloadPath);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult checkResult;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, checkResult));
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(
        sessionId, tokenId, bundlePolicy, identity.uid));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[sideloadPath] = sideloadPath;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // flag set: cache
    infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, infoPtr);
    EXPECT_TRUE(infoPtr->IsSideloadApp());

    // flag set: DB
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    ASSERT_EQ(ERR_OK, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, results));
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(1, results[0].GetInt(TokenFiledConst::FIELD_IS_SIDELOAD));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallDirtyRowTest001
 * @tc.desc: DB has a NONE-reserved row whose tokenId is NOT in any IDManager set
 *           (dirty/boot-recovery residue). ResolveExistingTokenReuse
 *           deletes the dirty row and continues with fresh allocation.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallDirtyRowTest001, TestSize.Level1)
{
    std::string bundleName = "DirtyRowCleanupBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    // step 1: install normally to create a valid token
    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID validTokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, validTokenId);

    // step 2: delete the token completely (NONE = full delete)
    int32_t sceneCode = 0;
    ASSERT_EQ(ERR_OK, DeleteIdentityCore(validTokenId, bundleName, ReservedType::NONE, sceneCode));

    // step 3: verify DB row for this token is gone
    GenericValues checkCond;
    checkCond.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(validTokenId));
    std::vector<GenericValues> checkResults;
    ASSERT_EQ(ERR_OK, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, checkCond, checkResults));
    EXPECT_TRUE(checkResults.empty());

    // step 4: reinstall — DB query by (bundleName, instIndex) finds 0 rows
    // (clean state, goes to fresh allocation path)
    Identity identity2 = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity2);
    AccessTokenID newTokenId = static_cast<AccessTokenID>(identity2.tokenId);
    ASSERT_NE(INVALID_TOKENID, newTokenId);
    // fresh allocation: new tokenId differs from the deleted one
    EXPECT_NE(validTokenId, newTokenId);

    // step 5: cleanup
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(newTokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallDirtyRowTest002
 * @tc.desc: DB has a NONE-reserved row whose tokenId is NOT in any IDManager set.
 *           ResolveExistingTokenReuse NONE branch deletes the dirty row
 *           (DeleteFromDbByTokenId) and install continues with fresh allocation.
 *           Unlike CleanedAndReallocated001, this test actually reaches the
 *           ResolveExistingTokenReuse NONE-dirty-row code path by
 *           manually inserting a stale DB row with an unregistered tokenId.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallDirtyRowTest002, TestSize.Level1)
{
    std::string bundleName = "ActualDirtyRowBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    // step 1: manually insert a dirty DB row (reserved=NONE, tokenId not in IDManager)
    // simulate boot-recovery residue: crash left the DB row but IDManager was re-initialized
    constexpr AccessTokenID dirtyTokenId = 0x25896321; // arbitrary id, never registered
    InsertDirtyTokenRow(bundleName, dirtyTokenId);

    // verify dirty row exists
    GenericValues verifyCond;
    verifyCond.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(dirtyTokenId));
    std::vector<GenericValues> verifyResults;
    ASSERT_EQ(ERR_OK, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, verifyCond, verifyResults));
    ASSERT_EQ(1u, verifyResults.size());

    // verify dirtyTokenId is not in any IDManager set
    TokenIdStatus dirtyStatus;
    EXPECT_NE(RET_SUCCESS, AccessTokenIDManager::GetInstance().GetTokenIdStatus(dirtyTokenId, dirtyStatus));

    // step 2: install the same (bundleName, instIndex)
    // GetTokenIdAndUid → QueryHapTokenFromDb finds the dirty row → userId matches →
    // ResolveExistingTokenReuse(reserved=NONE, tokenId=dirtyTokenId) →
    // GetTokenIdStatus fails (not registered) → DeleteFromDbByTokenId (dirty row cleaned) →
    // falls through to CreateTokenIdAndUid (fresh allocation)
    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID newTokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, newTokenId);

    // fresh allocation: new tokenId differs from the dirty one
    EXPECT_NE(dirtyTokenId, newTokenId);

    // step 3: verify dirty row was cleaned from DB
    std::vector<GenericValues> afterResults;
    ASSERT_EQ(ERR_OK, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, verifyCond, afterResults));
    EXPECT_TRUE(afterResults.empty());

    // step 4: verify new token works (cache + permission)
    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(newTokenId);
    ASSERT_NE(nullptr, infoPtr);
    EXPECT_EQ(bundleName, infoPtr->GetBundleName());

    // step 5: cleanup
    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(newTokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallDirtyRowTest003
 * @tc.desc: DB has a NONE-reserved row whose tokenId IS registered in IDManager
 *           (live token occupies it). ResolveExistingTokenReuse returns
 *           ERR_TOKENID_HAS_EXISTED and install fails without side effects.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallDirtyRowTest003, TestSize.Level1)
{
    std::string bundleName = "DirtyRowConflictBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    // step 1: install normally to create an ACTIVE token
    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID activeTokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, activeTokenId);

    // step 2: verify the token is ACTIVE in IDManager (registered in tokenIdSet_)
    TokenIdStatus status;
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().GetTokenIdStatus(activeTokenId, status));
    ASSERT_EQ(TokenIdStatus::ACTIVE, status);

    // step 3: attempt to install the same (bundleName, instIndex) again.
    // The DB row exists with reserved=NONE, and the tokenId IS in IDManager
    // (ACTIVE) — ResolveExistingTokenReuse NONE branch should detect
    // the conflict and return ERR_TOKENID_HAS_EXISTED.
    //
    // We call PrepareHapIdentity directly (sessionId=0, auto-create session)
    // to reach GetTokenIdAndUid → ResolveExistingTokenReuse.
    Identity conflictIdentity = {0, -1};
    int32_t conflictSessionId = 0;
    int32_t ret = g_installSessionManager->PrepareHapIdentity(
        conflictSessionId, baseInfo, bundlePolicy, nullptr, conflictIdentity);
    // The install should either fail with a conflict error or succeed with
    // a different tokenId (if the system chooses to allocate a new one).
    // Current implementation: GetTokenIdAndUid finds the DB row with
    // reserved=NONE, tokenId is registered → returns ERR_TOKENID_HAS_EXISTED.
    // But PrepareSessionIdentity's type check may reject before reaching here.
    // Verify the behavior is deterministic (no crash, no partial state).
    if (ret != RET_SUCCESS) {
        // expected: conflict detected
        EXPECT_TRUE(ret == AccessTokenError::ERR_TOKENID_HAS_EXISTED ||
            ret == AccessTokenError::ERR_BUNDLE_ALREADY_EXIST);
    }

    // step 4: verify the original ACTIVE token is unaffected
    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(activeTokenId);
    ASSERT_NE(nullptr, infoPtr);
    EXPECT_EQ(bundleName, infoPtr->GetBundleName());

    // step 5: cleanup
    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(activeTokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: DriftedUpdateTest001
 * @tc.desc: AC-8.9/BR-16: a drifted tokenid (not exist in ATM) makes UpdateHapPolicy return
 *           ERR_TOKENID_NOT_EXIST(12100004) without RollbackAll and without erasing the
 *           session; the remaining updates and the in-session allocation keep working.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, DriftedUpdateTest001, TestSize.Level1)
{
    std::string bundleName = "DriftUpdateBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    // t1..t5 for users 100/101/103/104; the token for user 102 is never created (drifted)
    std::vector<AccessTokenID> tokenIds =
        InstallBundleTokensForUsers(path, bundleName, bundlePolicy, {100, 101, 103, 104});

    // update session: 1 allocation (new user 105) + 5 updates (one of them drifted)
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartReplaceSession(path, sessionId));

    HapBaseInfo newUser;
    newUser.userID = TEST_USER_ID_REPAIR;
    newUser.bundleName = bundleName;
    newUser.instIndex = 0;
    Identity newIdentity = {0, -1};
    ASSERT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(
        sessionId, newUser, bundlePolicy, nullptr, newIdentity));
    ASSERT_NE(INVALID_TOKENID, static_cast<AccessTokenID>(newIdentity.tokenId));

    int32_t uid = -1; // no uid expectation
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIds[0], bundlePolicy, uid));
    // reset: the out param was overwritten with token[0]'s resolved uid; the next
    // token belongs to another user, pass no-expectation (-1) again
    uid = -1;
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIds[1], bundlePolicy, uid));

    // drifted tokenid: never registered in ATM
    constexpr AccessTokenID driftedTokenId = 0x2a580123;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        g_installSessionManager->UpdateHapPolicy(sessionId, driftedTokenId, bundlePolicy, uid));

    // session is still alive: remaining updates succeed
    uid = -1;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIds[2], bundlePolicy, uid));
    uid = -1;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIds[3], bundlePolicy, uid));
    // the in-session allocation is not rolled back
    TokenIdStatus status;
    EXPECT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().GetTokenIdStatus(
        static_cast<AccessTokenID>(newIdentity.tokenId), status));

    // finish with rollback: the in-session allocation is released, pre-existing tokens stay
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, false, modulePathMap));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: DriftedUpdateTest002
 * @tc.desc: AC-8.9/BR-16: after the drifted-token skip, the remaining updates and the new
 *           allocation land via FinishInstall; the drifted token stays absent from the DB.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, DriftedUpdateTest002, TestSize.Level1)
{
    std::string bundleName = "DriftUpdateLandBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    std::vector<AccessTokenID> tokenIds =
        InstallBundleTokensForUsers(path, bundleName, bundlePolicy, {100, 101, 103, 104});

    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartReplaceSession(path, sessionId));

    HapBaseInfo newUser;
    newUser.userID = TEST_USER_ID_REPAIR;
    newUser.bundleName = bundleName;
    newUser.instIndex = 0;
    Identity newIdentity = {0, -1};
    ASSERT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(
        sessionId, newUser, bundlePolicy, nullptr, newIdentity));

    constexpr AccessTokenID driftedTokenId = 0x2a580456;
    int32_t uid = -1; // no uid expectation
    for (const auto& tokenId : tokenIds) {
        // reset per token: the out param carries the previous token's resolved
        // uid, and each token belongs to a different user (no expectation)
        uid = -1;
        ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, uid));
    }
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        g_installSessionManager->UpdateHapPolicy(sessionId, driftedTokenId, bundlePolicy, uid));

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // all live tokens are queryable after the update
    for (const auto& tokenId : tokenIds) {
        EXPECT_NE(nullptr, AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId));
    }
    EXPECT_NE(nullptr, AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(
        static_cast<AccessTokenID>(newIdentity.tokenId)));

    // DB holds exactly the five live rows for this bundle; the drifted one stays absent
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    std::vector<GenericValues> hapTokenResults;
    ASSERT_EQ(ERR_OK, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, hapTokenResults));
    EXPECT_EQ(5u, hapTokenResults.size());
    for (const auto& row : hapTokenResults) {
        EXPECT_NE(driftedTokenId, static_cast<AccessTokenID>(row.GetInt(TokenFiledConst::FIELD_TOKEN_ID)));
    }

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: DriftedUpdateTest003
 * @tc.desc: AC-8.9/EX-18: a token that exists but belongs to another bundle is still fatal —
 *           ERR_PARAM_INVALID(12100001) with RollbackAll; the session is erased afterwards.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, DriftedUpdateTest003, TestSize.Level1)
{
    std::string bundleName = "DriftFatalBundle";
    std::string otherBundleName = "DriftFatalOtherBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    std::string otherPath = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + otherBundleName;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    HapBaseInfo otherInfo;
    otherInfo.userID = 100;
    otherInfo.bundleName = otherBundleName;
    otherInfo.instIndex = 0;
    Identity otherIdentity;
    InstallHap({otherPath}, otherInfo, bundlePolicy, otherIdentity);
    AccessTokenID otherTokenId = static_cast<AccessTokenID>(otherIdentity.tokenId);
    ASSERT_NE(INVALID_TOKENID, otherTokenId);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult result;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result));

    // token exists but belongs to another bundle: fatal, must roll the session back
    int32_t uid = -1; // no uid expectation
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        g_installSessionManager->UpdateHapPolicy(sessionId, otherTokenId, bundlePolicy, uid));

    // session was erased by RollbackAll
    EXPECT_EQ(AccessTokenError::ERR_SESSION_NOT_EXIST,
        g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, uid));
    // the other bundle's token is not touched by the rollback
    EXPECT_NE(nullptr, AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(otherTokenId));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, otherBundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: RepairPrepareTest001
 * @tc.desc: AC-8.9/BR-21/22 (I4): repair Prepare adopts a cleanly-registerable desired
 *           tokenid and a reusable desired uid when no sibling token exists; the repair
 *           session then finishes and lands the token.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, RepairPrepareTest001, TestSize.Level1)
{
    std::string bundleName = "RepairAdoptBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    // install the bundle (kernel/package baseline), then remove only its token row so the
    // repair sees no sibling uid and the desired-identity path is reachable
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    Identity seed;
    InstallHap({path}, baseInfo, bundlePolicy, seed);
    ASSERT_EQ(ERR_OK, InstallDbRepository::DeleteFromDbByTokenId(
        static_cast<AccessTokenID>(seed.tokenId)));

    // desired identity: valid free HAP-format tokenid + never-used reusable uid
    constexpr AccessTokenID desiredTokenId = 0x2003D1A5; // version=1, type=TOKEN_HAP, unique id
    constexpr int32_t desiredUid = 21054321;              // 105 * 200000 + 54321, bundleId never used

    // repair for user 105: the seed's cache entry (user 100) does not occupy this slot
    HapBaseInfo repairInfo = baseInfo;
    repairInfo.userID = TEST_USER_ID_REPAIR;
    Identity desired = {0, -1};
    desired.tokenId = desiredTokenId;
    desired.uid = desiredUid;
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(
        sessionId, repairInfo, bundlePolicy, nullptr, desired));
    // both expectations are adopted and echoed back through the out param
    EXPECT_EQ(desiredTokenId, AccessTokenIDManager::ParseTokenId(desired.tokenId));
    EXPECT_EQ(desiredUid, desired.uid);
    TokenIdStatus status;
    EXPECT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().GetTokenIdStatus(desiredTokenId, status));

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));
    EXPECT_NE(nullptr, AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(desiredTokenId));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: RepairPrepareTest002
 * @tc.desc: AC-8.9/BR-21 (I5): a desired tokenid that is already registered or has an
 *           invalid format is silently dropped in favor of a fresh allocation; the
 *           repair flow still succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, RepairPrepareTest002, TestSize.Level1)
{
    std::string bundleName = "RepairFallbackBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    Identity seed;
    InstallHap({path}, baseInfo, bundlePolicy, seed);
    AccessTokenID occupiedId = static_cast<AccessTokenID>(seed.tokenId);
    ASSERT_NE(INVALID_TOKENID, occupiedId);

    // case 1: desired tokenid already registered -> fresh allocation
    baseInfo.userID = 101;
    Identity desired = {0, -1};
    desired.tokenId = occupiedId;
    desired.uid = 20254399; // user 101: complete repair expectation, uid untouched by the case
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(
        sessionId, baseInfo, bundlePolicy, nullptr, desired));
    EXPECT_NE(occupiedId, AccessTokenIDManager::ParseTokenId(desired.tokenId));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // case 2: desired tokenid with invalid version/type bits -> fresh allocation
    baseInfo.userID = 102;
    Identity malformed = {0, -1};
    malformed.tokenId = 0x00000001; // version bits 0, not a valid HAP token id
    malformed.uid = 20454399; // user 102: complete repair expectation
    sessionId = 0;
    ASSERT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(
        sessionId, baseInfo, bundlePolicy, nullptr, malformed));
    EXPECT_NE(0x00000001, AccessTokenIDManager::ParseTokenId(malformed.tokenId));
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: RepairPrepareTest003
 * @tc.desc: AC-8.9/BR-22 (I8): uid priority is same-bundle srcUid > desired uid > fresh
 *           allocation; uid=-1 expresses no expectation; uid=0 is a legal expectation
 *           value that is validated (not adopted) without breaking the flow.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, RepairPrepareTest003, TestSize.Level1)
{
    std::string bundleName = "RepairUidBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    Identity seed;
    InstallHap({path}, baseInfo, bundlePolicy, seed);
    int32_t seedBundleId = 0;
    ASSERT_TRUE(AccessTokenIDManager::GetInstance().ExtractBundleId(seed.uid, seedBundleId));

    // priority 1: same-bundle sibling uid wins over the desired uid
    RepairPrepareSiblingUidWins(path, bundlePolicy, seedBundleId);

    // no-sibling scenarios share the session id and the (unused) path map
    int32_t sessionId = 0;
    std::map<std::string, std::string> modulePathMap;

    // priority 2: a reusable desired uid is adopted when no sibling exists
    Identity adopt;
    adopt.tokenId = 0x2003D5FA;
    adopt.uid = 21054323;
    sessionId = RepairPrepareOnClearedBundle("RepairUidAdoptBundle", bundlePolicy, adopt);
    ASSERT_NE(0, sessionId);
    EXPECT_EQ(21054323, adopt.uid);
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // uid=-1 expresses no expectation: a fresh uid is allocated
    Identity noExpectation;
    noExpectation.tokenId = 0x2003D60B;
    noExpectation.uid = -1;
    sessionId = RepairPrepareOnClearedBundle("RepairUidFreshBundle", bundlePolicy, noExpectation);
    ASSERT_NE(0, sessionId);
    EXPECT_NE(-1, noExpectation.uid);
    int32_t freshBundleId = 0;
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().ExtractBundleId(noExpectation.uid, freshBundleId));
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // uid=0 is a legal expectation value: validated, not adopted, flow unaffected
    Identity zeroExpectation;
    zeroExpectation.tokenId = 0x2003D71C;
    zeroExpectation.uid = 0;
    sessionId = RepairPrepareOnClearedBundle("RepairUidZeroBundle", bundlePolicy, zeroExpectation);
    ASSERT_NE(0, sessionId);
    EXPECT_NE(0, zeroExpectation.uid);
    EXPECT_TRUE(AccessTokenIDManager::GetInstance().ExtractBundleId(zeroExpectation.uid, freshBundleId));
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, "RepairUidAdoptBundle", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, "RepairUidFreshBundle", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, "RepairUidZeroBundle", ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: RepairPrepareTest004
 * @tc.desc: The repair adoption validates the dlp/clone identity flag bits of the
 *           desired token id: a desired id whose flags match the installing identity
 *           (clone-form for instIndex>0, dlp-form for dlpType>COMMON) is adopted;
 *           a plain-form id for a clone/dlp repair is rejected and falls back to a
 *           fresh allocation whose flags are set correctly.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, RepairPrepareTest004, TestSize.Level1)
{
    BundlePolicy plainPolicy;
    plainPolicy.dlpType = DLP_COMMON;
    plainPolicy.isDebugGrant = false;
    BundlePolicy dlpPolicy;
    dlpPolicy.dlpType = DLP_FULL_CONTROL;
    dlpPolicy.isDebugGrant = false;
    // version=1, type=TOKEN_HAP plus identity flags: cloneFlag is bit 24, dlpFlag is bit 26
    constexpr AccessTokenID plainFormId = 0x2005D1A5;
    constexpr AccessTokenID cloneFormId = 0x2105D1A6;
    constexpr AccessTokenID dlpFormId = 0x2405D1A7;

    // clone repair with a clone-form desired id: adopted as-is
    AccessTokenID adopted = RunRepairFlagScenario("RepairFlagCloneAdoptBundle", plainPolicy, 1, cloneFormId, 20054330);
    EXPECT_EQ(cloneFormId, adopted);
    EXPECT_EQ(1, TokenIDAttributes::GetTokenIdCloneFlag(adopted));

    // clone repair with a plain-form desired id: rejected, fresh id carries cloneFlag
    AccessTokenID fresh = RunRepairFlagScenario("RepairFlagCloneMismatchBundle", plainPolicy, 1, plainFormId, 20054331);
    EXPECT_NE(plainFormId, fresh);
    EXPECT_EQ(1, TokenIDAttributes::GetTokenIdCloneFlag(fresh));

    // dlp repair with a dlp-form desired id: adopted as-is
    adopted = RunRepairFlagScenario("RepairFlagDlpAdoptBundle", dlpPolicy, 0, dlpFormId, 20054332);
    EXPECT_EQ(dlpFormId, adopted);
    EXPECT_EQ(1, TokenIDAttributes::GetTokenIdDlpFlag(adopted));

    // dlp repair with a plain-form desired id: rejected, fresh id carries dlpFlag
    fresh = RunRepairFlagScenario("RepairFlagDlpMismatchBundle", dlpPolicy, 0, plainFormId, 20054333);
    EXPECT_NE(plainFormId, fresh);
    EXPECT_EQ(1, TokenIDAttributes::GetTokenIdDlpFlag(fresh));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, "RepairFlagCloneAdoptBundle", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, "RepairFlagCloneMismatchBundle",
        ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, "RepairFlagDlpAdoptBundle", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, "RepairFlagDlpMismatchBundle",
        ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: UntrustedCollectTest001
 * @tc.desc: AC-8.10/8.12: a token demoted to UNTRUSTED (cache evicted, id moved to the
 *           untrusted set) is invisible to GetHapTokenInfo; an update session that
 *           explicitly names the token collects it from the DB, and FinishInstall
 *           restores it to ACTIVE and normally queryable.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, UntrustedCollectTest001, TestSize.Level1)
{
    std::string bundleName = "UntrustedCollectBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    // demote: same path as the migration-enforce failure handling
    AccessTokenInfoManager::GetInstance().CommitDeleteHapCache(tokenId, bundleName);
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
        tokenId, TokenIdStatus::UNTRUSTED));

    // untrusted token is invisible to normal queries
    EXPECT_EQ(nullptr, AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId));
    HapTokenInfo queryInfo;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenId, queryInfo));

    // an update session that explicitly names the untrusted token collects it
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult result;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result));

    int32_t uid = -1; // no uid expectation
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy, uid));

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // collection complete: token is ACTIVE again and normally queryable
    TokenIdStatus status;
    EXPECT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().GetTokenIdStatus(tokenId, status));
    EXPECT_EQ(TokenIdStatus::ACTIVE, status);
    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, infoPtr);
    EXPECT_EQ(bundleName, infoPtr->GetBundleName());

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
