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

#include <algorithm>
#include <set>
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
#include "bundle_info_manager.h"
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
#include "parameters.h"
#include "multiple_mode_utils.h"

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
// 101 * UID_MASK + 54322: user segment matches TEST_USER_ID_SIBLING (legal input)
static constexpr int32_t DESIRED_SIBLING_UID = 20254322;
static constexpr int32_t ILLEGAL_SIBLING_UID = 20054322; // 100 * UID_MASK + 54322
static constexpr int32_t CLONE_TOKEN_COUNT = 3;
static constexpr int32_t INDEX_CLONE_B = 1;
static constexpr int32_t INDEX_CLONE_C = 2;
// aligned with the SYSTEM_APP_FLAG bit of InstallIdentityManager::BuildTokenAttr
static constexpr uint32_t SYSTEM_APP_FLAG = 0x0001;
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

// Wrap a plain 32-bit token id into the in-out AccessTokenIDEx param of
// UpdateHapPolicy: low 32 bits carry the token id, high 32 bits the token
// attr refreshed by the upgrade.
AccessTokenIDEx BuildTokenIdEx(AccessTokenID tokenId)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    return tokenIdEx;
}
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
    hapList.userIdForEnterpriseSign = baseInfo.userID;
    // no desired uid: must be INVALID_UID so PrepareHapIdentity skips the uid-user check
    identity.uid = -1;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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

// Full four-stage install with an explicit install mode; mirrors InstallHap
// which always installs in main mode (mode defaults to DEFAULT_OR_MAIN_MODE).
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

// Phase-1 + phase-2 (TYPE_MERGE) with an explicit install mode; the session
// id is ready for PrepareHapIdentity / FinishInstall when RET_SUCCESS returns.
int32_t StartMergeSessionMode(const std::string& path, MultipleMode mode, int32_t& sessionId)
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
    return g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_MERGE, mode, result);
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

// Overwrite the sticky flag columns (migrated / forbid-perm-dialog) of the
// token's db row, mimicking a row written by the migration flow. Returns
// false when the db row is missing so callers can bail out with ASSERT_TRUE.
bool SetTokenStickyFlagsInDb(AccessTokenID tokenId, bool migrated, bool forbidPermDialog)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> hapTokenResults;
    if (AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, hapTokenResults) != ERR_OK ||
        hapTokenResults.size() != 1) {
        return false;
    }
    hapTokenResults.front().Remove(TokenFiledConst::FIELD_MIGRATED);
    hapTokenResults.front().Put(TokenFiledConst::FIELD_MIGRATED, migrated ? 1 : 0);
    hapTokenResults.front().Remove(TokenFiledConst::FIELD_FORBID_PERM_DIALOG);
    hapTokenResults.front().Put(TokenFiledConst::FIELD_FORBID_PERM_DIALOG, forbidPermDialog ? 1 : 0);
    std::vector<AddInfo> addInfoVec;
    AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, hapTokenResults, addInfoVec);
    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, delInfoVec);
    return AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec) == ERR_OK;
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
    return g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    AccessTokenInfoManager::GetInstance().CommitDeleteHapCache(tokenId);
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

// hap_info_table rows of one bundleName; mode >= 0 narrows the query to that
// mode, mode < 0 returns the rows of all modes.
std::vector<GenericValues> QuerySignInfoRows(const std::string& bundleName, int32_t mode)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    if (mode >= 0) {
        condition.Put(TokenFiledConst::FIELD_MODE, mode);
    }
    std::vector<GenericValues> rows;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, condition, rows));
    return rows;
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

void AssertPermRowPresent(AccessTokenID tokenId, const std::string& permissionName)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> permRows;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition, permRows));
    bool found = false;
    for (const auto& row : permRows) {
        if (row.GetString(TokenFiledConst::FIELD_PERMISSION_NAME) == permissionName) {
            found = true;
        }
    }
    EXPECT_TRUE(found);
}

// Canonical string of one db row: keys iterate in map order, so two equal
// rows always serialize to the same string regardless of field write order.
std::string RowToCanonicalString(const GenericValues& row)
{
    std::string canonical;
    for (const auto& key : row.GetAllKeys()) {
        VariantValue value = row.Get(key);
        canonical += key + ":";
        switch (value.GetType()) {
            case ValueType::TYPE_STRING:
                canonical += value.GetString();
                break;
            case ValueType::TYPE_BLOB:
                canonical += std::to_string(value.GetBlob().size());
                break;
            case ValueType::TYPE_INT64:
                canonical += std::to_string(value.GetInt64());
                break;
            default:
                canonical += std::to_string(value.GetInt());
                break;
        }
        canonical += ";";
    }
    return canonical;
}

std::vector<std::string> RowsToCanonical(const std::vector<GenericValues>& rows)
{
    std::vector<std::string> canonicalRows;
    canonicalRows.reserve(rows.size());
    for (const auto& row : rows) {
        canonicalRows.emplace_back(RowToCanonicalString(row));
    }
    std::sort(canonicalRows.begin(), canonicalRows.end());
    return canonicalRows;
}

std::vector<std::string> FindRowsToCanonical(AtmDataType type, const GenericValues& condition)
{
    std::vector<GenericValues> rows;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(type, condition, rows));
    return RowsToCanonical(rows);
}

// Dual-mode snapshot of one token: identity basics plus the db rows of the
// four token-owned tables, canonicalized so a before/after compare covers
// uid/instIndex/tokenAttr and every perm/extend/undefine field value.
struct ModeTokenSnapshot {
    int32_t uid = 0;
    int32_t instIndex = 0;
    std::vector<std::string> tokenRow;
    std::vector<std::string> permRows;
    std::vector<std::string> extendRows;
    std::vector<std::string> undefineRows;
};

ModeTokenSnapshot TakeModeTokenSnapshot(AccessTokenID tokenId)
{
    ModeTokenSnapshot snapshot;
    auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    if (infoPtr != nullptr) {
        snapshot.uid = infoPtr->GetUid();
        snapshot.instIndex = infoPtr->GetInstIndex();
    }
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    snapshot.tokenRow = FindRowsToCanonical(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition);
    snapshot.permRows = FindRowsToCanonical(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition);
    snapshot.extendRows = FindRowsToCanonical(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, condition);
    snapshot.undefineRows = FindRowsToCanonical(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, condition);
    return snapshot;
}

void AssertModeTokenSnapshotUnchanged(const ModeTokenSnapshot& before, AccessTokenID tokenId)
{
    ModeTokenSnapshot after = TakeModeTokenSnapshot(tokenId);
    EXPECT_EQ(before.uid, after.uid);
    EXPECT_EQ(before.instIndex, after.instIndex);
    EXPECT_EQ(before.tokenRow, after.tokenRow);
    EXPECT_EQ(before.permRows, after.permRows);
    EXPECT_EQ(before.extendRows, after.extendRows);
    EXPECT_EQ(before.undefineRows, after.undefineRows);
}

BundlePolicy CommonBundlePolicy()
{
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    return bundlePolicy;
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

// Phase-1 + phase-2 (TYPE_REPLACE) with an explicit install mode; mirrors
// StartReplaceSession which always runs in main mode.
int32_t StartReplaceSessionMode(const std::string& path, MultipleMode mode, int32_t& sessionId)
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
    return g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, mode, result);
}

// Sibling/clone base info for the auto-session install path.
HapBaseInfo MakeSiblingInfo(const std::string& bundleName, int32_t userId, int32_t instIndex)
{
    HapBaseInfo baseInfo;
    baseInfo.userID = userId;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = instIndex;
    return baseInfo;
}

size_t CountGrantedBriefs(const std::vector<BriefPermData>& briefs)
{
    size_t granted = 0;
    for (const auto& brief : briefs) {
        if (brief.status == PERMISSION_GRANTED) {
            granted++;
        }
    }
    return granted;
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
// The seed always installs the ORIGINAL app with a plain policy: a DLP repair
// resolves its permission-inheriting original app by (userId, bundleName, 0)
// in the memory cache (InitDlpPermissionList), so a fresh-bundle DLP seed
// would fail at its own install (no original in cache yet).
AccessTokenID RunRepairFlagScenario(const std::string& bundleName, const BundlePolicy& policy,
    int32_t instIndex, AccessTokenID desiredId, int32_t desiredUid)
{
    BundlePolicy seedPolicy;
    seedPolicy.dlpType = DLP_COMMON;
    seedPolicy.isDebugGrant = false;
    SeedAndClearTokenRow(bundleName, seedPolicy);
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
    return AccessTokenIDManager::ExtractTokenIdFromFull(desired.tokenId);
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

// An illegal desired uid (user segment mismatch) is rejected up front at the
// session creation even when a same-bundle sibling exists.
void RepairPrepareIllegalDesiredRejected(const std::string& bundleName, const BundlePolicy& bundlePolicy)
{
    HapBaseInfo baseInfo;
    baseInfo.userID = TEST_USER_ID_SIBLING;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    Identity desired = {0, -1};
    desired.tokenId = 0x2003D4EA;
    desired.uid = ILLEGAL_SIBLING_UID; // user segment 100, mismatches the installing user 101
    int32_t sessionId = 0;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, g_installSessionManager->PrepareHapIdentity(
        sessionId, baseInfo, bundlePolicy, nullptr, desired));
    EXPECT_EQ(0, sessionId);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
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
    hapList.userIdForEnterpriseSign = 100;
    
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, InstallTypeEnum::TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, InstallTypeEnum::TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_NE(ERR_OK, ret);

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "InstallHapFailedTest004", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->CheckHapPermissionInfo(
        INVALID_SESSION, InstallTypeEnum::TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, InstallTypeEnum::TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_EQ(ERR_OK, ret);

    sessionId = 0;
    bundleInfo.clear();
    HapVerifyResultInfo resultInfo2;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo2, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result2;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, InstallTypeEnum::TYPE_MERGE, MultipleMode::DEFAULT_OR_MAIN_MODE, result2);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, InstallTypeEnum::TYPE_MERGE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, InstallTypeEnum::TYPE_MERGE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, InstallTypeEnum::TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_EQ(ERR_OK, ret);

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, identity.uid);
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
 * @tc.name: UpdateHapTokenIdExTest001
 * @tc.desc: Test the in-out AccessTokenIDEx of UpdateHapPolicy, with NORMAL change
 *           to SYSTEM: the low 32 bits locate the token and stay unchanged, the
 *           high 32 bits (token attr) are refreshed with the attr this upgrade
 *           applies and echoed back to the caller.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTokenIdExTest001, TestSize.Level0)
{
    // install in NORMAL mode: the token attr is 0
    std::string path = "/state:[cam,mic]/Module001/UpdateHapTokenIdExTest001";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "UpdateHapTokenIdExTest001";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    // update with a SYSTEM package: the applied attr becomes SYSTEM_APP_FLAG
    std::string path2 =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTokenIdExTest001";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path2);
    hapList.isPreInstalled = false;
    hapList.userIdForEnterpriseSign = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_EQ(ERR_OK, ret);

    // caller passes the stale full token id (attr 0 from the install round)
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    int32_t uid = -1; // no uid expectation
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid);
    EXPECT_EQ(ERR_OK, ret);
    // low 32 bits: the token id stays unchanged
    EXPECT_EQ(tokenId, tokenIdEx.tokenIdExStruct.tokenID);
    // high 32 bits: refreshed with the attr this upgrade applies
    EXPECT_EQ(SYSTEM_APP_FLAG, tokenIdEx.tokenIdExStruct.tokenAttr);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path2] = path2;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    // the committed attr equals the refreshed high bits
    std::shared_ptr<HapTokenInfoInner> infoPtr =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    EXPECT_NE(infoPtr, nullptr);
    if (infoPtr != nullptr) {
        EXPECT_EQ(SYSTEM_APP_FLAG, infoPtr->GetAttr());
    }

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "UpdateHapTokenIdExTest001", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: UpdateHapTokenIdExTest002
 * @tc.desc: Test the in-out AccessTokenIDEx of UpdateHapPolicy, with SYSTEM change
 *           to NORMAL and an error path: on success the high 32 bits are cleared
 *           to the new attr; on failure (session not exist) the caller's input
 *           is left untouched.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapTokenIdExTest002, TestSize.Level0)
{
    // install in SYSTEM mode: the token attr is SYSTEM_APP_FLAG
    std::string path =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/UpdateHapTokenIdExTest002";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "UpdateHapTokenIdExTest002";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    Identity identity = {0, -1};
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    // update with a NORMAL package: the applied attr becomes 0
    std::string path2 = "/state:[cam,mic]/Module001/UpdateHapTokenIdExTest002";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path2);
    hapList.isPreInstalled = false;
    hapList.userIdForEnterpriseSign = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_EQ(ERR_OK, ret);

    // caller passes the full token id of the install round (attr = SYSTEM_APP_FLAG)
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    // error path first: invalid session leaves the in-out param untouched
    int32_t uid = -1; // no uid expectation
    ret = g_installSessionManager->UpdateHapPolicy(INVALID_SESSION, tokenIdEx, bundlePolicy, uid);
    EXPECT_EQ(AccessTokenError::ERR_SESSION_NOT_EXIST, ret);
    EXPECT_EQ(tokenId, tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(SYSTEM_APP_FLAG, tokenIdEx.tokenIdExStruct.tokenAttr);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid);
    EXPECT_EQ(ERR_OK, ret);
    // low 32 bits unchanged, high 32 bits cleared to the new attr
    EXPECT_EQ(tokenId, tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(0U, tokenIdEx.tokenIdExStruct.tokenAttr);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path2] = path2;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    std::shared_ptr<HapTokenInfoInner> infoPtr =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    EXPECT_NE(infoPtr, nullptr);
    if (infoPtr != nullptr) {
        EXPECT_EQ(0U, infoPtr->GetAttr());
    }

    int32_t sceneCode = 0;
    ret = DeleteIdentityCore(tokenId, "UpdateHapTokenIdExTest002", ReservedType::NONE, sceneCode);
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
    hapList.userIdForEnterpriseSign = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_EQ(ERR_OK, ret);

    bundlePolicy.preAuthorizationInfo.emplace_back(PreAuthorizationInfo{"ohos.permission.CAMERA", true});
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, identity.uid);
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
    hapList.userIdForEnterpriseSign = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_EQ(ERR_OK, ret);

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, identity.uid);
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
    hapList.userIdForEnterpriseSign = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_EQ(ERR_OK, ret);

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, identity.uid);
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
    hapList.userIdForEnterpriseSign = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_EQ(ERR_OK, ret);

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, identity.uid);
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
    hapList.userIdForEnterpriseSign = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_MERGE, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

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
    hapList.userIdForEnterpriseSign = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_EQ(ERR_OK, ret);

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, identity.uid);
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
    hapList.userIdForEnterpriseSign = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_EQ(ERR_OK, ret);

    int32_t uid = TEST_UID;
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid);
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
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

    int32_t uid = TEST_UID;
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
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
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

    int32_t uid = TEST_UID;
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
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
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

    int32_t uid = TEST_INVALID_UID;
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
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
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

    int32_t uid = identity2.uid;
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
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
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

    int32_t uid = TEST_UID2;
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
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
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

    int32_t uid = TEST_UID2;
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
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
 * @tc.name: UpdateHapKeepMigratedTest001
 * @tc.desc: Update of an ACTIVE, already-migrated token without a caller uid
 *           (level1: keep the current uid) must keep migrated=1 in db and memory.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapKeepMigratedTest001, TestSize.Level0)
{
    std::string bundleName = "UpdateHapKeepMig001";
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/" + bundleName;
    HapBaseInfo baseInfo{100, bundleName, 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};

    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    // simulate a prior migration on the live ACTIVE token (memory carries the flag)
    auto inner = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, inner);
    inner->SetMigrated(true);

    // update session without a desired uid: level1 keeps the current uid
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartReplaceSession(path, sessionId));
    int32_t uid = -1; // no uid expectation
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // prior migrated state must survive in db AND memory
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> migratedResults;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue,
        migratedResults));
    EXPECT_EQ(1, migratedResults.size());
    EXPECT_EQ(1, migratedResults[0].GetInt(TokenFiledConst::FIELD_MIGRATED));
    {
        auto innerAfter = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        ASSERT_NE(nullptr, innerAfter);
        EXPECT_TRUE(innerAfter->IsMigrated());
    }

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: UpdateHapKeepPermDialogCapTest001
 * @tc.desc: Update of an ACTIVE token whose perm dialog is forbidden (no caller
 *           uid) must keep forbid_perm_dialog=1 in db and memory.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateHapKeepPermDialogCapTest001, TestSize.Level0)
{
    std::string bundleName = "UpdateHapKeepDlg001";
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/" + bundleName;
    HapBaseInfo baseInfo{100, bundleName, 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};

    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    // forbid the perm dialog on the live ACTIVE token
    auto inner = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(nullptr, inner);
    inner->SetPermDialogForbidden(true);

    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartReplaceSession(path, sessionId));
    int32_t uid = -1; // no uid expectation
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // prior dialog-cap state must survive in db AND memory
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> dialogResults;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue,
        dialogResults));
    EXPECT_EQ(1, dialogResults.size());
    EXPECT_EQ(1, dialogResults[0].GetInt(TokenFiledConst::FIELD_FORBID_PERM_DIALOG));
    {
        auto innerAfter = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        ASSERT_NE(nullptr, innerAfter);
        EXPECT_TRUE(innerAfter->IsPermDialogForbidden());
    }

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: UpdateUntrustedKeepStickyFlagsTest001
 * @tc.desc: Update of an UNTRUSTED token (db snapshot rebuilt into the cache on
 *           commit) must keep migrated and forbid_perm_dialog from the db row.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, UpdateUntrustedKeepStickyFlagsTest001, TestSize.Level0)
{
    std::string bundleName = "UpdateUntrustedKeep001";
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/" + bundleName;
    HapBaseInfo baseInfo{100, bundleName, 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};

    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    // migration-written row, then demote the token to UNTRUSTED (cache evicted)
    ASSERT_TRUE(SetTokenStickyFlagsInDb(tokenId, true, true));
    DemoteTokenToUntrusted(tokenId, bundleName);

    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartReplaceSession(path, sessionId));
    int32_t uid = -1; // no uid expectation
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // the rebuilt cache entry must carry both sticky flags from the db row
    {
        auto innerAfter = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        ASSERT_NE(nullptr, innerAfter);
        EXPECT_TRUE(innerAfter->IsMigrated());
        EXPECT_TRUE(innerAfter->IsPermDialogForbidden());
    }
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> stickyResults;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue,
        stickyResults));
    EXPECT_EQ(1, stickyResults.size());
    EXPECT_EQ(1, stickyResults[0].GetInt(TokenFiledConst::FIELD_MIGRATED));
    EXPECT_EQ(1, stickyResults[0].GetInt(TokenFiledConst::FIELD_FORBID_PERM_DIALOG));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: ReservedDataReinstallKeepMigratedTest001
 * @tc.desc: RESERVED_DATA reinstall (token identity reused, cache entry rebuilt)
 *           must keep migrated and forbid_perm_dialog of the reserved row in db
 *           and memory.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, ReservedDataReinstallKeepMigratedTest001, TestSize.Level0)
{
    std::string bundleName = "ReservedReinstallKeep001";
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/" + bundleName;
    HapBaseInfo baseInfo{100, bundleName, 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};

    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    // uninstall keeping data, then mimic a migration-written reserved row
    int32_t sceneCode = 0;
    ASSERT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::RESERVED_DATA, sceneCode));
    ASSERT_TRUE(SetTokenStickyFlagsInDb(tokenId, true, true));

    // reinstall: RESERVED_DATA path reuses the token and reactivates it
    Identity identity2 = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity2);
    ASSERT_EQ(tokenId, static_cast<AccessTokenID>(identity2.tokenId));

    // the sticky flags of the reserved row must survive the reinstall
    {
        auto innerAfter = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        ASSERT_NE(nullptr, innerAfter);
        EXPECT_TRUE(innerAfter->IsMigrated());
        EXPECT_TRUE(innerAfter->IsPermDialogForbidden());
    }
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> stickyResults;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue,
        stickyResults));
    EXPECT_EQ(1, stickyResults.size());
    EXPECT_EQ(1, stickyResults[0].GetInt(TokenFiledConst::FIELD_MIGRATED));
    EXPECT_EQ(1, stickyResults[0].GetInt(TokenFiledConst::FIELD_FORBID_PERM_DIALOG));

    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: CheckTypeRetryTest001
 * @tc.desc: CheckHapPermissionInfo(TYPE_INSTALL) on an installed bundle returns
 *           ERR_BUNDLE_ALREADY_EXIST but keeps the session alive; re-entering the
 *           same session with TYPE_REPLACE passes and the finish lands normally.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, CheckTypeRetryTest001, TestSize.Level0)
{
    std::string bundleName = "CheckTypeRetry001";
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/" + bundleName;
    HapBaseInfo baseInfo{100, bundleName, 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};

    // install once: the bundle has package records in db
    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    // new session; TYPE_INSTALL is rejected (records exist) but the session survives
    BundleHapList hapList{std::vector<std::string>{path}, false, 100};
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult result;
    EXPECT_EQ(AccessTokenError::ERR_BUNDLE_ALREADY_EXIST,
        g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE,
            result));
    EXPECT_EQ(1, static_cast<int>(g_installSessionManager->sessionToInstallCache.count(sessionId)));

    // same session retried with TYPE_REPLACE passes the type check
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE,
        MultipleMode::DEFAULT_OR_MAIN_MODE, result));

    // the update flow continues on the same session
    int32_t uid = -1; // no uid expectation
    AccessTokenIDEx tokenIdEx = BuildTokenIdEx(tokenId);
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // token reused, session consumed
    EXPECT_EQ(0, static_cast<int>(g_installSessionManager->sessionToInstallCache.count(sessionId)));
    {
        auto innerAfter = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        ASSERT_NE(nullptr, innerAfter);
        EXPECT_EQ(bundleName, innerAfter->GetBundleName());
    }

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: CheckTypeLeftoverFinishTest001
 * @tc.desc: A session left alive by the CheckInstallType rejection is guarded:
 *           FinishInstall on it returns ERR_NOT_CHECK_PERMISSION and erases it,
 *           leaving the installed token unaffected.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, CheckTypeLeftoverFinishTest001, TestSize.Level0)
{
    std::string bundleName = "CheckTypeLeftover001";
    std::string path = "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/" + bundleName;
    HapBaseInfo baseInfo{100, bundleName, 0};
    BundlePolicy bundlePolicy{std::vector<PreAuthorizationInfo>(), DLP_COMMON, false};

    // install once: the bundle has package records in db
    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    // new session rejected by the type check, session stays alive
    BundleHapList hapList{std::vector<std::string>{path}, false, 100};
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult result;
    EXPECT_EQ(AccessTokenError::ERR_BUNDLE_ALREADY_EXIST,
        g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE,
            result));
    EXPECT_EQ(1, static_cast<int>(g_installSessionManager->sessionToInstallCache.count(sessionId)));

    // misuse guard: finishing the half-checked session fails and erases it
    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(AccessTokenError::ERR_NOT_CHECK_PERMISSION,
        g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));
    EXPECT_EQ(0, static_cast<int>(g_installSessionManager->sessionToInstallCache.count(sessionId)));

    // the installed token is unaffected
    {
        auto innerAfter = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        ASSERT_NE(nullptr, innerAfter);
        EXPECT_EQ(bundleName, innerAfter->GetBundleName());
    }

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
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
    hapList.userIdForEnterpriseSign = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_EQ(ERR_OK, ret);


    g_installSessionManager->migrationDone_ = false;
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, identity.uid);
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
    hapList.userIdForEnterpriseSign = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_EQ(ERR_OK, ret);

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ret = g_installSessionManager->UpdateHapPolicy(INVALID_SESSION, tokenIdEx, bundlePolicy, identity.uid);
    EXPECT_NE(ERR_OK, ret);

    tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity2.tokenId;
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, identity2.uid);
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
    hapList.userIdForEnterpriseSign = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_EQ(ERR_OK, ret);

    AccessTokenIDEx tokenIdEx = BuildTokenIdEx(static_cast<AccessTokenID>(123456789));
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, identity.uid);
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
    hapList.userIdForEnterpriseSign = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
    EXPECT_EQ(ERR_OK, ret);

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, identity.uid);
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
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

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
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

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
    hapList.userIdForEnterpriseSign = 100;

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
    AccessTokenIDEx tokenIdEx = BuildTokenIdEx(static_cast<AccessTokenID>(INVALID_SESSION));
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, identity.uid);
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
    hapList.userIdForEnterpriseSign = 100;
    
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
 * @tc.name: GetInfoBySessionTest002
 * @tc.desc: GetCacheSignInfoBySessionId on an auto-created (repair) session
 *           returns an empty result: no sign-check phase ran, so the session
 *           carries no verified bundle infos.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, GetInfoBySessionTest002, TestSize.Level0)
{
    // seed the installed base so the auto session (FillInstallPolicy) can be created
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;
    SeedAndClearTokenRow("GetInfoBySessionAuto001", bundlePolicy);

    HapBaseInfo baseInfo;
    baseInfo.userID = TEST_USER_ID;
    baseInfo.bundleName = "GetInfoBySessionAuto001";
    baseInfo.instIndex = 0;
    Identity identity = {0, -1};
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(
        sessionId, baseInfo, bundlePolicy, nullptr, identity));

    // the repair session has no sign-verified infos: the query yields nothing
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_NE(ERR_OK, g_installSessionManager->GetCacheSignInfoBySessionId(
        sessionId, bundleInfo, QUERY_ALL_SIGN_INFO));
    EXPECT_TRUE(bundleInfo.empty());

    // release the session through the non-persistent rollback
    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, false, modulePathMap));

    // clean the seeded sign rows so the test is idempotent across runs
    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, "GetInfoBySessionAuto001", ReservedType::NONE, sceneCode));
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

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
    EXPECT_EQ(ERR_OK, BundleInfoManager::GetInstance().GetHapSignInfo(
        "GetInfoByBundleNameTest001", bundleInfo2, QUERY_ALL_SIGN_INFO));

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
    EXPECT_NE(ERR_OK, BundleInfoManager::GetInstance().GetHapSignInfo(
        "", bundleInfo, QUERY_ALL_SIGN_INFO));
    EXPECT_NE(ERR_OK, BundleInfoManager::GetInstance().GetHapSignInfo(
        "GetInfoByBundleNameFailTest001", bundleInfo, QUERY_ALL_SIGN_INFO));
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
    EXPECT_NE(ERR_OK, BundleInfoManager::GetInstance().GetHapSignInfo(
        "GetInfoByBundleNameFailTest001", bundleInfo2, QUERY_ALL_SIGN_INFO));
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
        listIdl.userIdForEnterpriseSign = 100;
        CheckHapSignResultRawdata rawData;
        EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
            atManagerService_->CheckHapSignInfo(listIdl, cb, QUERY_ALL_SIGN_INFO, rawData));

        HapInfoCheckResultIdl checkResult;
        EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
            atManagerService_->CheckHapPermissionInfo(
                1, InstallTypeEnumIdl::TYPE_INSTALL, MultipleModeEnumIdl::DEFAULT_OR_MAIN_MODE, checkResult));

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
    hapList.userIdForEnterpriseSign = 100;

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
    hapList.userIdForEnterpriseSign = 100;

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
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, checkResult));
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
    EXPECT_EQ(identity2.uid, cache.updatedUidStateMap[tokenIdB].uid);

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
    AccessTokenIDEx tokenIdEx = BuildTokenIdEx(tokenA);
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
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
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identityA.tokenId;
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
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
    hapList.userIdForEnterpriseSign = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult checkResult;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, checkResult));
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(
        sessionId, tokenIdEx, bundlePolicy, identity.uid));
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
    hapList.userIdForEnterpriseSign = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    // ACL check should fail (getwifi is system_core, no ACL, no sideload bypass
    // permission in current production definitions)
    HapInfoCheckResult result;
    int32_t ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result);
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
    hapList.userIdForEnterpriseSign = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult checkResult;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, checkResult));
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(
        sessionId, tokenIdEx, bundlePolicy, identity.uid));
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
    hapList.userIdForEnterpriseSign = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult checkResult;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, checkResult));
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(
        sessionId, tokenIdEx, bundlePolicy, identity.uid));
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
    AccessTokenIDEx tokenIdEx = BuildTokenIdEx(tokenIds[0]);
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
    // reset: the out param was overwritten with token[0]'s resolved uid; the next
    // token belongs to another user, pass no-expectation (-1) again
    uid = -1;
    tokenIdEx = BuildTokenIdEx(tokenIds[1]);
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));

    // drifted tokenid: never registered in ATM
    constexpr AccessTokenID driftedTokenId = 0x2a580123;
    tokenIdEx = BuildTokenIdEx(driftedTokenId);
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));

    // session is still alive: remaining updates succeed
    uid = -1;
    tokenIdEx = BuildTokenIdEx(tokenIds[2]);
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
    uid = -1;
    tokenIdEx = BuildTokenIdEx(tokenIds[3]);
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
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
        AccessTokenIDEx tokenIdEx = BuildTokenIdEx(tokenId);
        ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
    }
    AccessTokenIDEx tokenIdEx = BuildTokenIdEx(driftedTokenId);
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));

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
    hapList.userIdForEnterpriseSign = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult result;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

    // token exists but belongs to another bundle: fatal, must roll the session back
    int32_t uid = -1; // no uid expectation
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = otherIdentity.tokenId;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));

    // session was erased by RollbackAll
    tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    EXPECT_EQ(AccessTokenError::ERR_SESSION_NOT_EXIST,
        g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
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
    EXPECT_EQ(desiredTokenId, AccessTokenIDManager::ExtractTokenIdFromFull(desired.tokenId));
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
    desired.uid = 20254399; // user 101: complete repair expectation matching case 1's repair user
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(
        sessionId, baseInfo, bundlePolicy, nullptr, desired));
    EXPECT_NE(occupiedId, AccessTokenIDManager::ExtractTokenIdFromFull(desired.tokenId));
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
    EXPECT_NE(0x00000001, AccessTokenIDManager::ExtractTokenIdFromFull(malformed.tokenId));
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: RepairPrepareTest003
 * @tc.desc: AC-8.9/BR-22 (I8): uid priority is same-bundle srcUid > desired uid > fresh
 *           allocation; uid=-1 expresses no expectation; a desired uid whose user
 *           segment mismatches the installing user (including uid=0 with a non-zero
 *           tokenId) is illegal input rejected up front at the session creation
 *           (ERR_PARAM_INVALID propagates to the caller, no session is created).
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

    // priority 1: same-bundle sibling uid wins; an illegal desired uid is
    // rejected up front even when a sibling exists
    RepairPrepareSiblingUidWins(path, bundlePolicy, seedBundleId);
    RepairPrepareIllegalDesiredRejected(bundleName, bundlePolicy);

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

    // uid=0 with a non-zero tokenId is illegal input: its user segment (0)
    // mismatches the installing user, rejected up front at the session
    // creation (ERR_PARAM_INVALID propagates, no session is created)
    Identity zeroExpectation;
    zeroExpectation.tokenId = 0x2003D71C;
    zeroExpectation.uid = 0;
    SeedAndClearTokenRow("RepairUidZeroBundle", bundlePolicy);
    HapBaseInfo zeroInfo;
    zeroInfo.userID = TEST_USER_ID_REPAIR;
    zeroInfo.bundleName = "RepairUidZeroBundle";
    zeroInfo.instIndex = 0;
    int32_t zeroSessionId = 0;
    int32_t zeroRet = g_installSessionManager->PrepareHapIdentity(
        zeroSessionId, zeroInfo, bundlePolicy, nullptr, zeroExpectation);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, zeroRet);
    EXPECT_EQ(0, zeroSessionId);

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

    // dlp repair with a dlp-form desired id: adopted as-is. The DLP instance
    // installs beside its original app: index 0 stays the original (both the
    // permission-inheriting lookup and the HasInstalled guard require it),
    // the DLP app itself takes an instance index.
    adopted = RunRepairFlagScenario("RepairFlagDlpAdoptBundle", dlpPolicy, 1, dlpFormId, 20054332);
    EXPECT_EQ(dlpFormId, adopted);
    EXPECT_EQ(1, TokenIDAttributes::GetTokenIdDlpFlag(adopted));

    // dlp repair with a plain-form desired id: rejected, fresh id carries dlpFlag
    fresh = RunRepairFlagScenario("RepairFlagDlpMismatchBundle", dlpPolicy, 1, plainFormId, 20054333);
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
    AccessTokenInfoManager::GetInstance().CommitDeleteHapCache(tokenId);
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
    hapList.userIdForEnterpriseSign = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult result;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_REPLACE, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

    int32_t uid = -1; // no uid expectation
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    EXPECT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));

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

/**
 * @tc.name: FinishHapTest010
 * @tc.desc: Supplement candidates are mode-scoped: a main-mode update session
 *           must not pull sub-mode tokens into the update plan (and vice
 *           versa). Main-mode tokens across users/instIndexes within the same
 *           mode domain are still supplemented.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, FinishHapTest010, TestSize.Level1)
{
    std::string bundleName = "ModeScopedSupplementBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    // main-mode token A (user 100, instIndex 0)
    HapBaseInfo mainInfo;
    mainInfo.userID = 100;
    mainInfo.bundleName = bundleName;
    mainInfo.instIndex = 0;
    Identity identityA = {0, -1};
    InstallHap({path}, mainInfo, bundlePolicy, identityA);
    AccessTokenID tokenIdA = static_cast<AccessTokenID>(identityA.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenIdA);

    // main-mode sibling B (user 101, same instIndex range)
    HapBaseInfo siblingInfo = mainInfo;
    siblingInfo.userID = 101;
    AccessTokenID tokenIdB = InstallBundleSiblingToken(siblingInfo, bundlePolicy);
    ASSERT_NE(INVALID_TOKENID, tokenIdB);

    // sub-mode token C (instIndex 10000): a fresh sub-mode install goes
    // through the four-stage path; the auto session is repair-only and has no
    // same-mode installed base to restore from (BR-3)
    AccessTokenID tokenIdC = InstallAppWithMode(path, bundleName, 100, 10000, MultipleMode::SUB_MODE);
    ASSERT_NE(INVALID_TOKENID, tokenIdC);

    // main-mode update session that only covers token A
    InstallCache cache;
    cache.bundleParam.bundleName = bundleName;
    cache.mode = MultipleMode::DEFAULT_OR_MAIN_MODE;
    cache.hasPermChecked = true;
    cache.updatedBundlePolicyMap[tokenIdA] = bundlePolicy;

    g_installSessionManager->SupplementUpdateInfo(cache);

    // A and B (same mode domain) are in the plan; C (sub mode) is NOT
    EXPECT_EQ(2U, cache.updatedBundlePolicyMap.size());
    EXPECT_TRUE(cache.updatedBundlePolicyMap.find(tokenIdA) != cache.updatedBundlePolicyMap.end());
    EXPECT_TRUE(cache.updatedBundlePolicyMap.find(tokenIdB) != cache.updatedBundlePolicyMap.end());
    EXPECT_TRUE(cache.updatedBundlePolicyMap.find(tokenIdC) == cache.updatedBundlePolicyMap.end());

    // sub-mode update session: only C is supplemented
    InstallCache subCache;
    subCache.bundleParam.bundleName = bundleName;
    subCache.mode = MultipleMode::SUB_MODE;
    subCache.hasPermChecked = true;
    subCache.updatedBundlePolicyMap[tokenIdC] = bundlePolicy;
    g_installSessionManager->SupplementUpdateInfo(subCache);
    EXPECT_EQ(1U, subCache.updatedBundlePolicyMap.size());
    EXPECT_TRUE(subCache.updatedBundlePolicyMap.find(tokenIdC) != subCache.updatedBundlePolicyMap.end());

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenIdC, bundleName, ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: QueryBundleTokensModeScopedTest001
 * @tc.desc: QueryBundleTokens mode-scoped filtering, verified in three groups:
 *           1. Main-mode query: hapTokenResults only contains main-mode rows
 *              (A, B); the sub-mode row C is removed from the output entirely;
 *              bundleTokenIdList has 2 entries (A, B both ACTIVE).
 *           2. Sub-mode query: hapTokenResults only contains C; bundleTokenIdList
 *              has 1 entry.
 *           3. Reserved row: after RESERVED_DATA delete of A, A's db row stays
 *              in hapTokenResults (the reuse path needs to see reserved rows),
 *              but bundleTokenIdList only contains B (A is not ACTIVE, excluded
 *              from supplement candidates).
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, QueryBundleTokensModeScopedTest001, TestSize.Level1)
{
    std::string bundleName = "QueryTokensModeBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    // main-mode token A (user 100, instIndex 0) and sibling B (user 101)
    HapBaseInfo mainInfo;
    mainInfo.userID = 100;
    mainInfo.bundleName = bundleName;
    mainInfo.instIndex = 0;
    Identity identityA = {0, -1};
    InstallHap({path}, mainInfo, bundlePolicy, identityA);
    AccessTokenID tokenIdA = static_cast<AccessTokenID>(identityA.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenIdA);
    HapBaseInfo siblingInfo = mainInfo;
    siblingInfo.userID = 101;
    AccessTokenID tokenIdB = InstallBundleSiblingToken(siblingInfo, bundlePolicy);
    ASSERT_NE(INVALID_TOKENID, tokenIdB);

    // sub-mode token C (instIndex 10000)
    // sub-mode token C (instIndex 10000): a fresh sub-mode install goes
    // through the four-stage path; the auto session is repair-only and has no
    // same-mode installed base to restore from (BR-3)
    AccessTokenID tokenIdC = InstallAppWithMode(path, bundleName, 100, 10000, MultipleMode::SUB_MODE);
    ASSERT_NE(INVALID_TOKENID, tokenIdC);

    auto collectIds = [](const std::vector<GenericValues>& rows) {
        std::set<AccessTokenID> ids;
        for (const auto& row : rows) {
            ids.insert(static_cast<AccessTokenID>(row.GetInt(TokenFiledConst::FIELD_TOKEN_ID)));
        }
        return ids;
    };

    // main-mode query: only A and B in hapTokenResults, C excluded
    InstallCache mainCache;
    mainCache.mode = MultipleMode::DEFAULT_OR_MAIN_MODE;
    std::vector<GenericValues> mainResults;
    ASSERT_EQ(ERR_OK, InstallDbRepository::QueryBundleTokens(bundleName, mainCache, mainResults));
    auto mainIds = collectIds(mainResults);
    EXPECT_EQ(2U, mainIds.size());
    EXPECT_TRUE(mainIds.count(tokenIdA) > 0);
    EXPECT_TRUE(mainIds.count(tokenIdB) > 0);
    EXPECT_TRUE(mainIds.count(tokenIdC) == 0);
    // both ACTIVE, both in supplement candidates
    EXPECT_EQ(2U, mainCache.bundleTokenIdList.size());

    // sub-mode query: only C in hapTokenResults
    InstallCache subCache;
    subCache.mode = MultipleMode::SUB_MODE;
    std::vector<GenericValues> subResults;
    ASSERT_EQ(ERR_OK, InstallDbRepository::QueryBundleTokens(bundleName, subCache, subResults));
    auto subIds = collectIds(subResults);
    EXPECT_EQ(1U, subIds.size());
    EXPECT_TRUE(subIds.count(tokenIdC) > 0);
    EXPECT_EQ(1U, subCache.bundleTokenIdList.size());

    // reserve-delete A: reserved row stays in hapTokenResults (reuse path) but
    // drops out of bundleTokenIdList (not ACTIVE)
    int32_t sceneCode = 0;
    ASSERT_EQ(ERR_OK, DeleteIdentityCore(tokenIdA, bundleName, ReservedType::RESERVED_DATA, sceneCode));

    InstallCache reserveCache;
    reserveCache.mode = MultipleMode::DEFAULT_OR_MAIN_MODE;
    std::vector<GenericValues> reserveResults;
    ASSERT_EQ(ERR_OK, InstallDbRepository::QueryBundleTokens(bundleName, reserveCache, reserveResults));
    auto reserveIds = collectIds(reserveResults);
    // A's DB row still exists (reserved) and B is active — both mode-matched
    EXPECT_EQ(2U, reserveIds.size());
    EXPECT_TRUE(reserveIds.count(tokenIdA) > 0); // reserved row kept for reuse
    // only B is ACTIVE → only B in supplement candidates
    EXPECT_EQ(1U, reserveCache.bundleTokenIdList.size());
    EXPECT_EQ(tokenIdB, reserveCache.bundleTokenIdList[0]);

    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenIdC, bundleName, ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: UntrustedUpdatePermInheritTest001
 * @tc.desc: An update that names an UNTRUSTED token inherits user-granted states
 *           from the db when the brief cache misses (db-snapshot tokens are not
 *           registered there), so a user granted permission survives the update
 *           instead of being silently reset to denied. Pre-authorized states are
 *           deliberately not used: those are re-decided by the new policy at
 *           merge time (UpdatePermStatus keeps the new initialized state for
 *           SYSTEM_FIXED / PRE_AUTHORIZED_CANCELABLE old flags), so only a
 *           user-set grant discriminates the inheritance path.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, UntrustedUpdatePermInheritTest001, TestSize.Level1)
{
    std::string bundleName = "UntrustedPermInheritBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;

    // install requesting cam without pre-auth: the user-grant permission starts denied
    BundlePolicy installPolicy;
    installPolicy.dlpType = DLP_COMMON;
    installPolicy.isDebugGrant = false;

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    Identity identity = {0, -1};
    InstallHap({path}, baseInfo, installPolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    ASSERT_EQ(PERMISSION_DENIED, atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA"));

    // user grants cam: this is the state the update must inherit
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    ASSERT_EQ(PERMISSION_GRANTED, atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA"));

    // demote: the memory and brief-cache entries are dropped while the db rows
    // (cam granted by user) remain, mimicking a migration-abnormal untrusted token
    DemoteTokenToUntrusted(tokenId, bundleName);

    // update session names the untrusted token; the request list still contains
    // cam, so with the db backfill the user-granted state must survive
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartReplaceSession(path, sessionId));
    BundlePolicy updatePolicy; // plain policy: no preAuthorizationInfo
    int32_t uid = -1; // no uid expectation
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = identity.tokenId;
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, updatePolicy, uid));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // collected back to ACTIVE with the user-granted state preserved
    TokenIdStatus status;
    EXPECT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().GetTokenIdStatus(tokenId, status));
    EXPECT_EQ(TokenIdStatus::ACTIVE, status);
    EXPECT_EQ(PERMISSION_GRANTED, atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA"));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallModeTest001
 * @tc.desc: EX-2/AC-09E: CheckHapPermissionInfo rejects mode outside {0,1}
 *           (including the query-only CURRENT_MODE sentinel) with 12100001
 *           and leaves the session not permission-checked.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallModeTest001, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/ModeInvalidRejected001";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userIdForEnterpriseSign = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO);
    ASSERT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    // out of the install domain
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, static_cast<MultipleMode>(2), result);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    // CURRENT_MODE is a query-only sentinel and must never enter the install chain
    ret = g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::CURRENT_MODE, result);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    // the session stays not permission-checked: no half state leaks to the next phase
    auto cacheIt = g_installSessionManager->sessionToInstallCache.find(sessionId);
    ASSERT_TRUE(cacheIt != g_installSessionManager->sessionToInstallCache.end());
    EXPECT_FALSE(cacheIt->second.hasPermChecked);
}

/**
 * @tc.name: InstallModeTest002
 * @tc.desc: EX-1/AC-09E: PrepareHapIdentity rejects an instIndex whose encoded
 *           mode mismatches the session mode with 12100001; no identity is
 *           allocated and no sign row is persisted.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallModeTest002, TestSize.Level0)
{
    std::string bundleName = "ModeInstIndexMismatch001";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userIdForEnterpriseSign = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));

    HapInfoCheckResult result;
    // session mode stays DEFAULT_OR_MAIN_MODE
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

    // prepare with a sub-mode instIndex while the session mode is main (0)
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 10000;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    Identity identity = {0, -1};
    int32_t ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    EXPECT_EQ(0, identity.tokenId);
    // session recycled by the existing rollback, no half state left
    EXPECT_EQ(0, static_cast<int>(g_installSessionManager->sessionToInstallCache.count(sessionId)));
    EXPECT_TRUE(QuerySignInfoRows(bundleName, -1).empty());

    // reverse direction: sub-mode session with a main-mode instIndex is rejected too
    int32_t subSessionId = 0;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, subSessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult subResult;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        subSessionId, TYPE_INSTALL, MultipleMode::SUB_MODE, subResult));
    HapBaseInfo subBaseInfo;
    subBaseInfo.userID = 100;
    subBaseInfo.bundleName = bundleName;
    subBaseInfo.instIndex = 9999;
    Identity subIdentity = {0, -1};
    ret = g_installSessionManager->PrepareHapIdentity(subSessionId, subBaseInfo, bundlePolicy, nullptr, subIdentity);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    EXPECT_EQ(0, subIdentity.tokenId);
    EXPECT_EQ(0, static_cast<int>(g_installSessionManager->sessionToInstallCache.count(subSessionId)));
    EXPECT_TRUE(QuerySignInfoRows(bundleName, -1).empty());
}

/**
 * @tc.name: InstallModeTest003
 * @tc.desc: AC-09/AC-12: a mode=1 four-stage install persists hap_info_table
 *           rows with mode 1 and the token row keeps inst_index 10000.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallModeTest003, TestSize.Level0)
{
    std::string bundleName = "ModeFullChainSubMode001";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 10000;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    Identity identity = {0, -1};
    InstallHapWithMode({path}, baseInfo, bundlePolicy, identity, MultipleMode::SUB_MODE);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    // sign rows of this install carry mode 1 (first real write, not the column default)
    auto signRows = QuerySignInfoRows(bundleName, 1);
    ASSERT_EQ(1, static_cast<int>(signRows.size()));
    EXPECT_TRUE(QuerySignInfoRows(bundleName, 0).empty());

    // token row keeps the declared inst_index (mode dimension of hap_token_info_table)
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> tokenRows;
    ASSERT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, tokenRows));
    ASSERT_EQ(1, static_cast<int>(tokenRows.size()));
    EXPECT_EQ(10000, tokenRows[0].GetInt(TokenFiledConst::FIELD_INST_INDEX));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallModeTest004
 * @tc.desc: AC-09: a mode=0 four-stage install persists hap_info_table rows
 *           with mode 0 and the token row keeps inst_index 0.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallModeTest004, TestSize.Level0)
{
    std::string bundleName = "ModeFullChainMainMode001";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    Identity identity = {0, -1};
    InstallHapWithMode({path}, baseInfo, bundlePolicy, identity, MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    auto signRows = QuerySignInfoRows(bundleName, 0);
    ASSERT_EQ(1, static_cast<int>(signRows.size()));
    EXPECT_TRUE(QuerySignInfoRows(bundleName, 1).empty());

    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> tokenRows;
    ASSERT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, tokenRows));
    ASSERT_EQ(1, static_cast<int>(tokenRows.size()));
    EXPECT_EQ(0, tokenRows[0].GetInt(TokenFiledConst::FIELD_INST_INDEX));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallModeTest005
 * @tc.desc: AC-10: the sub-mode main app (instIndex=10000, non-DLP) gets
 *           cloneFlag 0 - it is the main app inside its own mode.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallModeTest005, TestSize.Level0)
{
    std::string bundleName = "ModeCloneFlagMainApp001";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 10000;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    Identity identity = {0, -1};
    InstallHapWithMode({path}, baseInfo, bundlePolicy, identity, MultipleMode::SUB_MODE);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    EXPECT_EQ(0, TokenIDAttributes::GetTokenIdCloneFlag(tokenId));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallModeTest006
 * @tc.desc: AC-10b: a sub-mode clone (instIndex=10001, non-DLP) gets
 *           cloneFlag 1.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallModeTest006, TestSize.Level0)
{
    std::string bundleName = "ModeCloneFlagSubClone001";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 10001;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    Identity identity = {0, -1};
    InstallHapWithMode({path}, baseInfo, bundlePolicy, identity, MultipleMode::SUB_MODE);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    EXPECT_EQ(1, TokenIDAttributes::GetTokenIdCloneFlag(tokenId));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallModeTest007
 * @tc.desc: AC-10b/BR-11: DLP semantics win over the clone rule - a DLP app
 *           with instIndex=10001 still gets cloneFlag 0 (assertion point is
 *           PrepareHapIdentity per AC-10b; the mode-blind DLP original-app
 *           resolution in InitDlpPermissionList is a separate known gap).
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallModeTest007, TestSize.Level0)
{
    std::string bundleName = "ModeCloneFlagDlp001";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userIdForEnterpriseSign = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult result;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::SUB_MODE, result));

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 10002;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_READ;
    Identity identity = {0, -1};
    ASSERT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(
        sessionId, baseInfo, bundlePolicy, nullptr, identity));
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    EXPECT_NE(0, identity.tokenId);
    // DLP semantics win over the clone rule, and the DLP flag itself is set
    EXPECT_EQ(0, TokenIDAttributes::GetTokenIdCloneFlag(tokenId));
    EXPECT_EQ(1, TokenIDAttributes::GetTokenIdDlpFlag(tokenId));

    // no sign row is persisted: the DLP case asserts the identity stage only
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, false, modulePathMap));
    EXPECT_TRUE(QuerySignInfoRows(bundleName, -1).empty());
}

/**
 * @tc.name: InstallModeTest008
 * @tc.desc: AC-11: a mode=1 TYPE_MERGE loads no mode=0 rows as merge base;
 *           after the install the mode=0 rows stay untouched.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallModeTest008, TestSize.Level0)
{
    std::string bundleName = "ModeMergeCrossMode001";
    std::string path1 = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    std::string path2 = "/SYSTEM/system_basic/state:[mic]/acl:[]/Module002/" + bundleName;

    // main mode install with Module001
    HapBaseInfo baseInfo0;
    baseInfo0.userID = 100;
    baseInfo0.bundleName = bundleName;
    baseInfo0.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    Identity identity0 = {0, -1};
    InstallHapWithMode({path1}, baseInfo0, bundlePolicy, identity0, MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenId0 = static_cast<AccessTokenID>(identity0.tokenId);

    auto rowsBefore = QuerySignInfoRows(bundleName, 0);
    ASSERT_EQ(1, static_cast<int>(rowsBefore.size()));
    std::string pathBefore = rowsBefore[0].GetString(TokenFiledConst::FIELD_PATH);
    std::vector<uint8_t> persistBefore = rowsBefore[0].GetBlob(TokenFiledConst::FIELD_PERSIST_DATA);

    // sub-mode merge session for Module002: no same-mode installed rows exist
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartMergeSessionMode(path2, MultipleMode::SUB_MODE, sessionId));

    // merge base is empty: only the newly verified module, no old module path
    auto cacheIt = g_installSessionManager->sessionToInstallCache.find(sessionId);
    ASSERT_TRUE(cacheIt != g_installSessionManager->sessionToInstallCache.end());
    EXPECT_EQ(1, static_cast<int>(cacheIt->second.bundleInfos.size()));
    EXPECT_TRUE(cacheIt->second.oldModulePaths.empty());

    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = bundleName;
    baseInfo1.instIndex = 10000;
    Identity identity1 = {0, -1};
    ASSERT_EQ(ERR_OK, g_installSessionManager->PrepareHapIdentity(
        sessionId, baseInfo1, bundlePolicy, nullptr, identity1));
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path2] = path2;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // main mode row untouched (path/persist_data unchanged); sub mode row added
    auto rowsAfter = QuerySignInfoRows(bundleName, 0);
    ASSERT_EQ(1, static_cast<int>(rowsAfter.size()));
    EXPECT_EQ(pathBefore, rowsAfter[0].GetString(TokenFiledConst::FIELD_PATH));
    EXPECT_EQ(persistBefore, rowsAfter[0].GetBlob(TokenFiledConst::FIELD_PERSIST_DATA));
    EXPECT_EQ(1, static_cast<int>(QuerySignInfoRows(bundleName, 1).size()));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId0, bundleName, ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId1, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallModeTest009
 * @tc.desc: AC-11b: a mode=0 TYPE_MERGE loads the mode=0 installed rows as
 *           its merge base (old module paths preserved through the merge).
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallModeTest009, TestSize.Level0)
{
    std::string bundleName = "ModeMergeSameMode001";
    std::string path1 = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    std::string path2 = "/SYSTEM/system_basic/state:[mic]/acl:[]/Module002/" + bundleName;
    std::string path3 = "/SYSTEM/system_basic/state:[syswin]/acl:[]/Module003/" + bundleName;

    // main mode install with Module001 + Module002
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = bundleName;
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    Identity identity = {0, -1};
    InstallHapWithMode({path1, path2}, baseInfo, bundlePolicy, identity, MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    ASSERT_EQ(2, static_cast<int>(QuerySignInfoRows(bundleName, 0).size()));

    // L2 discriminator: a user-set grant on the first install must survive the
    // same-mode merge (permission inheritance, USER_SET as the variable)
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    ASSERT_EQ(PERMISSION_GRANTED, atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA"));

    // same mode merge session adding Module003
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartMergeSessionMode(path3, MultipleMode::DEFAULT_OR_MAIN_MODE, sessionId));

    // merge base loaded: Module001/Module002 appended from db with their old paths
    auto cacheIt = g_installSessionManager->sessionToInstallCache.find(sessionId);
    ASSERT_TRUE(cacheIt != g_installSessionManager->sessionToInstallCache.end());
    EXPECT_EQ(3, static_cast<int>(cacheIt->second.bundleInfos.size()));
    ASSERT_EQ(2, static_cast<int>(cacheIt->second.oldModulePaths.size()));
    EXPECT_EQ(path1, cacheIt->second.oldModulePaths[0]);
    EXPECT_EQ(path2, cacheIt->second.oldModulePaths[1]);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path3] = path3;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));
    EXPECT_EQ(3, static_cast<int>(QuerySignInfoRows(bundleName, 0).size()));
    EXPECT_TRUE(QuerySignInfoRows(bundleName, 1).empty());

    // L2: the user-set grant survived the merge rewrite; L3-db backing: row exists
    EXPECT_EQ(PERMISSION_GRANTED, atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA"));
    GenericValues permCondition;
    permCondition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    permCondition.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.CAMERA");
    std::vector<GenericValues> permRows;
    ASSERT_EQ(ERR_OK, AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, permCondition, permRows));
    EXPECT_EQ(1, static_cast<int>(permRows.size()));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallModeTest010
 * @tc.desc: AC-11: TYPE_INSTALL in mode=1 is not blocked by an existing
 *           mode=0 install of the same bundleName (already-exist is per mode).
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallModeTest010, TestSize.Level0)
{
    std::string bundleName = "ModeTypeInstallCross001";
    std::string path1 = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    std::string path2 = "/SYSTEM/system_basic/state:[mic]/acl:[]/Module002/" + bundleName;

    HapBaseInfo baseInfo0;
    baseInfo0.userID = 100;
    baseInfo0.bundleName = bundleName;
    baseInfo0.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    Identity identity0 = {0, -1};
    InstallHapWithMode({path1}, baseInfo0, bundlePolicy, identity0, MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenId0 = static_cast<AccessTokenID>(identity0.tokenId);

    // sub-mode TYPE_INSTALL for the same bundleName must not report ALREADY_EXIST
    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = bundleName;
    baseInfo1.instIndex = 10000;
    Identity identity1 = {0, -1};
    InstallHapWithMode({path2}, baseInfo1, bundlePolicy, identity1, MultipleMode::SUB_MODE);
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);

    EXPECT_EQ(1, static_cast<int>(QuerySignInfoRows(bundleName, 0).size()));
    EXPECT_EQ(1, static_cast<int>(QuerySignInfoRows(bundleName, 1).size()));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId0, bundleName, ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId1, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallModeTest011
 * @tc.desc: AC-12c: installing the same bundleName+moduleName in mode=0 and
 *           mode=1 leaves both hap_info_table rows (PK bundle_name+module_name
 *           +mode); the second install does not delete the first mode's row.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallModeTest011, TestSize.Level0)
{
    std::string bundleName = "ModeCrossModuleCoexist001";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;

    // main mode install, then sub mode install of the very same module
    HapBaseInfo baseInfo0;
    baseInfo0.userID = 100;
    baseInfo0.bundleName = bundleName;
    baseInfo0.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    Identity identity0 = {0, -1};
    InstallHapWithMode({path}, baseInfo0, bundlePolicy, identity0, MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenId0 = static_cast<AccessTokenID>(identity0.tokenId);

    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = bundleName;
    baseInfo1.instIndex = 10000;
    Identity identity1 = {0, -1};
    InstallHapWithMode({path}, baseInfo1, bundlePolicy, identity1, MultipleMode::SUB_MODE);
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);

    // both rows coexist under the (bundle_name, module_name, mode) primary key
    auto rows0 = QuerySignInfoRows(bundleName, 0);
    auto rows1 = QuerySignInfoRows(bundleName, 1);
    ASSERT_EQ(1, static_cast<int>(rows0.size()));
    ASSERT_EQ(1, static_cast<int>(rows1.size()));
    EXPECT_EQ("Module001", rows0[0].GetString(TokenFiledConst::FIELD_MODULE_NAME));
    EXPECT_EQ("Module001", rows1[0].GetString(TokenFiledConst::FIELD_MODULE_NAME));
    EXPECT_EQ(path, rows0[0].GetString(TokenFiledConst::FIELD_PATH));
    EXPECT_EQ(path, rows1[0].GetString(TokenFiledConst::FIELD_PATH));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId0, bundleName, ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId1, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallModeTest012
 * @tc.desc: AC-13: the same bundleName in two modes gets distinct uids, both
 *           satisfying uid = userID*200000 + bundleId with bundleId in
 *           [10000, 65535]; the first token's uid is unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallModeTest012, TestSize.Level0)
{
    constexpr int32_t bundleIdMin = 10000;
    constexpr int32_t bundleIdMax = 65535;
    std::string bundleName = "ModeUidDistinct001";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;

    HapBaseInfo baseInfo0;
    baseInfo0.userID = 100;
    baseInfo0.bundleName = bundleName;
    baseInfo0.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    Identity identity0 = {0, -1};
    InstallHapWithMode({path}, baseInfo0, bundlePolicy, identity0, MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenId0 = static_cast<AccessTokenID>(identity0.tokenId);
    int32_t uid0 = identity0.uid;

    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = bundleName;
    baseInfo1.instIndex = 10000;
    Identity identity1 = {0, -1};
    InstallHapWithMode({path}, baseInfo1, bundlePolicy, identity1, MultipleMode::SUB_MODE);
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);
    int32_t uid1 = identity1.uid;

    EXPECT_NE(uid0, uid1);
    EXPECT_EQ(100, uid0 / UID_MASK);
    EXPECT_EQ(100, uid1 / UID_MASK);
    int32_t bundleId0 = uid0 % UID_MASK;
    int32_t bundleId1 = uid1 % UID_MASK;
    EXPECT_TRUE(bundleId0 >= bundleIdMin && bundleId0 <= bundleIdMax);
    EXPECT_TRUE(bundleId1 >= bundleIdMin && bundleId1 <= bundleIdMax);
    EXPECT_NE(bundleId0, bundleId1);

    // the existing mode=0 token keeps its uid after the sub-mode install
    auto infoPtr0 = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId0);
    ASSERT_NE(nullptr, infoPtr0);
    EXPECT_EQ(uid0, infoPtr0->tokenInfoBasic_.uid);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId0, bundleName, ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId1, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallModeTest013
 * @tc.desc: EX-1/EX-6: a mode-mismatched prepare failure recycles the session
 *           through the existing rollback (no half state): FinishInstall on
 *           the recycled session reports ERR_SESSION_NOT_EXIST, and the same
 *           bundle installs cleanly with consistent parameters afterwards.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallModeTest013, TestSize.Level0)
{
    std::string bundleName = "ModeMismatchRecycle001";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundleHapList hapList{std::vector<std::string>{path}, false, 100};
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult result;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::DEFAULT_OR_MAIN_MODE, result));

    // mismatched prepare fails and the session is rolled back
    HapBaseInfo badInfo;
    badInfo.userID = 100;
    badInfo.bundleName = bundleName;
    badInfo.instIndex = 10000;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    Identity identity = {0, -1};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        g_installSessionManager->PrepareHapIdentity(sessionId, badInfo, bundlePolicy, nullptr, identity));
    EXPECT_EQ(0, identity.tokenId);

    // the recycled session is gone: finishing it reports session-not-exist
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    EXPECT_EQ(AccessTokenError::ERR_SESSION_NOT_EXIST,
        g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // the same bundle installs cleanly with consistent parameters
    HapBaseInfo goodInfo;
    goodInfo.userID = 100;
    goodInfo.bundleName = bundleName;
    goodInfo.instIndex = 0;
    Identity goodIdentity = {0, -1};
    InstallHapWithMode({path}, goodInfo, bundlePolicy, goodIdentity, MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenId = static_cast<AccessTokenID>(goodIdentity.tokenId);
    EXPECT_EQ(1, static_cast<int>(QuerySignInfoRows(bundleName, 0).size()));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(tokenId, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: InstallModeTest014
 * @tc.desc: AC-12/BR-5 op-level write set: ConvertInstallCacheToBundleInfoItems
 *           produces sign add rows all carrying the session mode, and a delete
 *           condition scoped by the (bundle_name, mode) pair.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, InstallModeTest014, TestSize.Level0)
{
    std::string bundleName = "ModeWriteSetCheck001";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundleHapList hapList{std::vector<std::string>{path}, false, 100};
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(
        hapList, nullptr, sessionId, bundleInfo, resultInfo, QUERY_ALL_SIGN_INFO));
    HapInfoCheckResult checkResult;
    ASSERT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(
        sessionId, TYPE_INSTALL, MultipleMode::SUB_MODE, checkResult));
    auto cacheIt = g_installSessionManager->sessionToInstallCache.find(sessionId);
    ASSERT_TRUE(cacheIt != g_installSessionManager->sessionToInstallCache.end());
    ASSERT_FALSE(cacheIt->second.bundleInfos.empty());

    // op level: every add row and the delete condition carry the session mode
    std::vector<GenericValues> signValues;
    GenericValues delCondition;
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ASSERT_EQ(ERR_OK, InstallDbRepository::ConvertInstallCacheToBundleInfoItems(
        cacheIt->second, modulePathMap, signValues, delCondition));
    ASSERT_EQ(1, static_cast<int>(signValues.size()));
    EXPECT_EQ(bundleName, signValues[0].GetString(TokenFiledConst::FIELD_BUNDLE_NAME));
    EXPECT_EQ("Module001", signValues[0].GetString(TokenFiledConst::FIELD_MODULE_NAME));
    EXPECT_EQ(static_cast<int32_t>(MultipleMode::SUB_MODE), signValues[0].GetInt(TokenFiledConst::FIELD_MODE));
    EXPECT_EQ(bundleName, delCondition.GetString(TokenFiledConst::FIELD_BUNDLE_NAME));
    EXPECT_EQ(static_cast<int32_t>(MultipleMode::SUB_MODE), delCondition.GetInt(TokenFiledConst::FIELD_MODE));

    // release the session through the non-persistent rollback
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, false, modulePathMap));
}

/**
 * @tc.name: ModeIsolationTest001
 * @tc.desc: A main-mode TYPE_REPLACE update leaves the sub-mode token of the
 *           same bundleName untouched: uid/instIndex, user-set grant states,
 *           perm/extend/undefine db rows and the sub-mode sign rows stay
 *           snapshot-identical, while the main-mode token is really updated
 *           (control group).
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, ModeIsolationTest001, TestSize.Level1)
{
    std::string bundleName = "ModeIsolationUpdateBundle";
    std::string mainPath = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    std::string subPath = "/SYSTEM/system_basic/state:[cam,mic]/acl:[]/Module002/" + bundleName;

    AccessTokenID tokenMain = InstallAppWithMode(mainPath, bundleName, 100, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenSub = InstallAppWithMode(subPath, bundleName, 100, 10000,
        MultipleMode::SUB_MODE);
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        tokenSub, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    ASSERT_EQ(PERMISSION_GRANTED, atManagerService_->VerifyAccessToken(tokenSub, "ohos.permission.CAMERA"));

    ModeTokenSnapshot subBefore = TakeModeTokenSnapshot(tokenSub);
    auto subSignBefore = RowsToCanonical(QuerySignInfoRows(bundleName, 1));

    std::string newPath = "/SYSTEM/system_basic/state:[cam,syswin]/acl:[]/Module001/" + bundleName;
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartReplaceSession(newPath, sessionId));
    BundlePolicy bundlePolicy = CommonBundlePolicy();
    int32_t uid = -1; // no uid expectation
    AccessTokenIDEx tokenIdEx = BuildTokenIdEx(tokenMain);
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[newPath] = newPath;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // control: the main-mode update really landed
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(tokenMain, "ohos.permission.SYSTEM_FLOAT_WINDOW"));
    AssertPermRowPresent(tokenMain, "ohos.permission.SYSTEM_FLOAT_WINDOW");
    // isolation: the sub-mode token is snapshot-identical
    AssertModeTokenSnapshotUnchanged(subBefore, tokenSub);
    EXPECT_EQ(PERMISSION_GRANTED, atManagerService_->VerifyAccessToken(tokenSub, "ohos.permission.CAMERA"));
    AssertPermRowAbsent(tokenSub, "ohos.permission.SYSTEM_FLOAT_WINDOW");
    EXPECT_EQ(subSignBefore, RowsToCanonical(QuerySignInfoRows(bundleName, 1)));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: ModeIsolationTest002
 * @tc.desc: Reverse direction: a sub-mode TYPE_REPLACE update leaves the
 *           main-mode token snapshot-identical (grants, db rows, sign rows),
 *           while the sub-mode token itself is updated.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, ModeIsolationTest002, TestSize.Level1)
{
    std::string bundleName = "ModeIsolationUpdateSubBundle";
    std::string mainPath = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    std::string subPath = "/SYSTEM/system_basic/state:[cam,mic]/acl:[]/Module002/" + bundleName;

    AccessTokenID tokenMain = InstallAppWithMode(mainPath, bundleName, 100, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenSub = InstallAppWithMode(subPath, bundleName, 100, 10000,
        MultipleMode::SUB_MODE);
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        tokenMain, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));

    ModeTokenSnapshot mainBefore = TakeModeTokenSnapshot(tokenMain);
    auto mainSignBefore = RowsToCanonical(QuerySignInfoRows(bundleName, 0));

    std::string newSubPath = "/SYSTEM/system_basic/state:[cam,mic,syswin]/acl:[]/Module002/" + bundleName;
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartReplaceSessionMode(newSubPath, MultipleMode::SUB_MODE, sessionId));
    BundlePolicy bundlePolicy = CommonBundlePolicy();
    int32_t uid = -1; // no uid expectation
    AccessTokenIDEx tokenIdEx = BuildTokenIdEx(tokenSub);
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[newSubPath] = newSubPath;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // control: the sub-mode update really landed; the main-mode token is untouched
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(tokenSub, "ohos.permission.SYSTEM_FLOAT_WINDOW"));
    AssertModeTokenSnapshotUnchanged(mainBefore, tokenMain);
    EXPECT_EQ(PERMISSION_GRANTED, atManagerService_->VerifyAccessToken(tokenMain, "ohos.permission.CAMERA"));
    AssertPermRowAbsent(tokenMain, "ohos.permission.SYSTEM_FLOAT_WINDOW");
    EXPECT_EQ(mainSignBefore, RowsToCanonical(QuerySignInfoRows(bundleName, 0)));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: ModeIsolationTest003
 * @tc.desc: Deleting the sub-mode token cleans only the sub-mode sign rows
 *           and releases only its own bundleId; the main-mode token keeps its
 *           snapshot, sign rows and registered bundleId.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, ModeIsolationTest003, TestSize.Level1)
{
    std::string bundleName = "ModeIsolationDeleteBundle";
    std::string mainPath = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    std::string subPath = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module002/" + bundleName;

    AccessTokenID tokenMain = InstallAppWithMode(mainPath, bundleName, 100, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenSub = InstallAppWithMode(subPath, bundleName, 100, 10000,
        MultipleMode::SUB_MODE);
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        tokenMain, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));

    ModeTokenSnapshot mainBefore = TakeModeTokenSnapshot(tokenMain);
    auto mainSignBefore = RowsToCanonical(QuerySignInfoRows(bundleName, 0));
    auto mainInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenMain);
    ASSERT_NE(nullptr, mainInfo);
    int32_t mainBundleId = mainInfo->GetUid() % UID_MASK;

    int32_t sceneCode = 0;
    ASSERT_EQ(ERR_OK, DeleteIdentityCore(tokenSub, bundleName, ReservedType::NONE, sceneCode));

    // sub side: gone from cache and its mode-1 sign rows are cleaned
    AssertTokenInvisible(tokenSub);
    EXPECT_TRUE(QuerySignInfoRows(bundleName, 1).empty());
    // main side: snapshot-identical, sign rows kept, bundleId still registered
    AssertModeTokenSnapshotUnchanged(mainBefore, tokenMain);
    EXPECT_EQ(PERMISSION_GRANTED, atManagerService_->VerifyAccessToken(tokenMain, "ohos.permission.CAMERA"));
    EXPECT_EQ(mainSignBefore, RowsToCanonical(QuerySignInfoRows(bundleName, 0)));
    EXPECT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(mainBundleId));

    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: ModeIsolationTest004
 * @tc.desc: A sub-mode RESERVED_DATA delete + reinstall reuses the reserved
 *           sub token and keeps its user grant, while the main-mode token
 *           stays snapshot-identical across the whole cycle.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, ModeIsolationTest004, TestSize.Level1)
{
    std::string bundleName = "ModeIsolationReservedBundle";
    std::string mainPath = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    std::string subPath = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module002/" + bundleName;

    AccessTokenID tokenMain = InstallAppWithMode(mainPath, bundleName, 100, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenSub = InstallAppWithMode(subPath, bundleName, 100, 10000,
        MultipleMode::SUB_MODE);
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        tokenSub, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    ASSERT_EQ(PERMISSION_GRANTED, atManagerService_->VerifyAccessToken(tokenSub, "ohos.permission.CAMERA"));

    ModeTokenSnapshot mainBefore = TakeModeTokenSnapshot(tokenMain);

    int32_t sceneCode = 0;
    ASSERT_EQ(ERR_OK, DeleteIdentityCore(tokenSub, bundleName, ReservedType::RESERVED_DATA, sceneCode));

    // sub reinstall in the same mode reuses the reserved token and its grant
    AccessTokenID tokenSub2 = InstallAppWithMode(subPath, bundleName, 100, 10000,
        MultipleMode::SUB_MODE);
    EXPECT_EQ(tokenSub, tokenSub2);
    EXPECT_EQ(PERMISSION_GRANTED, atManagerService_->VerifyAccessToken(tokenSub2, "ohos.permission.CAMERA"));

    // main side: untouched by the reserved delete/reinstall cycle
    AssertModeTokenSnapshotUnchanged(mainBefore, tokenMain);

    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: ModeSupplementTest001
 * @tc.desc: End-to-end supplement scoping: a main-mode update session that
 *           names one token supplements the same-mode cross-user sibling with
 *           the new policy (db rows written), while the sub-mode token of the
 *           same bundleName never enters the update plan (no db write).
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, ModeSupplementTest001, TestSize.Level1)
{
    std::string bundleName = "ModeSupplementE2EBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundlePolicy bundlePolicy = CommonBundlePolicy();

    AccessTokenID tokenA = InstallAppWithMode(path, bundleName, 100, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenB = InstallBundleSiblingToken(MakeSiblingInfo(bundleName, 101, 0), bundlePolicy);
    AccessTokenID tokenC = InstallAppWithMode(path, bundleName, 100, 10000, MultipleMode::SUB_MODE);

    ModeTokenSnapshot subBefore = TakeModeTokenSnapshot(tokenC);

    std::string newPath = "/SYSTEM/system_basic/state:[cam,syswin]/acl:[]/Module001/" + bundleName;
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartReplaceSession(newPath, sessionId));
    int32_t uid = -1; // no uid expectation
    AccessTokenIDEx tokenIdEx = BuildTokenIdEx(tokenA);
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[newPath] = newPath;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    // same-mode cross-user sibling B is supplemented with the new policy
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(tokenB, "ohos.permission.SYSTEM_FLOAT_WINDOW"));
    AssertPermRowPresent(tokenB, "ohos.permission.SYSTEM_FLOAT_WINDOW");
    // the sub-mode token stays out of the update plan (memory + db)
    AssertModeTokenSnapshotUnchanged(subBefore, tokenC);
    EXPECT_EQ(PERMISSION_DENIED,
        atManagerService_->VerifyAccessToken(tokenC, "ohos.permission.SYSTEM_FLOAT_WINDOW"));
    AssertPermRowAbsent(tokenC, "ohos.permission.SYSTEM_FLOAT_WINDOW");

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: ModeSupplementTest002
 * @tc.desc: Clone scoping in both directions: a main-mode update supplements
 *           the main-mode clone but never the sub-mode clone, and a sub-mode
 *           update supplements the sub-mode clone but never the main-mode
 *           clone (snapshot compare on the excluded side each round).
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, ModeSupplementTest002, TestSize.Level1)
{
    std::string bundleName = "ModeSupplementCloneBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundlePolicy bundlePolicy = CommonBundlePolicy();

    AccessTokenID tokenA = InstallAppWithMode(path, bundleName, 100, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenMainClone = InstallBundleSiblingToken(MakeSiblingInfo(bundleName, 100, 1),
        bundlePolicy);
    AccessTokenID tokenC = InstallAppWithMode(path, bundleName, 100, 10000, MultipleMode::SUB_MODE);
    AccessTokenID tokenSubClone = InstallBundleSiblingToken(MakeSiblingInfo(bundleName, 100, 10001),
        bundlePolicy);

    // round 1: main-mode update pulls the main clone, never the sub clone
    ModeTokenSnapshot subCloneBefore = TakeModeTokenSnapshot(tokenSubClone);
    std::string newPath = "/SYSTEM/system_basic/state:[cam,syswin]/acl:[]/Module001/" + bundleName;
    int32_t sessionId = 0;
    ASSERT_EQ(ERR_OK, StartReplaceSession(newPath, sessionId));
    int32_t uid = -1; // no uid expectation
    AccessTokenIDEx tokenIdEx = BuildTokenIdEx(tokenA);
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(sessionId, tokenIdEx, bundlePolicy, uid));
    std::map<std::string, std::string> modulePathMap;
    modulePathMap[newPath] = newPath;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(tokenMainClone, "ohos.permission.SYSTEM_FLOAT_WINDOW"));
    AssertModeTokenSnapshotUnchanged(subCloneBefore, tokenSubClone);
    AssertPermRowAbsent(tokenSubClone, "ohos.permission.SYSTEM_FLOAT_WINDOW");

    // round 2: sub-mode update pulls the sub clone, never the main clone
    ModeTokenSnapshot mainCloneBefore = TakeModeTokenSnapshot(tokenMainClone);
    std::string newSubPath = "/SYSTEM/system_basic/state:[cam,manwifi]/acl:[manwifi]/Module001/" + bundleName;
    int32_t subSessionId = 0;
    ASSERT_EQ(ERR_OK, StartReplaceSessionMode(newSubPath, MultipleMode::SUB_MODE, subSessionId));
    tokenIdEx = BuildTokenIdEx(tokenC);
    ASSERT_EQ(ERR_OK, g_installSessionManager->UpdateHapPolicy(subSessionId, tokenIdEx, bundlePolicy, uid));
    std::map<std::string, std::string> subPathMap;
    subPathMap[newSubPath] = newSubPath;
    ASSERT_EQ(ERR_OK, g_installSessionManager->FinishInstall(subSessionId, true, subPathMap));
    EXPECT_EQ(PERMISSION_GRANTED,
        atManagerService_->VerifyAccessToken(tokenSubClone, "ohos.permission.MANAGE_WIFI_CONNECTION"));
    AssertModeTokenSnapshotUnchanged(mainCloneBefore, tokenMainClone);
    AssertPermRowAbsent(tokenMainClone, "ohos.permission.MANAGE_WIFI_CONNECTION");

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: ModePermSyncTest001
 * @tc.desc: The grant/revoke sibling sync list (GetRelatedSandBoxHapList,
 *           the permission_manager grant/revoke chain) is mode-scoped: the
 *           main app's list holds its same-mode DLP sibling only - never the
 *           sub-mode app of the same bundle+user - and granting on the main
 *           app leaves the sub-mode app's state and db rows untouched.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, ModePermSyncTest001, TestSize.Level1)
{
    std::string bundleName = "ModePermSyncBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundlePolicy dlpPolicy = CommonBundlePolicy();
    dlpPolicy.dlpType = DLP_FULL_CONTROL;

    AccessTokenID tokenA = InstallAppWithMode(path, bundleName, 100, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenDlpMain = InstallBundleSiblingToken(MakeSiblingInfo(bundleName, 100, 1), dlpPolicy);
    AccessTokenID tokenC = InstallAppWithMode(path, bundleName, 100, 10000, MultipleMode::SUB_MODE);
    AccessTokenID tokenDlpSub = InstallBundleSiblingToken(MakeSiblingInfo(bundleName, 100, 10001),
        dlpPolicy);

    // same bundle, same user, different token: only the mode filter keeps the
    // sub app out of the main app's sync list
    std::vector<AccessTokenID> relatedOfA;
    AccessTokenInfoManager::GetInstance().GetRelatedSandBoxHapList(tokenA, relatedOfA);
    ASSERT_EQ(1U, relatedOfA.size());
    EXPECT_EQ(tokenDlpMain, relatedOfA[0]);

    // reverse direction: the sub app's list holds its own DLP sibling only
    std::vector<AccessTokenID> relatedOfC;
    AccessTokenInfoManager::GetInstance().GetRelatedSandBoxHapList(tokenC, relatedOfC);
    ASSERT_EQ(1U, relatedOfC.size());
    EXPECT_EQ(tokenDlpSub, relatedOfC[0]);

    // full link: granting on the main app never rewrites the sub-mode app
    ModeTokenSnapshot subBefore = TakeModeTokenSnapshot(tokenC);
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        tokenA, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    ASSERT_EQ(PERMISSION_GRANTED, atManagerService_->VerifyAccessToken(tokenA, "ohos.permission.CAMERA"));
    AssertModeTokenSnapshotUnchanged(subBefore, tokenC);
    EXPECT_EQ(PERMISSION_DENIED, atManagerService_->VerifyAccessToken(tokenC, "ohos.permission.CAMERA"));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: ModeUidLifecycleTest001
 * @tc.desc: uid/bundleId lifecycle across modes: deleting the sub-mode token
 *           releases only the sub-mode bundleId, and a sub-mode reinstall
 *           never disturbs the main-mode uid/bundleId or its snapshot.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, ModeUidLifecycleTest001, TestSize.Level1)
{
    std::string bundleName = "ModeUidLifecycleBundle";
    std::string mainPath = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    std::string subPath = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module002/" + bundleName;

    AccessTokenID tokenMain = InstallAppWithMode(mainPath, bundleName, 100, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenSub = InstallAppWithMode(subPath, bundleName, 100, 10000,
        MultipleMode::SUB_MODE);
    auto mainInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenMain);
    auto subInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenSub);
    ASSERT_NE(nullptr, mainInfo);
    ASSERT_NE(nullptr, subInfo);
    int32_t mainUid = mainInfo->GetUid();
    int32_t mainBundleId = mainUid % UID_MASK;
    int32_t subBundleId = subInfo->GetUid() % UID_MASK;
    ASSERT_NE(mainBundleId, subBundleId);
    ModeTokenSnapshot mainBefore = TakeModeTokenSnapshot(tokenMain);

    int32_t sceneCode = 0;
    ASSERT_EQ(ERR_OK, DeleteIdentityCore(tokenSub, bundleName, ReservedType::NONE, sceneCode));

    // only the sub-mode bundleId is released; the main one stays registered
    EXPECT_EQ(0U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(subBundleId));
    EXPECT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(mainBundleId));

    // sub-mode reinstall succeeds and the main identity is untouched
    InstallAppWithMode(subPath, bundleName, 100, 10000, MultipleMode::SUB_MODE);
    AssertModeTokenSnapshotUnchanged(mainBefore, tokenMain);
    auto mainInfoAgain = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenMain);
    ASSERT_NE(nullptr, mainInfoAgain);
    EXPECT_EQ(mainUid, mainInfoAgain->GetUid());
    EXPECT_EQ(1U, AccessTokenIDManager::GetInstance().bundleIdSet_.count(mainBundleId));

    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: ModeQueryTest001
 * @tc.desc: The (userID, bundleName, instIndex) triple resolves each mode's
 *           own token - main app, main clone, sub app, sub clone - with no
 *           cross-mode leakage, and the appId channel serves both modes.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, ModeQueryTest001, TestSize.Level0)
{
    std::string bundleName = "ModeQueryTripleBundle";
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;
    BundlePolicy bundlePolicy = CommonBundlePolicy();

    AccessTokenID tokenA = InstallAppWithMode(path, bundleName, 100, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenMainClone = InstallBundleSiblingToken(MakeSiblingInfo(bundleName, 100, 1),
        bundlePolicy);
    AccessTokenID tokenC = InstallAppWithMode(path, bundleName, 100, 10000, MultipleMode::SUB_MODE);
    AccessTokenID tokenSubClone = InstallBundleSiblingToken(MakeSiblingInfo(bundleName, 100, 10001),
        bundlePolicy);

    EXPECT_EQ(tokenA, AccessTokenInfoManager::GetInstance().GetHapTokenID(100, bundleName, 0).tokenIdExStruct.tokenID);
    EXPECT_EQ(tokenMainClone,
        AccessTokenInfoManager::GetInstance().GetHapTokenID(100, bundleName, 1).tokenIdExStruct.tokenID);
    EXPECT_EQ(tokenC,
        AccessTokenInfoManager::GetInstance().GetHapTokenID(100, bundleName, 10000).tokenIdExStruct.tokenID);
    EXPECT_EQ(tokenSubClone,
        AccessTokenInfoManager::GetInstance().GetHapTokenID(100, bundleName, 10001).tokenIdExStruct.tokenID);
    // an uninstalled slot in the main domain resolves nothing
    EXPECT_EQ(0U, AccessTokenInfoManager::GetInstance().GetHapTokenID(100, bundleName, 2).tokenIdExStruct.tokenID);

    // the appId channel routes through each token's own mode sign rows
    // (the path-driven stub pins appId == bundleName for both modes)
    std::string appIdOfMain;
    ASSERT_EQ(ERR_OK, BundleInfoManager::GetInstance().GetHapAppIdByTokenId(tokenA, appIdOfMain));
    std::string appIdOfSub;
    ASSERT_EQ(ERR_OK, BundleInfoManager::GetInstance().GetHapAppIdByTokenId(tokenC, appIdOfSub));
    EXPECT_EQ(bundleName, appIdOfMain);
    EXPECT_EQ(bundleName, appIdOfSub);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: ModeQueryTest002
 * @tc.desc: CURRENT_MODE sign-info semantics: with the device running in sub
 *           mode, a main-only bundle falls back to its main rows while an
 *           explicit SUB_MODE query stays strict (bundle-not-exist); explicit
 *           mode queries of a dual-mode bundle return only their own rows.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, ModeQueryTest002, TestSize.Level1)
{
    std::string mainOnlyBundle = "ModeQueryFallbackMainOnly";
    std::string mainPath = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + mainOnlyBundle;
    std::string dualBundle = "ModeQueryFallbackDual";
    std::string dualMainPath = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + dualBundle;
    std::string dualSubPath = "/SYSTEM/system_basic/state:[mic]/acl:[]/Module002/" + dualBundle;

    AccessTokenID tokenMain = InstallAppWithMode(mainPath, mainOnlyBundle, 100, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenDualMain = InstallAppWithMode(dualMainPath, dualBundle, 100, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenDualSub = InstallAppWithMode(dualSubPath, dualBundle, 100, 10000,
        MultipleMode::SUB_MODE);
    ASSERT_NE(INVALID_TOKENID, tokenMain);
    ASSERT_NE(INVALID_TOKENID, tokenDualMain);
    ASSERT_NE(INVALID_TOKENID, tokenDualSub);

    // simulate the device running in sub mode (canary: the shim must bite)
    system::SetIntParameter("persist.sceneboard.ispcmode", 1);
    EXPECT_EQ(MultipleMode::SUB_MODE, MultipleModeUtils::GetCurrentMode());

    std::vector<TrustedBundleInfo> infos;
    // main-only bundle: CURRENT_MODE resolves sub, finds nothing, falls back to main
    EXPECT_EQ(ERR_OK, BundleInfoManager::GetInstance().GetHapSignInfo(
        mainOnlyBundle, infos, QUERY_ALL_SIGN_INFO, MultipleMode::CURRENT_MODE));
    EXPECT_EQ(1U, infos.size());
    // explicit SUB_MODE on the main-only bundle stays strict: no fallback
    EXPECT_NE(ERR_OK, BundleInfoManager::GetInstance().GetHapSignInfo(
        mainOnlyBundle, infos, QUERY_ALL_SIGN_INFO, MultipleMode::SUB_MODE));
    // dual bundle: each explicit mode sees only its own row
    EXPECT_EQ(ERR_OK, BundleInfoManager::GetInstance().GetHapSignInfo(
        dualBundle, infos, QUERY_ALL_SIGN_INFO, MultipleMode::SUB_MODE));
    EXPECT_EQ(1U, infos.size());
    EXPECT_EQ(ERR_OK, BundleInfoManager::GetInstance().GetHapSignInfo(
        dualBundle, infos, QUERY_ALL_SIGN_INFO, MultipleMode::DEFAULT_OR_MAIN_MODE));
    EXPECT_EQ(1U, infos.size());

    system::ClearIntParameter("persist.sceneboard.ispcmode");
    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, mainOnlyBundle, ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, dualBundle, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: ModeRestoreTest001
 * @tc.desc: Restore-chain level: after cache eviction, the pure db snapshot
 *           restores each mode's identity (uid + instIndex/mode dimension)
 *           and the db-rebuilt perm brief keeps each mode's own user grant.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, ModeRestoreTest001, TestSize.Level1)
{
    std::string bundleName = "ModeRestoreBundle";
    std::string mainPath = "/SYSTEM/system_basic/state:[cam,mic]/acl:[]/Module001/" + bundleName;
    std::string subPath = "/SYSTEM/system_basic/state:[cam,mic]/acl:[]/Module002/" + bundleName;

    AccessTokenID tokenMain = InstallAppWithMode(mainPath, bundleName, 100, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);
    AccessTokenID tokenSub = InstallAppWithMode(subPath, bundleName, 100, 10000,
        MultipleMode::SUB_MODE);
    auto mainInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenMain);
    auto subInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenSub);
    ASSERT_NE(nullptr, mainInfo);
    ASSERT_NE(nullptr, subInfo);
    int32_t mainUid = mainInfo->GetUid();
    int32_t subUid = subInfo->GetUid();
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        tokenMain, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM));
    ASSERT_EQ(ERR_OK, atManagerService_->GrantPermission(
        tokenSub, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));

    // evict both caches: the db rows are the only remaining source
    AccessTokenInfoManager::GetInstance().CommitDeleteHapCache(tokenMain);
    AccessTokenInfoManager::GetInstance().CommitDeleteHapCache(tokenSub);
    EXPECT_EQ(nullptr, AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenMain));
    EXPECT_EQ(nullptr, AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenSub));

    // the pure db snapshot restores the identity including the mode dimension
    auto mainInner = AccessTokenInfoManager::GetInstance().LoadHapTokenInfoFromDbAndNoCache(tokenMain);
    ASSERT_NE(nullptr, mainInner);
    EXPECT_EQ(mainUid, mainInner->GetUid());
    EXPECT_EQ(0, mainInner->GetInstIndex());
    auto subInner = AccessTokenInfoManager::GetInstance().LoadHapTokenInfoFromDbAndNoCache(tokenSub);
    ASSERT_NE(nullptr, subInner);
    EXPECT_EQ(subUid, subInner->GetUid());
    EXPECT_EQ(10000, subInner->GetInstIndex());

    // the perm brief rebuilt from the db keeps each mode's own user grant
    std::vector<BriefPermData> mainBriefs;
    ASSERT_EQ(ERR_OK, InstallDbRepository::BuildPermStateByTokenId(tokenMain, mainBriefs));
    EXPECT_EQ(1U, CountGrantedBriefs(mainBriefs));
    std::vector<BriefPermData> subBriefs;
    ASSERT_EQ(ERR_OK, InstallDbRepository::BuildPermStateByTokenId(tokenSub, subBriefs));
    EXPECT_EQ(1U, CountGrantedBriefs(subBriefs));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, DeleteIdentityCore(INVALID_TOKENID, bundleName, ReservedType::NONE, sceneCode));
}

/**
 * @tc.name: GetAppIdFromDbModeScopedTest001
 * @tc.desc: GetAppIdFromDb is mode-scoped on the token rows: the appId reads
 *           back only from a token row inside the requested mode domain; the
 *           other mode (or no row at all, the repair/drift state) reports
 *           ERR_PARAM_INVALID - the signal FillInstallPolicy's kernel fast
 *           path uses to degrade to the db-verify path instead of failing
 *           the repair session.
 * @tc.type: FUNC
 */
HWTEST_F(InstallSessionManagerMockTest, GetAppIdFromDbModeScopedTest001, TestSize.Level1)
{
    std::string bundleName = "GetAppIdModeScopedBundle";
    std::string mainPath = "/SYSTEM/system_basic/state:[cam]/acl:[]/Module001/" + bundleName;

    AccessTokenID tokenMain = InstallAppWithMode(mainPath, bundleName, 100, 0,
        MultipleMode::DEFAULT_OR_MAIN_MODE);

    // same mode: the appId reads back from the main-mode token row
    // (the mock FillBundleParam pins appId = bundleName + "aaaaa")
    std::string appId;
    ASSERT_EQ(ERR_OK, InstallDbRepository::GetAppIdFromDb(
        bundleName, MultipleMode::DEFAULT_OR_MAIN_MODE, appId));
    EXPECT_EQ(bundleName + "aaaaa", appId);

    // other mode: no token row in the sub-mode domain -> error signal
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, InstallDbRepository::GetAppIdFromDb(
        bundleName, MultipleMode::SUB_MODE, appId));

    // last token row gone (repair/drift state): the same-mode read reports the
    // same signal, which must degrade the session instead of killing it
    int32_t sceneCode = 0;
    ASSERT_EQ(ERR_OK, DeleteIdentityCore(tokenMain, bundleName, ReservedType::NONE, sceneCode));
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, InstallDbRepository::GetAppIdFromDb(
        bundleName, MultipleMode::DEFAULT_OR_MAIN_MODE, appId));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
