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

#include "delete_identity_mock_test.h"

#include <thread>
#include <chrono>
#include "permission_kernel_utils.h"
#include "perm_setproc.h"
#include "spm_setproc.h"

#define private public
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_info_utils.h"
#include "accesstoken_manager_service.h"
#include "accesstoken_dfx_define.h"
#include "boot_verify_scheduler.h"
#include "install_session_manager.h"
#undef private
#include "accesstoken_migration_manager.h"
#include "access_token.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "atm_data_type.h"
#include "hap_token_info.h"
#include "token_field_const.h"
#include "generic_values.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static std::shared_ptr<AccessTokenManagerService> atManagerService_;
static InstallSessionManager* g_installSessionManager = nullptr;
static constexpr int32_t UID_MASK = 200000;
}

void DeleteIdentityMockTest::SetUpTestCase()
{
    atManagerService_ = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    g_installSessionManager = &InstallSessionManager::GetInstance();

    uint32_t hapSize = 0;
    uint32_t nativeSize = 0;
    uint32_t pefDefSize = 0;
    uint32_t dlpSize = 0;
    AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize);

    AccessTokenMigrationManager::GetInstance().Initialize();
    AccessTokenMigrationManager::GetInstance().FinishMigration();
}

void DeleteIdentityMockTest::TearDownTestCase()
{
    g_installSessionManager = nullptr;
    DelayedSingleton<AccessTokenManagerService>::DestroyInstance();
    atManagerService_ = nullptr;
}

void DeleteIdentityMockTest::SetUp()
{
    CleanAllTestData();
}

void DeleteIdentityMockTest::TearDown()
{
    // Clean up session cache
    std::vector<int32_t> sessionList;
    for (auto it : g_installSessionManager->sessionToInstallCache) {
        sessionList.emplace_back(it.first);
    }
    for (auto session : sessionList) {
        g_installSessionManager->RollbackAll(session);
    }
}

void DeleteIdentityMockTest::InstallHap(const std::vector<std::string>& hapPaths,
    const HapBaseInfo& baseInfo, const BundlePolicy& bundlePolicy, Identity& identity)
{
    BundleHapList hapList;
    hapList.hapPaths = hapPaths;
    hapList.isPreInstalled = false;
    hapList.userId = baseInfo.userID;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo);
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

void DeleteIdentityMockTest::CloneApp(const std::string& hapPath, const HapBaseInfo& baseInfo,
    const BundlePolicy& bundlePolicy, Identity& identity)
{
    int32_t sessionId = 0;
    int32_t ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy,
        nullptr, identity);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity.uid);
    EXPECT_NE(0, identity.tokenId);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[hapPath] = hapPath;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);
}

bool DeleteIdentityMockTest::VerifyTokenDeletedFromDatabase(AccessTokenID tokenId)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, results);
    if (ret != ERR_OK || results.size() != 0) {
        return false;
    }

    GenericValues conditionValue2;
    conditionValue2.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> permStateResults;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue2, permStateResults);
    return ret == ERR_OK && permStateResults.size() == 0;
}

bool DeleteIdentityMockTest::VerifyTokenExistsInDatabase(AccessTokenID tokenId, int32_t& uid, int32_t& reserved)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, results);
    if (ret != ERR_OK || results.size() != 1) {
        return false;
    }

    uid = results[0].GetInt(TokenFiledConst::FIELD_UID);
    reserved = results[0].GetInt(TokenFiledConst::FIELD_RESERVED);
    return true;
}

bool DeleteIdentityMockTest::VerifyBundleDeletedFromDatabase(const std::string& bundleName)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    std::vector<GenericValues> results;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results);
    return ret == ERR_OK && results.size() == 0;
}

bool DeleteIdentityMockTest::VerifyPermissionDeletedFromDatabase(AccessTokenID tokenId)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> permStateResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE,
        conditionValue, permStateResults);
    return ret == ERR_OK && permStateResults.size() == 0;
}

bool DeleteIdentityMockTest::VerifyTokenInCache(AccessTokenID tokenId)
{
    auto tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInnerFromCache(tokenId);
    return tokenInfo != nullptr;
}

bool DeleteIdentityMockTest::VerifyTokenNotInCache(AccessTokenID tokenId)
{
    return !VerifyTokenInCache(tokenId);
}

bool DeleteIdentityMockTest::VerifyBundleInCache(const std::string& bundleName, AccessTokenID tokenId)
{
    auto bundleInfo = AccessTokenInfoManager::GetInstance().GetBundleInfoInner(bundleName);
    if (bundleInfo == nullptr) {
        return false;
    }
    // Check if the tokenId is in the bundle's token list
    for (auto id : bundleInfo->tokenIds) {
        if (id == tokenId) {
            return true;
        }
    }
    return false;
}

bool DeleteIdentityMockTest::VerifyBundleNotInCache(const std::string& bundleName)
{
    auto bundleInfo = AccessTokenInfoManager::GetInstance().GetBundleInfoInner(bundleName);
    return bundleInfo == nullptr;
}

bool DeleteIdentityMockTest::VerifyPermissionDeletedFromKernel(AccessTokenID tokenId)
{
    std::vector<uint32_t> opCodeList;
    int32_t ret = GetPermissionsFromKernel(tokenId, opCodeList);
    // If get permissions fails, we consider it as deleted (token doesn't exist in kernel)
    return ret != RET_SUCCESS || opCodeList.size() == 0;
}

bool DeleteIdentityMockTest::VerifySpmDeletedFromKernel(AccessTokenID tokenId)
{
    if (!PermissionKernelUtils::IsKernelSupportSpm()) {
        // If SPM is not supported, skip the check
        return true;
    }

    // Try to get SPM entry from kernel
    SpmData* spmData = SpmDataNew(0, 0, SPM_NAME_BUF_SIZE);
    if (spmData == nullptr) {
        return false;
    }

    int ret = SpmGetEntry(tokenId, spmData);
    SpmDataFree(spmData);

    // If get entry fails (e.g., ENOTSUP or entry not found), we consider it as deleted
    return ret != RET_SUCCESS;
}

void DeleteIdentityMockTest::CleanTestData(const std::string& bundleName, int32_t userID)
{
    // Delete all tokens for this bundle using INVALID_TOKENID
    int32_t sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, bundleName,
        ReservedType::NONE, sceneCode);
}

void DeleteIdentityMockTest::CleanAllTestData()
{
    // Clean up all test bundles
    std::vector<std::string> testBundles = {
        "DeleteIdentityTest001", "DeleteIdentityTest002", "DeleteIdentityTest003",
        "DeleteIdentityTest004", "DeleteIdentityTest005", "DeleteIdentityTest006",
        "DeleteIdentityTest007", "DeleteIdentityTest008", "DeleteIdentityTest009",
        "DeleteIdentityTest010", "DeleteIdentityTest011", "DeleteIdentityTest012",
        "DeleteIdentityTest012B", "DeleteIdentityTest013", "DeleteIdentityTest014",
        "DeleteIdentityTest015", "DeleteIdentityTest016", "DeleteIdentityTest017",
        "DeleteIdentityTest018", "DeleteIdentityTest019", "DeleteIdentityTest020"
    };

    for (const auto& bundleName : testBundles) {
        // Use INVALID_TOKENID to delete all tokens for this bundle
        int32_t sceneCode = 0;
        atManagerService_->DeleteIdentityCore(INVALID_TOKENID, bundleName,
            ReservedType::NONE, sceneCode);
    }
}

/**
 * @tc.name: DeleteIdentityTest001
 * @tc.desc: Test delete a token with type NONE (direct deletion).
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest001, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic]/acl:[cam]/Module001/DeleteIdentityTest001";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "DeleteIdentityTest001";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    // Delete with type NONE
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId, "DeleteIdentityTest001",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_NORMAL, sceneCode);

    // Verify all data is deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId));
    EXPECT_TRUE(VerifyBundleDeletedFromDatabase("DeleteIdentityTest001"));

    // Verify kernel data is deleted
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId));

    // Clean up test data
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest001",
        ReservedType::NONE, sceneCode);
}

/**
 * @tc.name: DeleteIdentityTest002
 * @tc.desc: Test delete a token with type RESERVED_IDENTITY (token reserved).
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest002, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic]/acl:[cam]/Module001/DeleteIdentityTest002";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "DeleteIdentityTest002";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    // Delete with type RESERVED_IDENTITY
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId, "DeleteIdentityTest002",
        ReservedType::RESERVED_IDENTITY, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_KEEP_TOKEN_FINISH, sceneCode);

    // Verify token info exists with uid=-1 and reserved=1
    int32_t uid, reserved;
    EXPECT_TRUE(VerifyTokenExistsInDatabase(tokenId, uid, reserved));
    EXPECT_EQ(-1, uid);
    EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_IDENTITY), reserved);

    // Verify bundle info is deleted
    EXPECT_TRUE(VerifyBundleDeletedFromDatabase("DeleteIdentityTest002"));

    // Verify permission state is deleted
    EXPECT_TRUE(VerifyPermissionDeletedFromDatabase(tokenId));

    // Verify kernel data is deleted
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId));

    // Clean up test data
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest002",
        ReservedType::NONE, sceneCode);
}

/**
 * @tc.name: DeleteIdentityTest003
 * @tc.desc: Test delete a token with type RESERVED_DATA (data reserved).
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest003, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam,mic]/acl:[cam]/Module001/DeleteIdentityTest003";
    std::vector<std::string> hapPaths = {path};
    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "DeleteIdentityTest003";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    // Delete with type RESERVED_DATA
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId, "DeleteIdentityTest003",
        ReservedType::RESERVED_DATA, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_KEEP_DATA, sceneCode);

    // Verify token info exists with uid unchanged and reserved=2
    int32_t uid, reserved;
    EXPECT_TRUE(VerifyTokenExistsInDatabase(tokenId, uid, reserved));
    EXPECT_NE(-1, uid);
    EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_DATA), reserved);

    // Verify bundle info is deleted
    EXPECT_TRUE(VerifyBundleDeletedFromDatabase("DeleteIdentityTest003"));

    // Verify permission state is NOT deleted (reserved data)
    EXPECT_FALSE(VerifyPermissionDeletedFromDatabase(tokenId));

    // Verify kernel data is deleted even for RESERVED_DATA
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId));

    // Clean up test data
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest003",
        ReservedType::NONE, sceneCode);
}

/**
 * @tc.name: DeleteIdentityTest004
 * @tc.desc: Test create token1 and token2 (app clone), delete token1 with NONE.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest004, TestSize.Level0)
{
    std::string path1 = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest004";
    std::string path2 = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest004";
    std::vector<std::string> hapPaths1 = {path1};
    std::vector<std::string> hapPaths2 = {path2};

    // Create token1
    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = "DeleteIdentityTest004";
    baseInfo1.instIndex = 0;
    BundlePolicy bundlePolicy1;
    bundlePolicy1.dlpType = DLP_COMMON;
    bundlePolicy1.isDebugGrant = false;

    Identity identity1;
    InstallHap(hapPaths1, baseInfo1, bundlePolicy1, identity1);
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);

    // Create token2 (app clone)
    HapBaseInfo baseInfo2;
    baseInfo2.userID = 100;
    baseInfo2.bundleName = "DeleteIdentityTest004";
    baseInfo2.instIndex = 1;
    BundlePolicy bundlePolicy2;
    bundlePolicy2.dlpType = DLP_COMMON;
    bundlePolicy2.isDebugGrant = false;

    Identity identity2;
    CloneApp(path2, baseInfo2, bundlePolicy2, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    // Delete token1 with type NONE
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId1, "DeleteIdentityTest004",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_NORMAL, sceneCode);

    // Verify bundle info still exists (token2 still exists)
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "DeleteIdentityTest004");
    std::vector<GenericValues> results;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_GT(results.size(), 0);

    // Verify token1 is deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId1));

    // Verify token1 is removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId1));

    // Verify bundle still exists in cache (token2 still exists)
    EXPECT_TRUE(VerifyBundleInCache("DeleteIdentityTest004", tokenId2));

    // Verify token2 is in cache
    EXPECT_TRUE(VerifyTokenInCache(tokenId2));

    // Delete token2
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId2, "DeleteIdentityTest004",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_NORMAL, sceneCode);

    // Verify all data is deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId2));
    EXPECT_TRUE(VerifyBundleDeletedFromDatabase("DeleteIdentityTest004"));

    // Verify all tokens are removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId2));
    EXPECT_TRUE(VerifyBundleNotInCache("DeleteIdentityTest004"));

    // Verify kernel data is deleted
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId2));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId2));

    // Clean up test data
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest004",
        ReservedType::NONE, sceneCode);
}

/**
 * @tc.name: DeleteIdentityTest005
 * @tc.desc: Test create token1 and token2 (app clone), delete token1 with RESERVED_IDENTITY.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest005, TestSize.Level0)
{
    std::string path1 = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest005";
    std::string path2 = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest005";
    std::vector<std::string> hapPaths1 = {path1};
    std::vector<std::string> hapPaths2 = {path2};

    // Create token1
    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = "DeleteIdentityTest005";
    baseInfo1.instIndex = 0;
    BundlePolicy bundlePolicy1;
    bundlePolicy1.dlpType = DLP_COMMON;
    bundlePolicy1.isDebugGrant = false;

    Identity identity1;
    InstallHap(hapPaths1, baseInfo1, bundlePolicy1, identity1);
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);

    // Create token2 (app clone)
    HapBaseInfo baseInfo2;
    baseInfo2.userID = 100;
    baseInfo2.bundleName = "DeleteIdentityTest005";
    baseInfo2.instIndex = 1;
    BundlePolicy bundlePolicy2;
    bundlePolicy2.dlpType = DLP_COMMON;
    bundlePolicy2.isDebugGrant = false;

    Identity identity2;
    CloneApp(path2, baseInfo2, bundlePolicy2, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    // Delete token1 with type RESERVED_IDENTITY
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId1, "DeleteIdentityTest005",
        ReservedType::RESERVED_IDENTITY, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_KEEP_TOKEN_FINISH, sceneCode);

    // Verify bundle info still exists
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "DeleteIdentityTest005");
    std::vector<GenericValues> results;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_GT(results.size(), 0);

    // Verify token1 exists with uid=-1
    int32_t uid, reserved;
    EXPECT_TRUE(VerifyTokenExistsInDatabase(tokenId1, uid, reserved));
    EXPECT_EQ(-1, uid);

    // Verify token1 is removed from cache (RESERVED_IDENTITY removes cache)
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId1));

    // Verify bundle still exists in cache (token2 still exists)
    EXPECT_TRUE(VerifyBundleInCache("DeleteIdentityTest005", tokenId2));

    // Verify token2 is in cache
    EXPECT_TRUE(VerifyTokenInCache(tokenId2));

    // Delete token2 with type NONE
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId2, "DeleteIdentityTest005",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_NORMAL, sceneCode);

    // Verify all data is deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId2));
    EXPECT_TRUE(VerifyBundleDeletedFromDatabase("DeleteIdentityTest005"));

    // Verify all tokens are removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId2));
    EXPECT_TRUE(VerifyBundleNotInCache("DeleteIdentityTest005"));

    // Verify kernel data is deleted
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId2));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId2));

    // Clean up test data
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest005",
        ReservedType::NONE, sceneCode);
}

/**
 * @tc.name: DeleteIdentityTest006
 * @tc.desc: Test create token1 and token2 (app clone), delete token1 with RESERVED_DATA.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest006, TestSize.Level0)
{
    std::string path1 = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest006";
    std::string path2 = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest006";
    std::vector<std::string> hapPaths1 = {path1};
    std::vector<std::string> hapPaths2 = {path2};

    // Create token1
    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = "DeleteIdentityTest006";
    baseInfo1.instIndex = 0;
    BundlePolicy bundlePolicy1;
    bundlePolicy1.dlpType = DLP_COMMON;
    bundlePolicy1.isDebugGrant = false;

    Identity identity1;
    InstallHap(hapPaths1, baseInfo1, bundlePolicy1, identity1);
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);

    // Create token2 (app clone)
    HapBaseInfo baseInfo2;
    baseInfo2.userID = 100;
    baseInfo2.bundleName = "DeleteIdentityTest006";
    baseInfo2.instIndex = 1;
    BundlePolicy bundlePolicy2;
    bundlePolicy2.dlpType = DLP_COMMON;
    bundlePolicy2.isDebugGrant = false;

    Identity identity2;
    CloneApp(path2, baseInfo2, bundlePolicy2, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    // Delete token1 with type RESERVED_DATA
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId1, "DeleteIdentityTest006",
        ReservedType::RESERVED_DATA, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_KEEP_DATA, sceneCode);

    // Verify bundle info still exists
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "DeleteIdentityTest006");
    std::vector<GenericValues> results;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_GT(results.size(), 0);

    // Verify token1 exists with uid unchanged
    int32_t uid, reserved;
    EXPECT_TRUE(VerifyTokenExistsInDatabase(tokenId1, uid, reserved));
    EXPECT_NE(-1, uid);

    // Verify token1 is removed from cache (RESERVED_DATA removes cache)
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId1));

    // Verify bundle still exists in cache (token2 still exists)
    EXPECT_TRUE(VerifyBundleInCache("DeleteIdentityTest006", tokenId2));

    // Verify token2 is in cache
    EXPECT_TRUE(VerifyTokenInCache(tokenId2));

    // Delete token2 with type NONE
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId2, "DeleteIdentityTest006",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_NORMAL, sceneCode);

    // Verify all data is deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId2));
    EXPECT_TRUE(VerifyBundleDeletedFromDatabase("DeleteIdentityTest006"));

    // Verify all tokens are removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId2));
    EXPECT_TRUE(VerifyBundleNotInCache("DeleteIdentityTest006"));

    // Verify kernel data is deleted
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId2));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId2));

    // Clean up test data
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest006",
        ReservedType::NONE, sceneCode);
}

/**
 * @tc.name: DeleteIdentityTest007
 * @tc.desc: Test create token1 and token2 (multi-user same app), delete token1 with NONE.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest007, TestSize.Level0)
{
    std::string path1 = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest007";
    std::string path2 = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest007";
    std::vector<std::string> hapPaths1 = {path1};
    std::vector<std::string> hapPaths2 = {path2};

    // Create token1 (user 100)
    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = "DeleteIdentityTest007";
    baseInfo1.instIndex = 0;
    BundlePolicy bundlePolicy1;
    bundlePolicy1.dlpType = DLP_COMMON;
    bundlePolicy1.isDebugGrant = false;

    Identity identity1;
    InstallHap(hapPaths1, baseInfo1, bundlePolicy1, identity1);
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);
    int32_t bundleId1 = identity1.uid - 100 * UID_MASK;

    // Create token2 (user 101, same bundleName and instIndex)
    HapBaseInfo baseInfo2;
    baseInfo2.userID = 101;
    baseInfo2.bundleName = "DeleteIdentityTest007";
    baseInfo2.instIndex = 0;
    BundlePolicy bundlePolicy2;
    bundlePolicy2.dlpType = DLP_COMMON;
    bundlePolicy2.isDebugGrant = false;

    Identity identity2;
    CloneApp(path2, baseInfo2, bundlePolicy2, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);
    int32_t bundleId2 = identity2.uid - 101 * UID_MASK;

    // Verify bundleId is the same for multi-user
    EXPECT_EQ(bundleId1, bundleId2);

    // Delete token1 with type NONE
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId1, "DeleteIdentityTest007",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_NORMAL, sceneCode);

    // Verify bundle info still exists (token2 still exists)
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "DeleteIdentityTest007");
    std::vector<GenericValues> results;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_GT(results.size(), 0);

    // Verify token1 is deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId1));

    // Verify token1 is removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId1));

    // Verify bundle still exists in cache (token2 still exists)
    EXPECT_TRUE(VerifyBundleInCache("DeleteIdentityTest007", tokenId2));

    // Verify token2 is in cache
    EXPECT_TRUE(VerifyTokenInCache(tokenId2));

    // Delete token2 with type NONE
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId2, "DeleteIdentityTest007",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_NORMAL, sceneCode);

    // Verify all data is deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId2));
    EXPECT_TRUE(VerifyBundleDeletedFromDatabase("DeleteIdentityTest007"));

    // Verify all tokens are removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId2));
    EXPECT_TRUE(VerifyBundleNotInCache("DeleteIdentityTest007"));

    // Verify kernel data is deleted
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId2));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId2));

    // Clean up test data (cleans all users)
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest007",
        ReservedType::NONE, sceneCode);
}

/**
 * @tc.name: DeleteIdentityTest008
 * @tc.desc: Test create token1 and token2 (multi-user), delete token1 with RESERVED_IDENTITY.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest008, TestSize.Level0)
{
    std::string path1 = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest008";
    std::string path2 = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest008";
    std::vector<std::string> hapPaths1 = {path1};
    std::vector<std::string> hapPaths2 = {path2};

    // Create token1 (user 100)
    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = "DeleteIdentityTest008";
    baseInfo1.instIndex = 0;
    BundlePolicy bundlePolicy1;
    bundlePolicy1.dlpType = DLP_COMMON;
    bundlePolicy1.isDebugGrant = false;

    Identity identity1;
    InstallHap(hapPaths1, baseInfo1, bundlePolicy1, identity1);
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);

    // Create token2 (user 101)
    HapBaseInfo baseInfo2;
    baseInfo2.userID = 101;
    baseInfo2.bundleName = "DeleteIdentityTest008";
    baseInfo2.instIndex = 0;
    BundlePolicy bundlePolicy2;
    bundlePolicy2.dlpType = DLP_COMMON;
    bundlePolicy2.isDebugGrant = false;

    Identity identity2;
    CloneApp(path2, baseInfo2, bundlePolicy2, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    // Delete token1 with type RESERVED_IDENTITY
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId1, "DeleteIdentityTest008",
        ReservedType::RESERVED_IDENTITY, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_KEEP_TOKEN_FINISH, sceneCode);

    // Verify token1 exists with uid=-1
    int32_t uid, reserved;
    EXPECT_TRUE(VerifyTokenExistsInDatabase(tokenId1, uid, reserved));
    EXPECT_EQ(-1, uid);

    // Verify token1 is removed from cache (RESERVED_IDENTITY removes cache)
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId1));

    // Verify bundle still exists in cache (token2 still exists)
    EXPECT_TRUE(VerifyBundleInCache("DeleteIdentityTest008", tokenId2));

    // Verify token2 is in cache
    EXPECT_TRUE(VerifyTokenInCache(tokenId2));

    // Delete token2 with type NONE
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId2, "DeleteIdentityTest008",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_NORMAL, sceneCode);

    // Verify all data is deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId2));
    EXPECT_TRUE(VerifyBundleDeletedFromDatabase("DeleteIdentityTest008"));

    // Verify all tokens are removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId2));
    EXPECT_TRUE(VerifyBundleNotInCache("DeleteIdentityTest008"));

    // Verify kernel data is deleted
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId2));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId2));

    // Clean up test data (cleans all users)
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest008",
        ReservedType::NONE, sceneCode);
}

/**
 * @tc.name: DeleteIdentityTest009
 * @tc.desc: Test create token1 and token2 (multi-user), delete token1 with RESERVED_DATA.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest009, TestSize.Level0)
{
    std::string path1 = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest009";
    std::string path2 = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest009";
    std::vector<std::string> hapPaths1 = {path1};
    std::vector<std::string> hapPaths2 = {path2};

    // Create token1 (user 100)
    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = "DeleteIdentityTest009";
    baseInfo1.instIndex = 0;
    BundlePolicy bundlePolicy1;
    bundlePolicy1.dlpType = DLP_COMMON;
    bundlePolicy1.isDebugGrant = false;

    Identity identity1;
    InstallHap(hapPaths1, baseInfo1, bundlePolicy1, identity1);
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);

    // Create token2 (user 101)
    HapBaseInfo baseInfo2;
    baseInfo2.userID = 101;
    baseInfo2.bundleName = "DeleteIdentityTest009";
    baseInfo2.instIndex = 0;
    BundlePolicy bundlePolicy2;
    bundlePolicy2.dlpType = DLP_COMMON;
    bundlePolicy2.isDebugGrant = false;

    Identity identity2;
    CloneApp(path2, baseInfo2, bundlePolicy2, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    // Delete token1 with type RESERVED_DATA
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId1, "DeleteIdentityTest009",
        ReservedType::RESERVED_DATA, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_KEEP_DATA, sceneCode);

    // Verify token1 exists with uid unchanged
    int32_t uid, reserved;
    EXPECT_TRUE(VerifyTokenExistsInDatabase(tokenId1, uid, reserved));
    EXPECT_NE(-1, uid);

    // Verify token1 is removed from cache (RESERVED_DATA removes cache)
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId1));

    // Verify bundle still exists in cache (token2 still exists)
    EXPECT_TRUE(VerifyBundleInCache("DeleteIdentityTest009", tokenId2));

    // Verify token2 is in cache
    EXPECT_TRUE(VerifyTokenInCache(tokenId2));

    // Delete token2 with type NONE
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId2, "DeleteIdentityTest009",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_NORMAL, sceneCode);

    // Verify all data is deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId2));
    EXPECT_TRUE(VerifyBundleDeletedFromDatabase("DeleteIdentityTest009"));

    // Verify all tokens are removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId2));
    EXPECT_TRUE(VerifyBundleNotInCache("DeleteIdentityTest009"));

    // Verify kernel data is deleted
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId2));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId2));

    // Clean up test data (cleans all users)
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest009",
        ReservedType::NONE, sceneCode);
}

/**
 * @tc.name: DeleteIdentityTest010
 * @tc.desc: Test create 3 tokens (token1 clone, token3 multi-user), delete with mixed types.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest010, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest010";
    std::vector<std::string> hapPaths = {path};

    // Create token1 (user 100, instIndex 0)
    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = "DeleteIdentityTest010";
    baseInfo1.instIndex = 0;
    BundlePolicy bundlePolicy1;
    bundlePolicy1.dlpType = DLP_COMMON;
    bundlePolicy1.isDebugGrant = false;

    Identity identity1;
    InstallHap(hapPaths, baseInfo1, bundlePolicy1, identity1);
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);

    // Create token2 (user 100, instIndex 1 - app clone)
    HapBaseInfo baseInfo2;
    baseInfo2.userID = 100;
    baseInfo2.bundleName = "DeleteIdentityTest010";
    baseInfo2.instIndex = 1;
    BundlePolicy bundlePolicy2;
    bundlePolicy2.dlpType = DLP_COMMON;
    bundlePolicy2.isDebugGrant = false;

    Identity identity2;
    CloneApp(path, baseInfo2, bundlePolicy2, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    // Create token3 (user 101, instIndex 0 - multi-user)
    HapBaseInfo baseInfo3;
    baseInfo3.userID = 101;
    baseInfo3.bundleName = "DeleteIdentityTest010";
    baseInfo3.instIndex = 0;
    BundlePolicy bundlePolicy3;
    bundlePolicy3.dlpType = DLP_COMMON;
    bundlePolicy3.isDebugGrant = false;

    Identity identity3;
    CloneApp(path, baseInfo3, bundlePolicy3, identity3);
    AccessTokenID tokenId3 = static_cast<AccessTokenID>(identity3.tokenId);

    // Delete token1 with RESERVED_IDENTITY
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId1, "DeleteIdentityTest010",
        ReservedType::RESERVED_IDENTITY, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_KEEP_TOKEN_FINISH, sceneCode);

    // Delete token2 with NONE
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId2, "DeleteIdentityTest010",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_NORMAL, sceneCode);

    // Delete token3 with RESERVED_DATA
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId3, "DeleteIdentityTest010",
        ReservedType::RESERVED_DATA, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_KEEP_DATA, sceneCode);

    // Verify token1 exists with reserved
    int32_t uid, reserved;
    EXPECT_TRUE(VerifyTokenExistsInDatabase(tokenId1, uid, reserved));
    EXPECT_EQ(-1, uid);

    // Verify token2 is deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId2));

    // Verify token3 exists with reserved
    EXPECT_TRUE(VerifyTokenExistsInDatabase(tokenId3, uid, reserved));
    EXPECT_NE(-1, uid);

    // Verify cache states
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId1));
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId2));
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId3));
    EXPECT_TRUE(VerifyBundleNotInCache("DeleteIdentityTest010"));

    // Verify kernel data is deleted
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId2));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId2));
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId3));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId3));

    // Clean up test data (cleans all users)
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest010",
        ReservedType::NONE, sceneCode);
}

/**
 * @tc.name: DeleteIdentityTest011
 * @tc.desc: Test delete by bundleId only (without tokenId).
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest011, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest011";
    std::vector<std::string> hapPaths = {path};

    // Create token1 (user 100, instIndex 0)
    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = "DeleteIdentityTest011";
    baseInfo1.instIndex = 0;
    BundlePolicy bundlePolicy1;
    bundlePolicy1.dlpType = DLP_COMMON;
    bundlePolicy1.isDebugGrant = false;

    Identity identity1;
    InstallHap(hapPaths, baseInfo1, bundlePolicy1, identity1);
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);

    // Create token2 (user 100, instIndex 1)
    HapBaseInfo baseInfo2;
    baseInfo2.userID = 100;
    baseInfo2.bundleName = "DeleteIdentityTest011";
    baseInfo2.instIndex = 1;
    BundlePolicy bundlePolicy2;
    bundlePolicy2.dlpType = DLP_COMMON;
    bundlePolicy2.isDebugGrant = false;

    Identity identity2;
    CloneApp(path, baseInfo2, bundlePolicy2, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    // Delete by bundleId only (delete all tokens for this bundle)
    // This requires using DeleteIdentity with INVALID_TOKENID
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest011",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_ALL_BUNDLE, sceneCode);

    // Verify all tokens are deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId1));
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId2));
    EXPECT_TRUE(VerifyBundleDeletedFromDatabase("DeleteIdentityTest011"));

    // Verify all tokens are removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId1));
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId2));
    EXPECT_TRUE(VerifyBundleNotInCache("DeleteIdentityTest011"));

    // Verify kernel data is deleted
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId2));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId2));
}

/**
 * @tc.name: DeleteIdentityTest012
 * @tc.desc: Test delete with mismatched tokenId and bundleName.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest012, TestSize.Level0)
{
    std::string path1 = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest012";
    std::vector<std::string> hapPaths1 = {path1};

    // Create token1
    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = "DeleteIdentityTest012";
    baseInfo1.instIndex = 0;
    BundlePolicy bundlePolicy1;
    bundlePolicy1.dlpType = DLP_COMMON;
    bundlePolicy1.isDebugGrant = false;

    Identity identity1;
    InstallHap(hapPaths1, baseInfo1, bundlePolicy1, identity1);
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);

    // Create token2 with different bundleName
    std::string path2 = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest012B";
    std::vector<std::string> hapPaths2 = {path2};

    HapBaseInfo baseInfo2;
    baseInfo2.userID = 100;
    baseInfo2.bundleName = "DeleteIdentityTest012B";
    baseInfo2.instIndex = 0;
    BundlePolicy bundlePolicy2;
    bundlePolicy2.dlpType = DLP_COMMON;
    bundlePolicy2.isDebugGrant = false;

    Identity identity2;
    InstallHap(hapPaths2, baseInfo2, bundlePolicy2, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    // Try to delete token1 with wrong bundleName (bundleName of token2)
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId1, "DeleteIdentityTest012B",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    // Verify token1 still exists
    int32_t uid, reserved;
    EXPECT_TRUE(VerifyTokenExistsInDatabase(tokenId1, uid, reserved));

    // Verify token1 still exists in cache
    EXPECT_TRUE(VerifyTokenInCache(tokenId1));

    // Clean up
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId1, "DeleteIdentityTest012",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_NORMAL, sceneCode);
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId2, "DeleteIdentityTest012B",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_NORMAL, sceneCode);

    // Clean up test data
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest012",
        ReservedType::NONE, sceneCode);
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest012B",
        ReservedType::NONE, sceneCode);
}

/**
 * @tc.name: DeleteIdentityTest013
 * @tc.desc: Test delete with non-existent tokenId.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest013, TestSize.Level0)
{
    // Use a non-existent tokenId (create a valid tokenId but delete it first)
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest013";
    std::vector<std::string> hapPaths = {path};

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "DeleteIdentityTest013";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    // Delete the token first
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId, "DeleteIdentityTest013",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_NORMAL, sceneCode);

    // Try to delete again with the same tokenId (now non-existent)
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "DeleteIdentityTest013",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_TOKENID_NOT_EXIST, ret);

    // Clean up test data
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest013",
        ReservedType::NONE, sceneCode);
}

/**
 * @tc.name: DeleteIdentityTest014
 * @tc.desc: Test delete with native tokenId (non-HAP token).
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest014, TestSize.Level0)
{
    // Register a native token ID directly
    AccessTokenID nativeTokenId = 671688430; // 671688430: Native token ID format

    // Try to delete native token with DeleteIdentity (should fail)
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(nativeTokenId, "DeleteIdentityTest014",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: DeleteIdentityTest015
 * @tc.desc: Test delete by bundleName only with RESERVED_DATA type.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest015, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest015";
    std::vector<std::string> hapPaths = {path};

    // Create token1
    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = "DeleteIdentityTest015";
    baseInfo1.instIndex = 0;
    BundlePolicy bundlePolicy1;
    bundlePolicy1.dlpType = DLP_COMMON;
    bundlePolicy1.isDebugGrant = false;

    Identity identity1;
    InstallHap(hapPaths, baseInfo1, bundlePolicy1, identity1);
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);

    // Create token2 (app clone)
    HapBaseInfo baseInfo2;
    baseInfo2.userID = 100;
    baseInfo2.bundleName = "DeleteIdentityTest015";
    baseInfo2.instIndex = 1;
    BundlePolicy bundlePolicy2;
    bundlePolicy2.dlpType = DLP_COMMON;
    bundlePolicy2.isDebugGrant = false;

    Identity identity2;
    CloneApp(path, baseInfo2, bundlePolicy2, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    // Try to delete by bundleName only with RESERVED_DATA type (should fail or be rejected)
    // When using INVALID_TOKENID, only NONE type should be allowed
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest015",
        ReservedType::RESERVED_DATA, sceneCode);
    // This should either fail or be treated as NONE deletion
    // Based on implementation, it might be rejected or converted to NONE
    EXPECT_EQ(ret, ERR_PARAM_INVALID);

    // Clean up with correct type
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest015",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_ALL_BUNDLE, sceneCode);

    // Verify all tokens are deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId1));
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId2));
    EXPECT_TRUE(VerifyBundleDeletedFromDatabase("DeleteIdentityTest015"));

    // Verify all tokens are removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId1));
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId2));
    EXPECT_TRUE(VerifyBundleNotInCache("DeleteIdentityTest015"));

    // Verify kernel data is deleted
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId2));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId2));
}

/**
 * @tc.name: DeleteIdentityTest016
 * @tc.desc: Test delete by bundleName only with RESERVED_IDENTITY type.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest016, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest016";
    std::vector<std::string> hapPaths = {path};

    // Create token1
    HapBaseInfo baseInfo1;
    baseInfo1.userID = 100;
    baseInfo1.bundleName = "DeleteIdentityTest016";
    baseInfo1.instIndex = 0;
    BundlePolicy bundlePolicy1;
    bundlePolicy1.dlpType = DLP_COMMON;
    bundlePolicy1.isDebugGrant = false;

    Identity identity1;
    InstallHap(hapPaths, baseInfo1, bundlePolicy1, identity1);
    AccessTokenID tokenId1 = static_cast<AccessTokenID>(identity1.tokenId);

    // Create token2 (app clone)
    HapBaseInfo baseInfo2;
    baseInfo2.userID = 100;
    baseInfo2.bundleName = "DeleteIdentityTest016";
    baseInfo2.instIndex = 1;
    BundlePolicy bundlePolicy2;
    bundlePolicy2.dlpType = DLP_COMMON;
    bundlePolicy2.isDebugGrant = false;

    Identity identity2;
    CloneApp(path, baseInfo2, bundlePolicy2, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    // Try to delete by bundleName only with RESERVED_IDENTITY type (should fail)
    // When using INVALID_TOKENID, only NONE type should be allowed
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest016",
        ReservedType::RESERVED_IDENTITY, sceneCode);
    EXPECT_EQ(ret, ERR_PARAM_INVALID);

    // Clean up with correct type
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest016",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_ALL_BUNDLE, sceneCode);

    // Verify all tokens are deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId1));
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId2));
    EXPECT_TRUE(VerifyBundleDeletedFromDatabase("DeleteIdentityTest016"));

    // Verify all tokens are removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId1));
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId2));
    EXPECT_TRUE(VerifyBundleNotInCache("DeleteIdentityTest016"));

    // Verify kernel data is deleted
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId1));
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId2));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId2));
}

/**
 * @tc.name: DeleteIdentityTest017
 * @tc.desc: Test delete with empty bundleName.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest017, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest017";
    std::vector<std::string> hapPaths = {path};

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "DeleteIdentityTest017";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    // Try to delete with empty bundleName
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId, "",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_PARAM_INVALID, ret);

    // Verify token still exists in cache (no deletion happened)
    EXPECT_TRUE(VerifyTokenInCache(tokenId));

    // Clean up
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "DeleteIdentityTest017",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_NORMAL, sceneCode);

    // Verify token is deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId));
    EXPECT_TRUE(VerifyBundleDeletedFromDatabase("DeleteIdentityTest017"));

    // Verify token is removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId));
    EXPECT_TRUE(VerifyBundleNotInCache("DeleteIdentityTest017"));

    // Verify kernel data is deleted
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId));
}

/**
 * @tc.name: DeleteIdentityTest018
 * @tc.desc: Test delete already deleted token with RESERVED_DATA type.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest018, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest018";
    std::vector<std::string> hapPaths = {path};

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "DeleteIdentityTest018";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    // Delete with RESERVED_DATA
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId, "DeleteIdentityTest018",
        ReservedType::RESERVED_DATA, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_KEEP_DATA, sceneCode);

    // Verify token is reserved
    int32_t uid, reserved;
    EXPECT_TRUE(VerifyTokenExistsInDatabase(tokenId, uid, reserved));
    EXPECT_NE(-1, uid);
    EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_DATA), reserved);

    // Verify kernel data is deleted (should be deleted even for RESERVED_DATA)
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId));

    // Try to delete again with RESERVED_DATA
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "DeleteIdentityTest018",
        ReservedType::RESERVED_DATA, sceneCode);
    // shouwd be NONE to remove reserved token
    EXPECT_EQ(ret, ERR_PARAM_INVALID);

    // Clean up - delete the reserved token with NONE type
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "DeleteIdentityTest018",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_RESERVED_TOKEN, sceneCode);

    // Verify kernel data is deleted (should be deleted when RESERVED_DATA is used)
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId));

    // Clean up test data
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest018",
        ReservedType::NONE, sceneCode);
}

/**
 * @tc.name: DeleteIdentityTest019
 * @tc.desc: Test delete already deleted token with RESERVED_IDENTITY type.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest019, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest019";
    std::vector<std::string> hapPaths = {path};

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "DeleteIdentityTest019";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    // Delete with RESERVED_IDENTITY
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId, "DeleteIdentityTest019",
        ReservedType::RESERVED_IDENTITY, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_KEEP_TOKEN_FINISH, sceneCode);

    // Verify token is reserved
    int32_t uid, reserved;
    EXPECT_TRUE(VerifyTokenExistsInDatabase(tokenId, uid, reserved));
    EXPECT_EQ(-1, uid);
    EXPECT_EQ(static_cast<int32_t>(ReservedType::RESERVED_IDENTITY), reserved);

    // Verify token1 is removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId));

    // Verify kernel data is deleted (should be deleted even for RESERVED_IDENTITY)
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId));

    // Try to delete again with RESERVED_IDENTITY
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "DeleteIdentityTest019",
        ReservedType::RESERVED_IDENTITY, sceneCode);
    // only support NONE to delete reserved token
    EXPECT_EQ(ret, ERR_PARAM_INVALID);

    // Delete the token completely using NONE type
    int32_t ret2 = atManagerService_->DeleteIdentityCore(tokenId, "DeleteIdentityTest019",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret2);
}

/**
 * @tc.name: DeleteIdentityTest020
 * @tc.desc: Test delete reserved token with NONE type.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(DeleteIdentityMockTest, DeleteIdentityTest020, TestSize.Level0)
{
    std::string path = "/SYSTEM/system_basic/state:[cam]/acl:[cam]/Module001/DeleteIdentityTest020";
    std::vector<std::string> hapPaths = {path};

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "DeleteIdentityTest020";
    baseInfo.instIndex = 0;
    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    // Delete with RESERVED_IDENTITY
    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId, "DeleteIdentityTest020",
        ReservedType::RESERVED_IDENTITY, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_KEEP_TOKEN_FINISH, sceneCode);

    // Verify token is reserved
    int32_t uid, reserved;
    EXPECT_TRUE(VerifyTokenExistsInDatabase(tokenId, uid, reserved));
    EXPECT_EQ(-1, uid);

    // Verify token is removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId));

    // Verify kernel data is deleted (should be deleted even for RESERVED_IDENTITY)
    EXPECT_TRUE(VerifyPermissionDeletedFromKernel(tokenId));
    EXPECT_TRUE(VerifySpmDeletedFromKernel(tokenId));

    // Now delete with NONE type (should completely remove)
    sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "DeleteIdentityTest020",
        ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(AT_DELETE_RESERVED_TOKEN, sceneCode);

    // Verify token is completely deleted
    EXPECT_TRUE(VerifyTokenDeletedFromDatabase(tokenId));
    EXPECT_TRUE(VerifyBundleDeletedFromDatabase("DeleteIdentityTest020"));

    // Verify all tokens are removed from cache
    EXPECT_TRUE(VerifyTokenNotInCache(tokenId));
    EXPECT_TRUE(VerifyBundleNotInCache("DeleteIdentityTest020"));

    // Clean up test data
    sceneCode = 0;
    atManagerService_->DeleteIdentityCore(INVALID_TOKENID, "DeleteIdentityTest020",
        ReservedType::NONE, sceneCode);
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
