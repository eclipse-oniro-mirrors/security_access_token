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

#define private public
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_info_utils.h"
#include "accesstoken_manager_service.h"
#include "accesstoken_migration_manager.h"
#include "boot_verify_scheduler.h"
#include "install_session_manager.h"
#undef private
#include "access_token.h"
#include "access_token_error.h"
#include "hap_token_info.h"
#include "generic_values.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
// test hap path example
// /SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/testModuleName/testBundleName
std::shared_ptr<AccessTokenManagerService> atManagerService_;
static InstallSessionManager* g_installSessionManager = nullptr;
static constexpr int32_t INVALID_SESSION = 999;
static constexpr int32_t UID_MASK = 200000;
}

void InstallSessionManagerMockTest::SetUpTestCase()
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
        g_installSessionManager->RollbackAll(session);
    }
}

void InstallHap(const std::vector<std::string>& hapPaths, const HapBaseInfo& baseInfo,
    const BundlePolicy& bundlePolicy, Identity& identity)
{
    BundleHapList hapList;
    hapList.hapPaths = hapPaths;
    hapList.isPreInstalled = false;
    hapList.userId = baseInfo.userID;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    Identity identity;
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
    ret = atManagerService_->DeleteIdentityCore(tokenId, "InstallHapTest001", ReservedType::NONE, sceneCode);
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
    Identity identity;
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
    ret = atManagerService_->DeleteIdentityCore(tokenId, "InstallHapTest002", ReservedType::NONE, sceneCode);
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

    Identity identity;
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
    ret = atManagerService_->DeleteIdentityCore(tokenId, "InstallHapTest003", ReservedType::NONE, sceneCode);
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

    Identity identity;
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
    ret = atManagerService_->DeleteIdentityCore(tokenId, "InstallHapTest004", ReservedType::NONE, sceneCode);
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

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);

    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId, "InstallHapTest005", ReservedType::NONE, sceneCode);
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

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);

    int32_t sceneCode = 0;
    int32_t ret = atManagerService_->DeleteIdentityCore(tokenId, "InstallHapTest006", ReservedType::NONE, sceneCode);
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

    Identity identity;
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
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue2, hapTokenResults);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(hapTokenResults.size(), 1);

    GenericValues conditionValue3;
    conditionValue3.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> permStateResults;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue3, permStateResults);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(permStateResults.size(), 4);

    int32_t sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "InstallHapTest007", ReservedType::NONE, sceneCode);
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

    Identity identity;
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
    ret = atManagerService_->DeleteIdentityCore(tokenId, "InstallHapTest008", ReservedType::NONE, sceneCode);
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    Identity identity;
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
    ret = atManagerService_->DeleteIdentityCore(tokenId, "InstallHapTest010", ReservedType::NONE, sceneCode);
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, hapResults);
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
    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    // system hap attr is not 0
    AccessTokenIDEx idEx;
    idEx.tokenIDEx = identity.tokenId;
    EXPECT_NE(idEx.tokenIdExStruct.tokenAttr, 0);
    int32_t sceneCode = 0;
    ASSERT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId, "InstallHapTest013", ReservedType::NONE, sceneCode));

    std::string path2 = "/state:[cam,mic]/Module001/InstallHapTest013";
    std::vector<std::string> hapPaths2 = {path2};
    Identity identity2;
    InstallHap(hapPaths2, baseInfo, bundlePolicy, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    // normal hap attr is 0
    AccessTokenIDEx idEx2;
    idEx2.tokenIDEx = identity2.tokenId;
    EXPECT_EQ(idEx2.tokenIdExStruct.tokenAttr, 0);
    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId2, "InstallHapTest013", ReservedType::NONE, sceneCode));
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
    Identity identity;
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

    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result));

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path2] = path2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> hapTokenResults;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, hapTokenResults));
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
        atManagerService_->DeleteIdentityCore(tokenId, "InstallHapTest014", ReservedType::NONE, sceneCode));
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
    Identity identity;
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

    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result));

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path2] = path2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> hapTokenResults;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, hapTokenResults));
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
        atManagerService_->DeleteIdentityCore(tokenId, "InstallHapTest015", ReservedType::NONE, sceneCode));
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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
    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId, "InstallHapTest016", ReservedType::NONE, sceneCode));
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
    Identity identity;
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
    ret = atManagerService_->DeleteIdentityCore(tokenId, "InstallHapTest017", ReservedType::NONE, sceneCode);
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
    EXPECT_NE(ERR_OK, ret);

    bundleInfo.clear();
    BundleHapList hapList2;
    ret = g_installSessionManager->CheckHapSignInfo(hapList2, nullptr, sessionId, bundleInfo);
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, InstallTypeEnum::TYPE_INSTALL, result);
    EXPECT_NE(ERR_OK, ret);

    int32_t sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "InstallHapFailedTest004", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->CheckHapPermissionInfo(INVALID_SESSION, InstallTypeEnum::TYPE_INSTALL, result);
    EXPECT_NE(ERR_OK, ret);
}

/**
 * @tc.name: InstallHapFailedTest005
 * @tc.desc: Test install a new hap, TYPE_REPLACE & TYPE_MERGE when hap not installed.
 * @tc.type: FUNC
 * @tc.require: Issue
 */
HWTEST_F(InstallSessionManagerMockTest, InstallHapFailedTest005, TestSize.Level0)
{
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(
        "/SYSTEM/system_basic/state:[cam,mic]/acl:[getwifi]/Module001/InstallHapFailedTest005");
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, InstallTypeEnum::TYPE_REPLACE, result);
    EXPECT_NE(ERR_OK, ret);

    sessionId = 0;
    bundleInfo.clear();
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result2;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, InstallTypeEnum::TYPE_MERGE, result2);
    EXPECT_NE(ERR_OK, ret);
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

    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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
    Identity identity;
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    Identity identity;
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity.uid);
    EXPECT_NE(0, identity.tokenId);

    Identity identity2;
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    Identity identity;
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    Identity identity;
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
    int32_t ret = g_installSessionManager->FinishInstall(INVALID_SESSION, false, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    Identity identity;
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity.uid);
    EXPECT_NE(0, identity.tokenId);

    std::vector<std::string> hapPaths = {path};
    Identity identity2;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity2);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity2.tokenId);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_NE(ERR_OK, ret);

    int32_t sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "InstallHapFailedTest017", ReservedType::NONE, sceneCode);
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    Identity identity;
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
    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
    EXPECT_EQ(ERR_OK, ret);

    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    Identity identity2;
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity2);
    EXPECT_NE(ERR_OK, ret);

    int32_t sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "InstallHapFailedTest019", ReservedType::NONE, sceneCode);
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    Identity identity;
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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

    Identity identity;
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
    Identity identity;
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
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy);
    EXPECT_EQ(ERR_OK, ret);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "UpdateHapTest001", ReservedType::NONE, sceneCode);
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
    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    bundlePolicy.preAuthorizationInfo.emplace_back(PreAuthorizationInfo{"ohos.permission.CAMERA", true});
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy);
    EXPECT_EQ(ERR_OK, ret);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "UpdateHapTest002", ReservedType::NONE, sceneCode);
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
    Identity identity;
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
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy);
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
    ret = atManagerService_->DeleteIdentityCore(tokenId, "UpdateHapTest003", ReservedType::NONE, sceneCode);
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
    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> permStateResults;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateResults);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(permStateResults.size(), 3);

    std::string path2 = "/SYSTEM/system_basic/state:[mic,syswin]/Module002/UpdateHapTest004";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.hapPaths.emplace_back(path2);
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy);
    EXPECT_EQ(ERR_OK, ret);

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    modulePathMap[path2] = path2;
    ret = g_installSessionManager->FinishInstall(sessionId, true, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    std::vector<GenericValues> permStateResults2;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateResults2);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_EQ(permStateResults2.size(), 4);

    int32_t sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "UpdateHapTest004", ReservedType::NONE, sceneCode);
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
    Identity identity;
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
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy);
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
    ret = atManagerService_->DeleteIdentityCore(tokenId, "UpdateHapTest005", ReservedType::NONE, sceneCode);
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
    Identity identity;
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
    ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
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
    ret = atManagerService_->DeleteIdentityCore(tokenId, "UpdateHapTest006", ReservedType::NONE, sceneCode);
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
    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    std::vector<GenericValues> results;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "UpdateHapTest007");
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results));
    EXPECT_EQ(results.size(), 2);

    GenericValues condition2;
    condition2.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> permState;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition2, permState));
    EXPECT_EQ(permState.size(), 3);

    EXPECT_NE(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_EQ(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM));

    std::string path3 = "/SYSTEM/system_basic/state:[cam,syswin]/Module002/UpdateHapTest007";
    std::string path4 = "/SYSTEM/system_basic/state:[manwifi]/acl:[manwifi]/Module003/UpdateHapTest007";
    BundleHapList hapList{std::vector<std::string>(), false, 100};
    hapList.hapPaths.emplace_back(path3);
    hapList.hapPaths.emplace_back(path4);

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo));
    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_MERGE, result));

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path3] = path3;
    modulePathMap[path4] = path4;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    std::vector<GenericValues> results2;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results2));
    EXPECT_EQ(results2.size(), 3);

    std::vector<GenericValues> permState2;
    EXPECT_EQ(ERR_OK, AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition2, permState2));
    EXPECT_EQ(permState2.size(), 4);

    EXPECT_EQ(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_NE(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.MICROPHONE", 2, USER_GRANTED_PERM));

    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.GET_WIFI_INFO_INTERNAL") == PERMISSION_GRANTED);
    
    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId, "UpdateHapTest007", ReservedType::NONE, sceneCode));
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
    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);


    g_installSessionManager->migrationDone_ = false;
    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId, bundlePolicy);
    EXPECT_NE(ERR_OK, ret);
    g_installSessionManager->migrationDone_ = true;

    int32_t sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "UpdateHapFailedTest001", ReservedType::NONE, sceneCode);
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
    Identity identity;
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
    Identity identity2;
    InstallHap(hapPaths2, baseInfo2, bundlePolicy2, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(INVALID_SESSION, tokenId, bundlePolicy);
    EXPECT_NE(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, tokenId2, bundlePolicy);
    EXPECT_NE(ERR_OK, ret);

    int32_t sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "UpdateHapFailedTest002", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
    ret = atManagerService_->DeleteIdentityCore(tokenId2, "UpdateHapFailedTest002-2", ReservedType::NONE, sceneCode);
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
    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
    EXPECT_EQ(ERR_OK, ret);
    HapInfoCheckResult result;
    ret = g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result);
    EXPECT_EQ(ERR_OK, ret);

    ret = g_installSessionManager->UpdateHapPolicy(sessionId, 123456789, bundlePolicy);
    EXPECT_NE(ERR_OK, ret);

    int32_t sceneCode = 0;
    ret = atManagerService_->DeleteIdentityCore(tokenId, "UpdateHapFailedTest003", ReservedType::NONE, sceneCode);
    EXPECT_EQ(ERR_OK, ret);
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

    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result));

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "FinishHapTest001";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
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

    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo));

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

    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo));

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

    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo));

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
    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    baseInfo.instIndex = 1;
    int32_t sessionId = 0;
    Identity identity2;
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
        atManagerService_->DeleteIdentityCore(tokenId, "AppCloneTest001", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId2, "AppCloneTest001", ReservedType::NONE, sceneCode));
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
    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_DENIED);
    int32_t ret = atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    bundlePolicy.dlpType = DLP_FULL_CONTROL;
    baseInfo.instIndex = 1;
    int32_t sessionId = 0;
    Identity identity2;
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
        atManagerService_->DeleteIdentityCore(tokenId, "AppCloneTest002", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId2, "AppCloneTest002", ReservedType::NONE, sceneCode));
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
    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    bundlePolicy.preAuthorizationInfo.emplace_back(PreAuthorizationInfo{"ohos.permission.CAMERA", true});
    baseInfo.instIndex = 1;
    int32_t sessionId = 0;
    Identity identity2;
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
        atManagerService_->DeleteIdentityCore(tokenId, "AppCloneTest003", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId2, "AppCloneTest003", ReservedType::NONE, sceneCode));
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
    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    baseInfo.userID = 101;
    int32_t sessionId = 0;
    Identity identity2;
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
        atManagerService_->DeleteIdentityCore(tokenId, "AppCloneTest004", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId2, "AppCloneTest004", ReservedType::NONE, sceneCode));
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
    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);
    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.SYSTEM_FLOAT_WINDOW") == PERMISSION_GRANTED);
    EXPECT_NE(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));

    baseInfo.userID = 101;
    int32_t sessionId = 0;
    Identity identity2;
    int32_t ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity2);
    EXPECT_EQ(ERR_OK, ret);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);
    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));
    EXPECT_NE(ERR_OK, atManagerService_->GrantPermission(tokenId2, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));

    std::string path2 = "/SYSTEM/system_basic/state:[cam,getwifi]/acl:[getwifi]/Module001/AppCloneTest005";
    BundleHapList hapList{std::vector<std::string>(), false, 100};
    hapList.hapPaths.emplace_back(path2);
    sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_REPLACE, result));

    baseInfo.userID = 100;
    baseInfo.instIndex = 1;
    Identity identity3;
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity3);
    EXPECT_EQ(ERR_OK, ret);
    AccessTokenID tokenId3 = static_cast<AccessTokenID>(identity3.tokenId);

    modulePathMap[path2] = path2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    EXPECT_TRUE(
        atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.SYSTEM_FLOAT_WINDOW") == PERMISSION_DENIED);

    EXPECT_EQ(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);
    EXPECT_EQ(ERR_OK, atManagerService_->GrantPermission(tokenId2, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId, "AppCloneTest005", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId2, "AppCloneTest005", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId3, "AppCloneTest005", ReservedType::NONE, sceneCode));
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

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_EQ(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, atManagerService_->DeleteIdentityCore(
        tokenId, "InstallReservedHapTest001", ReservedType::RESERVED_IDENTITY, sceneCode));

    Identity identity2;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    EXPECT_NE(tokenId, tokenId2);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_DENIED);

    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId2, "InstallReservedHapTest001", ReservedType::NONE, sceneCode));
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

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_EQ(ERR_OK, atManagerService_->GrantPermission(tokenId, "ohos.permission.CAMERA", 2, USER_GRANTED_PERM));
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, atManagerService_->DeleteIdentityCore(
        tokenId, "InstallReservedHapTest002", ReservedType::RESERVED_DATA, sceneCode));

    Identity identity2;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    EXPECT_EQ(tokenId, tokenId2);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId2, "InstallReservedHapTest002", ReservedType::NONE, sceneCode));
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

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    baseInfo.instIndex = 1;
    int32_t sessionId = 0;
    Identity identity2;
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
    EXPECT_EQ(ERR_OK, atManagerService_->DeleteIdentityCore(
        tokenId2, "InstallReservedHapTest003", ReservedType::RESERVED_DATA, sceneCode));

    sessionId = 0;
    Identity identity3;
    ret = g_installSessionManager->PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity3);
    EXPECT_EQ(ERR_OK, ret);
    EXPECT_NE(0, identity3.uid);
    EXPECT_NE(0, identity3.tokenId);
    AccessTokenID tokenId3 = static_cast<AccessTokenID>(identity3.tokenId);

    EXPECT_EQ(ERR_OK, g_installSessionManager->FinishInstall(sessionId, true, modulePathMap));

    EXPECT_EQ(tokenId3, tokenId2);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId3, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId, "InstallReservedHapTest003", ReservedType::NONE, sceneCode));
    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId3, "InstallReservedHapTest003", ReservedType::NONE, sceneCode));
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

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, atManagerService_->DeleteIdentityCore(
        tokenId, "InstallReservedHapTest004", ReservedType::RESERVED_DATA, sceneCode));

    bundlePolicy.isDebugGrant = false;
    Identity identity2;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    EXPECT_EQ(tokenId, tokenId2);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId2, "InstallReservedHapTest004", ReservedType::NONE, sceneCode));
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

    Identity identity;
    InstallHap(hapPaths, baseInfo, bundlePolicy, identity);
    AccessTokenID tokenId = static_cast<AccessTokenID>(identity.tokenId);

    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId, "ohos.permission.CAMERA") == PERMISSION_GRANTED);

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK, atManagerService_->DeleteIdentityCore(
        tokenId, "InstallReservedHapTest005", ReservedType::RESERVED_DATA, sceneCode));

    std::string path2 =
        "/SYSTEM/system_basic/state:[cam,mic,syswin,getwifi]/acl:[getwifi]/Module001/InstallReservedHapTest005";
    std::vector<std::string> hapPaths2 = {path2};
    Identity identity2;
    InstallHap(hapPaths2, baseInfo, bundlePolicy, identity2);
    AccessTokenID tokenId2 = static_cast<AccessTokenID>(identity2.tokenId);

    EXPECT_EQ(tokenId, tokenId2);
    EXPECT_TRUE(atManagerService_->VerifyAccessToken(tokenId2, "ohos.permission.CAMERA") == PERMISSION_DENIED);

    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId2, "InstallReservedHapTest005", ReservedType::NONE, sceneCode));
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

    int32_t ret = g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo);
    EXPECT_EQ(ERR_OK, ret);

    std::vector<TrustedBundleInfo> bundleInfo2;
    EXPECT_EQ(ERR_OK, g_installSessionManager->GetCacheSignInfoBySessionId(sessionId, bundleInfo2));

    EXPECT_EQ(bundleInfo.size(), hapList.hapPaths.size());
    EXPECT_EQ(bundleInfo.size(), bundleInfo2.size());

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[path] = path;
    ret = g_installSessionManager->FinishInstall(sessionId, false, modulePathMap);
    EXPECT_EQ(ERR_OK, ret);

    std::vector<TrustedBundleInfo> bundleInfo3;
    EXPECT_NE(ERR_OK, g_installSessionManager->GetCacheSignInfoBySessionId(INVALID_SESSION, bundleInfo3));
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
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo));

    HapInfoCheckResult result;
    EXPECT_EQ(ERR_OK, g_installSessionManager->CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result));

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "GetInfoByBundleNameTest001";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
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
    EXPECT_EQ(ERR_OK, g_installSessionManager->GetHapSignInfo("GetInfoByBundleNameTest001", bundleInfo2));

    EXPECT_EQ(bundleInfo.size(), hapList.hapPaths.size());
    EXPECT_EQ(bundleInfo.size(), bundleInfo2.size());

    int32_t sceneCode = 0;
    EXPECT_EQ(ERR_OK,
        atManagerService_->DeleteIdentityCore(tokenId, "GetInfoByBundleNameTest001", ReservedType::NONE, sceneCode));
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
    EXPECT_NE(ERR_OK, g_installSessionManager->GetHapSignInfo("", bundleInfo));
    EXPECT_NE(ERR_OK, g_installSessionManager->GetHapSignInfo("GetInfoByBundleNameFailTest001", bundleInfo));
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
    EXPECT_NE(ERR_OK, g_installSessionManager->GetHapSignInfo("GetInfoByBundleNameFailTest001", bundleInfo2));
    EXPECT_TRUE(bundleInfo2.empty());

    GenericValues delCondition2;
    delCondition2.Put(TokenFiledConst::FIELD_BUNDLE_NAME, "GetInfoByBundleNameFailTest001");
    std::vector<AddInfo> addInfoVec2;
    std::vector<DelInfo> delInfoVec2;
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, delCondition2, delInfoVec2);
    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec2, addInfoVec2);
    EXPECT_EQ(ERR_OK, ret);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
