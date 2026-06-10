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

#include "install_session_manager_test.h"
#include "gtest/gtest.h"
#include <thread>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static uint64_t g_selfTokenId = 0;
static MockNativeToken* g_mock;
static constexpr size_t MAX_BUNDLE_LIST_SIZE = 128;
static constexpr size_t INVALID_SESSION = 999;
};

void InstallSessionManagerTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    // native process with MANAGER_HAP_ID
    g_mock = new (std::nothrow) MockNativeToken("foundation");
}

void InstallSessionManagerTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
}

void InstallSessionManagerTest::SetUp()
{
}

void InstallSessionManagerTest::TearDown()
{
}

/**
 * @tc.name: CheckHapSignInfoTest001
 * @tc.desc: Test CheckHapSignInfo, with invalid param.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, CheckHapSignInfoTest001, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    BundleHapList hapList;
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::CheckHapSignInfo(hapList, sessionId, bundleInfo, resultInfo));
    
    HapVerifyResultInfo resultInfo2;
    hapList.hapPaths = std::vector<std::string>(MAX_BUNDLE_LIST_SIZE + 1, "test");
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::CheckHapSignInfo(hapList, sessionId, bundleInfo, resultInfo2));
}
#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
/**
 * @tc.name: CheckHapSignInfoTest002
 * @tc.desc: Test CheckHapSignInfo, with not exist hap path.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, CheckHapSignInfoTest002, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    std::string path = "/data/not/exist/test.hap";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::CheckHapSignInfo(hapList, sessionId, bundleInfo, resultInfo));
}
#endif

/**
 * @tc.name: CheckHapPermissionInfoTest001
 * @tc.desc: Test CheckHapPermissionInfo, with invalid param.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, CheckHapPermissionInfoTest001, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = 0;
    InstallTypeEnum type = TYPE_INSTALL;
    HapInfoCheckResult result;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::CheckHapPermissionInfo(sessionId, type, result));
}
#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
/**
 * @tc.name: CheckHapPermissionInfoTest002
 * @tc.desc: Test CheckHapPermissionInfo, with not exist session.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, CheckHapPermissionInfoTest002, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = INVALID_SESSION;
    InstallTypeEnum type = TYPE_INSTALL;
    HapInfoCheckResult result;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::CheckHapPermissionInfo(sessionId, type, result));
}
#endif

/**
 * @tc.name: PrepareHapIdentityTest001
 * @tc.desc: Test PrepareHapIdentity, with invalid param.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, PrepareHapIdentityTest001, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = -1;

    HapBaseInfo baseInfo;
    baseInfo.userID = -1;
    baseInfo.bundleName = "";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, identity));

#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
    sessionId = INVALID_SESSION;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, identity));

    baseInfo.userID = 100;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, identity));
#endif
}
#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
/**
 * @tc.name: PrepareHapIdentityTest002
 * @tc.desc: Test PrepareHapIdentity, with not exist session.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, PrepareHapIdentityTest002, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = INVALID_SESSION;

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "PrepareHapIdentityTest002";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, identity));
}

/**
 * @tc.name: PrepareHapIdentityTest003
 * @tc.desc: Test PrepareHapIdentity, with exist HapBaseInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, PrepareHapIdentityTest003, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = 0;

    HapBaseInfo baseInfo;
    baseInfo.userID = 101;
    baseInfo.bundleName = "com.ohos.dlpmanager";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, identity));

    std::map<std::string, std::string> modulePathMap;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::FinishInstall(sessionId, false, modulePathMap));
}
#endif

/**
 * @tc.name: UpdateHapPolicyTest001
 * @tc.desc: Test UpdateHapPolicy, with invalid param.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, UpdateHapPolicyTest001, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = -1;
    int32_t tokenId = 123;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    EXPECT_NE(RET_SUCCESS, AccessTokenKit::UpdateHapPolicy(sessionId, tokenId, bundlePolicy));
}
#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
/**
 * @tc.name: UpdateHapPolicyTest002
 * @tc.desc: Test UpdateHapPolicy, with not exist session, with not exist tokenID.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, UpdateHapPolicyTest002, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = INVALID_SESSION;
    int32_t tokenId = 123;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    EXPECT_NE(RET_SUCCESS, AccessTokenKit::UpdateHapPolicy(sessionId, tokenId, bundlePolicy));

    sessionId = 0;
    HapBaseInfo baseInfo;
    baseInfo.userID = 101;
    baseInfo.bundleName = "com.ohos.dlpmanager";
    baseInfo.instIndex = 0;

    Identity identity;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, identity));

    EXPECT_NE(RET_SUCCESS, AccessTokenKit::UpdateHapPolicy(sessionId, tokenId, bundlePolicy));
}
#endif

/**
 * @tc.name: FinishInstallTest001
 * @tc.desc: Test FinishInstall, with invalid param.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, FinishInstallTest001, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = 0;
    std::map<std::string, std::string> modulePathMap;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::FinishInstall(sessionId, false, modulePathMap));
}
#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
/**
 * @tc.name: FinishInstallTest002
 * @tc.desc: Test FinishInstall success.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, FinishInstallTest002, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = 0;
    HapBaseInfo baseInfo;
    baseInfo.userID = 101;
    baseInfo.bundleName = "com.ohos.dlpmanager";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, identity));

    std::map<std::string, std::string> modulePathMap;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::FinishInstall(sessionId, true, modulePathMap));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteIdentity(
        static_cast<AccessTokenID>(identity.tokenId), "com.ohos.dlpmanager", ReservedType::NONE));
}
#endif

/**
 * @tc.name: GetCacheSignInfoBySessionIdTest001
 * @tc.desc: Test GetCacheSignInfoBySessionId, with invalid param.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, GetCacheSignInfoBySessionIdTest001, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::GetCacheSignInfoBySessionId(sessionId, bundleInfo));
#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
    sessionId = INVALID_SESSION;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::GetCacheSignInfoBySessionId(sessionId, bundleInfo));
#endif
}
#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
/**
 * @tc.name: GetCacheSignInfoBySessionIdTest002
 * @tc.desc: Test GetCacheSignInfoBySessionId, with empty result.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, GetCacheSignInfoBySessionIdTest002, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = 0;
    HapBaseInfo baseInfo;
    baseInfo.userID = 101;
    baseInfo.bundleName = "com.ohos.dlpmanager";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, identity));
    
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::GetCacheSignInfoBySessionId(sessionId, bundleInfo));
    EXPECT_TRUE(bundleInfo.empty());

    std::map<std::string, std::string> modulePathMap;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::FinishInstall(sessionId, false, modulePathMap));
}
#endif

/**
 * @tc.name: GetHapSignInfoTest001
 * @tc.desc: Test GetHapSignInfo, with invalid param, with not exist bundle.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, GetHapSignInfoTest001, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    std::string bundleName = "";
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::GetHapSignInfo(bundleName, bundleInfo));
#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
    bundleName = "GetHapSignInfoTest001";
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::GetHapSignInfo(bundleName, bundleInfo));
    #endif
}
#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
/**
 * @tc.name: GetHapSignInfoTest002
 * @tc.desc: Test GetHapSignInfo, with result.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, GetHapSignInfoTest002, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    std::string bundleName = "com.ohos.dlpmanager";
    std::vector<TrustedBundleInfo> bundleInfo;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapSignInfo(bundleName, bundleInfo));
    EXPECT_FALSE(bundleInfo.empty());
}

/**
 * @tc.name: GetCachePolicyBySessionIdTest001
 * @tc.desc: Test GetCachePolicyBySessionId, with invalid param.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, GetCachePolicyBySessionIdTest001, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = 0;
    std::string bundleName = "";

    BundlePolicyInfo bundlePolicyInfo;
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::GetCachePolicyBySessionId(sessionId, bundleName, bundlePolicyInfo));

    sessionId = INVALID_SESSION;
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::GetCachePolicyBySessionId(sessionId, bundleName, bundlePolicyInfo));

    bundleName = "GetCachePolicyBySessionIdTest001";
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::GetCachePolicyBySessionId(sessionId, bundleName, bundlePolicyInfo));
}
#else
/**
 * @tc.name: CheckHapSignInfoTest101
 * @tc.desc: Test CheckHapSignInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, CheckHapSignInfoTest101, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    std::string path = "/data/not/exist/test.hap";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    // parcel failed
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::CheckHapSignInfo(hapList, sessionId, bundleInfo, resultInfo));
}

/**
 * @tc.name: CheckHapPermissionInfoTest101
 * @tc.desc: Test CheckHapPermissionInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, CheckHapPermissionInfoTest101, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = INVALID_SESSION;
    InstallTypeEnum type = TYPE_INSTALL;
    HapInfoCheckResult result;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::CheckHapPermissionInfo(sessionId, type, result));
}

/**
 * @tc.name: PrepareHapIdentityTest101
 * @tc.desc: Test PrepareHapIdentity.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, PrepareHapIdentityTest101, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = INVALID_SESSION;

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "PrepareHapIdentityTest101";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, identity));
}

/**
 * @tc.name: UpdateHapPolicyTest101
 * @tc.desc: Test UpdateHapPolicy.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, UpdateHapPolicyTest101, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = INVALID_SESSION;
    int32_t tokenId = 123;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapPolicy(sessionId, tokenId, bundlePolicy));
}

/**
 * @tc.name: FinishInstallTest101
 * @tc.desc: Test FinishInstall.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, FinishInstallTest101, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = INVALID_SESSION;

    std::map<std::string, std::string> modulePathMap;
    modulePathMap["test"] = "test";
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::FinishInstall(sessionId, true, modulePathMap));
}

/**
 * @tc.name: GetCacheSignInfoBySessionIdTest101
 * @tc.desc: Test GetCacheSignInfoBySessionId.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, GetCacheSignInfoBySessionIdTest101, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    int32_t sessionId = INVALID_SESSION;

    std::vector<TrustedBundleInfo> bundleInfo;
    // parcel failed
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::GetCacheSignInfoBySessionId(sessionId, bundleInfo));
}

/**
 * @tc.name: GetHapSignInfoTest101
 * @tc.desc: Test GetHapSignInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(InstallSessionManagerTest, GetHapSignInfoTest101, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    std::string bundleName = "com.ohos.dlpmanager";
    std::vector<TrustedBundleInfo> bundleInfo;

    // parcel failed
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::GetHapSignInfo(bundleName, bundleInfo));
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
