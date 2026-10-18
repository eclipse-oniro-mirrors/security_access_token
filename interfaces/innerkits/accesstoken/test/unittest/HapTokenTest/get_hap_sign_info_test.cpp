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

#include "get_hap_sign_info_test.h"
#include "gtest/gtest.h"

#include "access_token_error.h"
#include "hap_token_info.h"
#include "nativetoken_kit.h"
#include "test_common.h"
#include "token_setproc.h"

#ifdef SPM_DATA_ENABLE
using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
// local aggregate of SignInfoQueryFlag: query every section in one call
constexpr uint32_t QUERY_ALL_SIGN_INFO = QUERY_PROFILE | QUERY_MODULE_INFO | QUERY_SHARED_FILES;
static uint64_t g_selfTokenId = 0;
static MockNativeToken* g_mock;
};

void GetHapSignInfoTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    // native process with MANAGER_HAP_ID
    g_mock = new (std::nothrow) MockNativeToken("foundation");
}

void GetHapSignInfoTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
}

void GetHapSignInfoTest::SetUp()
{
}

void GetHapSignInfoTest::TearDown()
{
}

/**
 * @tc.name: GetHapSignInfoTest001
 * @tc.desc: Test GetHapSignInfo, with invalid param, with not exist bundle.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapSignInfoTest, GetHapSignInfoTest001, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    std::string bundleName = "";
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::GetHapSignInfo(bundleName, QUERY_ALL_SIGN_INFO, bundleInfo));
    bundleName = "GetHapSignInfoTest001";
    EXPECT_EQ(AccessTokenError::ERR_BUNDLE_NOT_EXIST,
        AccessTokenKit::GetHapSignInfo(bundleName, QUERY_ALL_SIGN_INFO, bundleInfo));
}

/**
 * @tc.name: GetHapSignInfoTest002
 * @tc.desc: Test GetHapSignInfo, with result.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapSignInfoTest, GetHapSignInfoTest002, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    // Seed the query target through the four-phase install chain with a real
    // system hap: the install session binds to the bundle carried by the hap
    // signature and the hap_info_table row is persisted under that name, so
    // the query must target the signed bundle. Drop any leftover row first
    // so reruns stay stable.
    const std::string signedBundle = "com.ohos.bluetooth";
    AccessTokenKit::DeleteIdentity(0, signedBundle, ReservedType::NONE);

    BundleHapList hapList;
    hapList.hapPaths.emplace_back("/system/app/Bluetooth/Bluetooth.hap");
    hapList.isPreInstalled = false;
    hapList.userId = 100;

    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::CheckHapSignInfo(hapList, QUERY_ALL_SIGN_INFO,
        sessionId, bundleInfo, resultInfo));

    HapInfoCheckResult result;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result));

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "GetHapSignInfoTest002";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, identity));

    std::map<std::string, std::string> modulePathMap;
    modulePathMap[hapList.hapPaths[0]] = hapList.hapPaths[0];
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::FinishInstall(sessionId, true, modulePathMap));

    // the sign-info channel returns the persisted modules of the signed bundle
    std::vector<TrustedBundleInfo> bundleInfo2;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapSignInfo(signedBundle, QUERY_ALL_SIGN_INFO, bundleInfo2));
    EXPECT_FALSE(bundleInfo2.empty());

    // cleanup: the allocated token and the seeded row both live under the
    // signed bundle's namespace, one bundle-level delete drops them all
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteIdentity(0, signedBundle, ReservedType::NONE));
}

/**
 * @tc.name: GetHapSignInfoTest003
 * @tc.desc: Test GetHapSignInfo, with mode below CURRENT_MODE, with check failed.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapSignInfoTest, GetHapSignInfoTest003, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    std::string bundleName = "com.ohos.dlpmanager";
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::GetHapSignInfo(bundleName, QUERY_ALL_SIGN_INFO,
            static_cast<MultipleMode>(-2), bundleInfo));
}

/**
 * @tc.name: GetHapSignInfoTest004
 * @tc.desc: Test GetHapSignInfo, with mode above MAX_MODE, with check failed.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapSignInfoTest, GetHapSignInfoTest004, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    std::string bundleName = "com.ohos.dlpmanager";
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenKit::GetHapSignInfo(bundleName, QUERY_ALL_SIGN_INFO,
            static_cast<MultipleMode>(2), bundleInfo));
}

/**
 * @tc.name: GetHapSignInfoTest005
 * @tc.desc: Test GetHapSignInfo, with an explicit main mode, with not exist bundle.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetHapSignInfoTest, GetHapSignInfoTest005, TestSize.Level0)
{
    MockNativeToken mock("foundation");

    // a valid explicit mode passes the kit validation and reaches the service
    std::string bundleName = "GetHapSignInfoTest005";
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_EQ(AccessTokenError::ERR_BUNDLE_NOT_EXIST,
        AccessTokenKit::GetHapSignInfo(bundleName, QUERY_ALL_SIGN_INFO,
            MultipleMode::DEFAULT_OR_MAIN_MODE, bundleInfo));
    EXPECT_TRUE(bundleInfo.empty());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // SPM_DATA_ENABLE
