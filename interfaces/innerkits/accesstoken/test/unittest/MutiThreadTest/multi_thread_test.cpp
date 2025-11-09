/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "multi_thread_test.h"

#include <gtest/hwext/gtest-multithread.h>

#include "access_token.h"
#include "access_token_error.h"
#include "test_common.h"

using namespace testing::ext;
using namespace testing::mt;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t MAX_HAP_NUM = 100;
constexpr int32_t MULTIPLE_COUNT = 10;
static MockHapToken* g_mock = nullptr;
static AccessTokenID g_selfTokenId = 0;
std::vector<std::string> g_permList = {
    "ohos.permission.CAMERA",
    "ohos.permission.MICROPHONE",
    "ohos.permission.APPROXIMATELY_LOCATION",
    "ohos.permission.READ_IMAGEVIDEO",
    "ohos.permission.WRITE_IMAGEVIDEO",
    "ohos.permission.READ_WHOLE_CALENDAR",
    "ohos.permission.WRITE_WHOLE_CALENDAR",
    "ohos.permission.READ_DOCUMENT",
    "ohos.permission.WRITE_DOCUMENT",
    "ohos.permission.ACCESS_BLUETOOTH"
};

HapInfoParams g_testHapInfoParams = {
    .userID = 100, // 100: uerId
    .bundleName = "AccessTokenMultiThreadTest",
    .instIndex = 0,
    .appIDDesc = "AccessTokenMultiThreadTest",
    .apiVersion = 11, // api version is 11
    .isSystemApp = true
};

HapPolicyParams g_testPolicyParams = {
    .apl = APL_NORMAL,
    .domain = "AccessTokenMultiThreadTest",
};
}

void AccessTokenMultiThreadTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
    reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
    g_mock = new (std::nothrow) MockHapToken("AccessTokenMultiThreadMockTest", reqPerm, true);
}

void AccessTokenMultiThreadTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    SetSelfTokenID(g_selfTokenId);
    TestCommon::ResetTestEvironment();
}

void AccessTokenMultiThreadTest::SetUp()
{
}

void AccessTokenMultiThreadTest::TearDown()
{
}

/**
 * @tc.name: HapTokenMultiThreadTest001
 * @tc.desc: test InitHapToken, UpdateHapToken, DeleteToken
 * @tc.type: FUNC
 * @tc.require:
 */
HWMTEST_F(AccessTokenMultiThreadTest, HapTokenMultiThreadTest001, TestSize.Level1, MULTIPLE_COUNT)
{
    GTEST_LOG_(INFO) << "tid: " << gettid();
    HapPolicyParams policyPrams = g_testPolicyParams;
    HapInfoParams infoParms = g_testHapInfoParams;
    infoParms.bundleName = "HapTokenMultiThreadTest001_" + std::to_string(gettid());
    std::vector<AccessTokenIDEx> tokenIdList;
    MockNativeToken mock("foundation");
    for (const auto& permission : g_permList) {
        static PermissionStateFull permState = {
            .permissionName = permission,
            .isGeneral = true,
            .resDeviceID = {"local"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {1}
        };
        policyPrams.permStateList.emplace_back(permState);
    }
    for (int32_t i = 0; i < MAX_HAP_NUM; i++) {
        AccessTokenIDEx tokenIdEx;
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParms, policyPrams, tokenIdEx));
        EXPECT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
        tokenIdList.emplace_back(tokenIdEx);
        infoParms.userID++;
    }

    // update hap token
    for (auto tokenIdEx : tokenIdList) {
        UpdateHapInfoParams info = {
            .appIDDesc = infoParms.appIDDesc,
            .apiVersion = 18, // 18: api version
            .isSystemApp = false
        };
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdateHapToken(tokenIdEx, info, policyPrams));
    }

    // delete token
    for (auto tokenIdEx : tokenIdList) {
        EXPECT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID));
    }
}
}  // namespace SecurityComponent
}  // namespace Security
}  // namespace OHOS