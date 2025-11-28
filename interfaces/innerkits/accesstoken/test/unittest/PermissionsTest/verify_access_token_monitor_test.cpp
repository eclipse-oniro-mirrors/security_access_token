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

#include "verify_access_token_monitor_test.h"
#include "gtest/gtest.h"
#include <thread>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "iaccess_token_manager.h"
#include "permission_grant_info.h"
#include "permission_state_change_info_parcel.h"
#include "string_ex.h"
#include "test_common.h"
#include "tokenid_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static uint64_t g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int32_t TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
constexpr const int32_t VERIFY_THRESHOLD = 50;
};

void VerifyAccessTokenMonitorTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    // clean up test cases
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

void VerifyAccessTokenMonitorTest::TearDownTestCase()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
    TestCommon::ResetTestEvironment();
}

void VerifyAccessTokenMonitorTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");

    setuid(0);
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "VerifyAccessTokenMonitorTest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false
    };

    PermissionStateFull permStatMicro = {
        .permissionName = "ohos.permission.MICROPHONE",
        .isGeneral = true,
        .resDeviceID = {"device3"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };
    PermissionStateFull permStatLocation = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
        .isGeneral = true,
        .resDeviceID = {"device3"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "VerifyAccessTokenMonitorTest",
        .permStateList = { permStatMicro, permStatLocation },
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    ASSERT_NE(tokenIdEx.tokenIdExStruct.tokenID, INVALID_TOKENID);
}

void VerifyAccessTokenMonitorTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
}

/**
 * @tc.name: VerifyAccessTokenMonitorTestFunc001
 * @tc.desc: Verify user granted permission.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(VerifyAccessTokenMonitorTest, VerifyAccessTokenMonitorTestFunc001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "VerifyAccessTokenFuncTest001");
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);

    int64_t shellTokenId = GetSelfTokenID();
    SetSelfTokenID(tokenIdEx.tokenIDEx);
    int32_t ret = AccessTokenKit::VerifyAccessToken(
        static_cast<AccessTokenID>(shellTokenId), "ohos.permission.DUMP", true);
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    for (int32_t i = 1; i < VERIFY_THRESHOLD + 1; ++i) {
        EXPECT_EQ(AccessTokenKit::VerifyAccessToken(i, "ohos.permission.MICROPHONE", true), PERMISSION_DENIED);
    }

    ret = AccessTokenKit::VerifyAccessToken(static_cast<AccessTokenID>(shellTokenId), "ohos.permission.DUMP", true);
    EXPECT_EQ(PERMISSION_DENIED, ret);
    SetSelfTokenID(shellTokenId);
}

/**
 * @tc.name: VerifyAccessTokenMonitorTestFunc001
 * @tc.desc: Verify user granted permission.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(VerifyAccessTokenMonitorTest, VerifyAccessTokenMonitorTestFunc002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "VerifyAccessTokenFuncTest001");
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);

    int64_t shellTokenId = GetSelfTokenID();
    SetSelfTokenID(tokenIdEx.tokenIDEx);
    int32_t ret = AccessTokenKit::VerifyAccessToken(static_cast<AccessTokenID>(shellTokenId), "ohos.permission.DUMP");
    EXPECT_EQ(PERMISSION_GRANTED, ret);

    for (int32_t i = 1; i < VERIFY_THRESHOLD + 1; ++i) {
        EXPECT_EQ(AccessTokenKit::VerifyAccessToken(i, "ohos.permission.MICROPHONE"), PERMISSION_DENIED);
    }

    ret = AccessTokenKit::VerifyAccessToken(static_cast<AccessTokenID>(shellTokenId), "ohos.permission.DUMP");
    EXPECT_EQ(PERMISSION_DENIED, ret);
    SetSelfTokenID(shellTokenId);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS