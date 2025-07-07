/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "clear_user_granted__permission_state_test.h"
#include "gtest/gtest.h"
#include <thread>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "iaccess_token_manager.h"
#include "test_common.h"
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
static const unsigned int TEST_TOKENID_INVALID = 0;
static const int CYCLE_TIMES = 100;
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
HapInfoParams g_infoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "test3",
    .apiVersion = 8,
    .appDistributionType = "enterprise_mdm"
};
static MockHapToken* g_mock = nullptr;
};

void ClearUserGrantedPermissionStateTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
    g_mock = new (std::nothrow) MockHapToken("ClearUserGrantedPermissionStateTest", reqPerm);
}

void ClearUserGrantedPermissionStateTest::TearDownTestCase()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);

    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
}

void ClearUserGrantedPermissionStateTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");

    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
        .apiVersion = DEFAULT_API_VERSION
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    TestCommon::TestPreparePermStateList(policy);
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(info, policy);
    EXPECT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
}

void ClearUserGrantedPermissionStateTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

/**
 * @tc.name: ClearUserGrantedPermissionStateFuncTest001
 * @tc.desc: Clear user/system granted permission after ClearUserGrantedPermissionState has been invoked.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ClearUserGrantedPermissionStateTest, ClearUserGrantedPermissionStateFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ClearUserGrantedPermissionStateFuncTest001");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserGrantedPermissionState(tokenID));

    ASSERT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false));

    ASSERT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SET_WIFI_INFO", false));

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: ClearUserGrantedPermissionStateFuncTest002
 * @tc.desc: Clear user/system granted permission after ClearUserGrantedPermissionState has been invoked.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ClearUserGrantedPermissionStateTest, ClearUserGrantedPermissionStateFuncTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ClearUserGrantedPermissionStateFuncTest002");
    OHOS::Security::AccessToken::PermissionStateFull infoManagerTestState1 = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {OHOS::Security::AccessToken::PermissionState::PERMISSION_DENIED},
        .grantFlags = {PERMISSION_PRE_AUTHORIZED_CANCELABLE | PERMISSION_DEFAULT_FLAG}
    };
    OHOS::Security::AccessToken::PermissionStateFull infoManagerTestState2 = {
        .permissionName = "ohos.permission.SEND_MESSAGES",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {OHOS::Security::AccessToken::PermissionState::PERMISSION_DENIED},
        .grantFlags = {PERMISSION_PRE_AUTHORIZED_CANCELABLE | PERMISSION_USER_FIXED}
    };
    OHOS::Security::AccessToken::PermissionStateFull infoManagerTestState3 = {
        .permissionName = "ohos.permission.RECEIVE_SMS",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {OHOS::Security::AccessToken::PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PERMISSION_USER_FIXED}
    };
    OHOS::Security::AccessToken::HapPolicyParams policyPrams = {
        .apl = OHOS::Security::AccessToken::ATokenAplEnum::APL_NORMAL,
        .domain = "test.domain",
        .permStateList = {infoManagerTestState1, infoManagerTestState2, infoManagerTestState3}
    };
    AccessTokenIDEx tokenIdEx = TestCommon::AllocAndGrantHapTokenByTest(g_infoParms, policyPrams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserGrantedPermissionState(tokenID));

    // PERMISSION_SYSTEM_FIXED, not clear permission
    ASSERT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false));

    ASSERT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SEND_MESSAGES", false));

    ASSERT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RECEIVE_SMS", false));

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: ClearUserGrantedPermissionStateAbnormalTest001
 * @tc.desc: Clear user/system granted permission that tokenID or permission is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ClearUserGrantedPermissionStateTest, ClearUserGrantedPermissionStateAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ClearUserGrantedPermissionStateAbnormalTest001");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    ASSERT_EQ(
        AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::ClearUserGrantedPermissionState(TEST_TOKENID_INVALID));

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserGrantedPermissionState(tokenID));
}

/**
 * @tc.name: ClearUserGrantedPermissionStateSpecTets001
 * @tc.desc: ClearUserGrantedPermissionState is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ClearUserGrantedPermissionStateTest, ClearUserGrantedPermissionStateSpecTets001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ClearUserGrantedPermissionStateSpecTets001");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    for (int i = 0; i < CYCLE_TIMES; i++) {
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserGrantedPermissionState(tokenID));
        ASSERT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false));
    }
    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS