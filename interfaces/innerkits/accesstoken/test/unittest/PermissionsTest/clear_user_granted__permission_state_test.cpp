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
#include "accesstoken_log.h"
#include "accesstoken_service_ipc_interface_code.h"
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
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    SECURITY_DOMAIN_ACCESSTOKEN, "ClearUserGrantedPermissionStateTest"};
static AccessTokenID g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const unsigned int TEST_TOKENID_INVALID = 0;
static const int CYCLE_TIMES = 100;
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
HapInfoParams g_infoManagerTestInfoParms = TestCommon::GetInfoManagerTestInfoParms();
HapInfoParams g_infoManagerTestInfoParmsBak = g_infoManagerTestInfoParms;
};

void ClearUserGrantedPermissionStateTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();

    // clean up test cases
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                            g_infoManagerTestInfoParms.bundleName,
                                            g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, TestCommon::GetTestPolicyParams());
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void ClearUserGrantedPermissionStateTest::TearDownTestCase()
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName,
        g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
}

void ClearUserGrantedPermissionStateTest::SetUp()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetUp ok.");

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
    TestCommon::TestPreparePermDefList(policy);
    TestCommon::TestPreparePermStateList(policy);

    AccessTokenKit::AllocHapToken(info, policy);
}

void ClearUserGrantedPermissionStateTest::TearDown()
{
}

unsigned int ClearUserGrantedPermissionStateTest::GetAccessTokenID(int userID, std::string bundleName, int instIndex)
{
    return AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);
}

/**
 * @tc.name: ClearUserGrantedPermissionStateFuncTest001
 * @tc.desc: Clear user/system granted permission after ClearUserGrantedPermissionState has been invoked.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ClearUserGrantedPermissionStateTest, ClearUserGrantedPermissionStateFuncTest001, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = AccessTokenKit::ClearUserGrantedPermissionState(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SET_WIFI_INFO", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: ClearUserGrantedPermissionStateFuncTest002
 * @tc.desc: Clear user/system granted permission after ClearUserGrantedPermissionState has been invoked.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ClearUserGrantedPermissionStateTest, ClearUserGrantedPermissionStateFuncTest002, TestSize.Level0)
{
    PermissionDef g_infoManagerTestPermDef1 = {
        .permissionName = "ohos.permission.test1",
        .bundleName = "accesstoken_test",
        .grantMode = 1,
        .availableLevel = APL_NORMAL,
        .label = "label3",
        .labelId = 1,
        .description = "open the door",
        .descriptionId = 1,
        .availableType = MDM
    };
    AccessTokenIDEx tokenIdEx = {0};
    OHOS::Security::AccessToken::PermissionStateFull infoManagerTestState1 = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {OHOS::Security::AccessToken::PermissionState::PERMISSION_DENIED},
        .grantFlags = {PERMISSION_GRANTED_BY_POLICY | PERMISSION_DEFAULT_FLAG}
    };
    OHOS::Security::AccessToken::PermissionStateFull infoManagerTestState2 = {
        .permissionName = "ohos.permission.SEND_MESSAGES",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {OHOS::Security::AccessToken::PermissionState::PERMISSION_DENIED},
        .grantFlags = {PERMISSION_GRANTED_BY_POLICY | PERMISSION_USER_FIXED}
    };
    OHOS::Security::AccessToken::PermissionStateFull infoManagerTestState3 = {
        .permissionName = "ohos.permission.RECEIVE_SMS",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {OHOS::Security::AccessToken::PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PERMISSION_USER_FIXED}
    };
    OHOS::Security::AccessToken::HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = OHOS::Security::AccessToken::ATokenAplEnum::APL_NORMAL,
        .domain = "test.domain",
        .permList = {g_infoManagerTestPermDef1},
        .permStateList = {infoManagerTestState1, infoManagerTestState2, infoManagerTestState3}
    };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, infoManagerTestPolicyPrams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::ClearUserGrantedPermissionState(tokenID));

    ASSERT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false));

    ASSERT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SEND_MESSAGES", false));

    ASSERT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.RECEIVE_SMS", false));

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: ClearUserGrantedPermissionStateAbnormalTest001
 * @tc.desc: Clear user/system granted permission that tokenID or permission is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ClearUserGrantedPermissionStateTest, ClearUserGrantedPermissionStateAbnormalTest001, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int ret = AccessTokenKit::ClearUserGrantedPermissionState(TEST_TOKENID_INVALID);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::ClearUserGrantedPermissionState(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: ClearUserGrantedPermissionStateSpecTets001
 * @tc.desc: ClearUserGrantedPermissionState is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(ClearUserGrantedPermissionStateTest, ClearUserGrantedPermissionStateSpecTets001, TestSize.Level0)
{
    AccessTokenID tokenID = GetAccessTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    for (int i = 0; i < CYCLE_TIMES; i++) {
        int32_t ret = AccessTokenKit::ClearUserGrantedPermissionState(tokenID);
        ASSERT_EQ(RET_SUCCESS, ret);

        ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
        ASSERT_EQ(PERMISSION_DENIED, ret);
    }
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS