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

#include "revoke_permission_test.h"
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
static const int INVALID_PERMNAME_LEN = 260;
static const unsigned int TEST_TOKENID_INVALID = 0;
static const int CYCLE_TIMES = 100;
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static MockHapToken* g_mock = nullptr;
};

void RevokePermissionTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
    g_mock = new (std::nothrow) MockHapToken("RevokePermissionTest", reqPerm);

    // clean up test cases
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

void RevokePermissionTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
    TestCommon::ResetTestEvironment();
}

void RevokePermissionTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");

    setuid(0);
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "RevokePermissionTest",
        .apiVersion = DEFAULT_API_VERSION
    };

    PermissionStateFull permStatMicro = {
        .permissionName = "ohos.permission.MICROPHONE",
        .isGeneral = true,
        .resDeviceID = {"device3"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };
    PermissionStateFull permStatCamera = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"device3"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "RevokePermissionTest",
        .permStateList = { permStatMicro, permStatCamera },
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(tokenId, INVALID_TOKENID);
}

void RevokePermissionTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

/**
 * @tc.name: RevokePermissionFuncTest001
 * @tc.desc: Revoke permission that has ohos.permission.REVOKE_SENSITIVE_PERMISSIONS
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RevokePermissionTest, RevokePermissionFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionFuncTest001");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.CAMERA", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RevokePermissionAbnormalTest001
 * @tc.desc: Revoke permission that tokenID is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RevokePermissionTest, RevokePermissionAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionAbnormalTest001");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.GAMMA", PERMISSION_USER_FIXED);
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RevokePermissionAbnormalTest002
 * @tc.desc: Revoke permission that permission is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RevokePermissionTest, RevokePermissionAbnormalTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionAbnormalTest002");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int ret = AccessTokenKit::RevokePermission(tokenID, "", PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::RevokePermission(tokenID, invalidPerm, PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = AccessTokenKit::RevokePermission(TEST_TOKENID_INVALID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));

    ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.BETA", PERMISSION_USER_FIXED);
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, ret);
}

/**
 * @tc.name: RevokePermissionAbnormalTest003
 * @tc.desc: Revoke permission that flag is invalid.
 * @tc.type: FUNC
 * @tc.require:Issue I5RJBB
 */
HWTEST_F(RevokePermissionTest, RevokePermissionAbnormalTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionAbnormalTest003");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int invalidFlag = -1;
    int32_t ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.MICROPHONE", invalidFlag);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RevokePermissionSpecsTest001
 * @tc.desc: RevokePermission is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RevokePermissionTest, RevokePermissionSpecsTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionSpecsTest001");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    uint32_t flag;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        int32_t ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
        ASSERT_EQ(RET_SUCCESS, ret);

        ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
        ASSERT_EQ(PERMISSION_DENIED, ret);

        ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.MICROPHONE", flag);
        ASSERT_EQ(PERMISSION_USER_FIXED, flag);
        ASSERT_EQ(RET_SUCCESS, ret);
    }
    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RevokePermissionSpecsTest002
 * @tc.desc: Revoke permission caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(RevokePermissionTest, RevokePermissionSpecsTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionSpecsTest002");
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
    MockHapToken mock("RevokePermissionSpecsTest002", reqPerm, false);

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RevokePermissionSpecsTest003
 * @tc.desc: Revoke permission caller is system app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(RevokePermissionTest, RevokePermissionSpecsTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionSpecsTest003");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.CAMERA", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS