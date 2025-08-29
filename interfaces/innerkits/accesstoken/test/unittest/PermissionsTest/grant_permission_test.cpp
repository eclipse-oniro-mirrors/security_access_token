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

#include "grant_permission_test.h"
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

void GrantPermissionTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
    reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
    reqPerm.emplace_back("ohos.permission.MANAGE_HAP_TOKENID");
    g_mock = new (std::nothrow) MockHapToken("GrantPermissionTest", reqPerm);

    // clean up test cases
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

void GrantPermissionTest::TearDownTestCase()
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

void GrantPermissionTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");

    setuid(0);
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "GrantPermissionTest",
        .apiVersion = DEFAULT_API_VERSION
    };
    PermissionStateFull permStatMicro = {
        .permissionName = "ohos.permission.MICROPHONE",
        .isGeneral = true,
        .resDeviceID = {"device3"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };
    PermissionStateFull permStatCam = {
        .permissionName = "ohos.permission.CAMERA",
        .isGeneral = true,
        .resDeviceID = {"device3"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "GrantPermissionTest",
        .permStateList = { permStatMicro, permStatCam },
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(tokenId, INVALID_TOKENID);
}

void GrantPermissionTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

/**
 * @tc.name: GrantPermissionFuncTest001
 * @tc.desc: Grant permission that has ohos.permission.GRANT_SENSITIVE_PERMISSIONS
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GrantPermissionTest, GrantPermissionFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantPermissionFuncTest001");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.CAMERA", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: GrantPermissionAbnormalTest001
 * @tc.desc: Grant permission that tokenID or permission is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GrantPermissionTest, GrantPermissionAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantPermissionAbnormalTest001");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.GAMMA", PERMISSION_USER_FIXED);
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, ret);

    ret = AccessTokenKit::GrantPermission(tokenID, "", PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::GrantPermission(tokenID, invalidPerm, PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = AccessTokenKit::GrantPermission(TEST_TOKENID_INVALID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));

    ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.BETA", PERMISSION_USER_FIXED);
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, ret);
}

/**
 * @tc.name: GrantPermissionAbnormalTest002
 * @tc.desc: GrantPermission function abnormal branch
 * @tc.type: FUNC
 * @tc.require:Issue I5RJBB
 */
HWTEST_F(GrantPermissionTest, GrantPermissionAbnormalTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantPermissionAbnormalTest002");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    int32_t invalidFlag = -1;
    int32_t ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.MICROPHONE", invalidFlag);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: GrantPermissionSpecsTest001
 * @tc.desc: GrantPermission is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GrantPermissionTest, GrantPermissionSpecsTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantPermissionSpecsTest001");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    uint32_t flag;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        int32_t ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
        ASSERT_EQ(RET_SUCCESS, ret);

        ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
        ASSERT_EQ(PERMISSION_GRANTED, ret);

        ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.MICROPHONE", flag);
        ASSERT_EQ(PERMISSION_USER_FIXED, flag);
        ASSERT_EQ(RET_SUCCESS, ret);
    }
    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: GrantPermissionSpecsTest002
 * @tc.desc: GrantPermission caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(GrantPermissionTest, GrantPermissionSpecsTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantPermissionSpecsTest002");
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
    MockHapToken mock("GrantPermissionSpecsTest002", reqPerm, false);

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: GrantPermissionSpecsTest003
 * @tc.desc: GrantPermission caller is system app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(GrantPermissionTest, GrantPermissionSpecsTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantPermissionSpecsTest003");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    int ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: GrantPermissionSpecsTest004
 * @tc.desc: success to revoke permission when granting permission twice by secure component.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(GrantPermissionTest, GrantPermissionSpecsTest004, TestSize.Level0)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
    reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
    MockHapToken mock("GrantPermissionSpecsTest004", reqPerm, true);

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    int ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.SECURE_PASTE", PERMISSION_COMPONENT_SET);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.SECURE_PASTE", PERMISSION_COMPONENT_SET);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SECURE_PASTE", false);
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenKit::RevokePermission(tokenID, "ohos.permission.SECURE_PASTE", PERMISSION_COMPONENT_SET);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.SECURE_PASTE", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: GrantPermissionWithRenderTest001
 * @tc.desc: Grant permission with render tokenID
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(GrantPermissionTest, GrantPermissionWithRenderTest001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    // get render token
    uint64_t renderToken = AccessTokenKit::GetRenderTokenID(tokenID);
    ASSERT_NE(renderToken, INVALID_TOKENID);
    ASSERT_NE(renderToken, tokenID);

    int ret = AccessTokenKit::GrantPermission(renderToken, "ohos.permission.SECURE_PASTE", PERMISSION_COMPONENT_SET);
    EXPECT_EQ(ERR_TOKENID_NOT_EXIST, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: GrantPermissionWithManualTest001
 * @tc.desc: GrantPermission with MANUAL_SETTINGS permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GrantPermissionTest, GrantPermissionWithManualTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantPermissionWithManualTest001");
    MockNativeToken mock("foundation");

    HapInfoParams infoParams;
    HapPolicyParams policyParams;
    TestCommon::GetHapParams(infoParams, policyParams);
    policyParams.apl = APL_NORMAL;
    TestCommon::TestPrepareManualPermissionStatus(policyParams);
    AccessTokenIDEx fullTokenId;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(infoParams, policyParams, fullTokenId));
    AccessTokenID tokenID = fullTokenId.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MANUAL_ATM_SELF_USE"));
    // old grant function can't grant MANUAL_SETTINGS
    EXPECT_EQ(ERR_PERMISSION_NOT_EXIST, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.MANUAL_ATM_SELF_USE", PERMISSION_USER_FIXED, USER_GRANTED_PERM));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MANUAL_ATM_SELF_USE"));

    // new grant function can grant MANUAL_SETTINGS
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.MANUAL_ATM_SELF_USE", PERMISSION_USER_FIXED, OPERABLE_PERM));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MANUAL_ATM_SELF_USE"));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS