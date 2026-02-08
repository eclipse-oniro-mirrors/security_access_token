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

#include "revoke_permission_kill_test.h"
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
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static MockHapToken* g_mock = nullptr;
} // namespace

void RevokePermissionKillTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
    reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
    reqPerm.emplace_back("ohos.permission.MANAGE_HAP_TOKENID");
    g_mock = new (std::nothrow) MockHapToken("RevokePermissionKillMockTest", reqPerm);

    // clean up test cases
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

void RevokePermissionKillTest::TearDownTestCase()
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

void RevokePermissionKillTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");

    setuid(0);
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "RevokePermissionKillTest",
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
        .domain = "RevokePermissionKillTest",
        .permStateList = { permStatMicro, permStatCamera },
    };

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(tokenId, INVALID_TOKENID);
}

void RevokePermissionKillTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

/**
 * @tc.name: RevokePermissionWithKillTest001
 * @tc.desc: Revoke permission without killing process (killProcess=false)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RevokePermissionKillTest, RevokePermissionWithKillTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionWithKillTest001");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // Grant permission first
    int ret = AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(
        tokenID, "ohos.permission.MICROPHONE", false));

    // Revoke with killProcess=false
    ret = AccessTokenKit::RevokePermission(
        tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED, OPERABLE_PERM, false);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Verify permission is revoked
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RevokePermissionWithKillTest002
 * @tc.desc: Revoke permission with killing process (killProcess=true)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RevokePermissionKillTest, RevokePermissionWithKillTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionWithKillTest002");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // Grant permission first
    int ret = AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Revoke with killProcess=true
    ret = AccessTokenKit::RevokePermission(
        tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED, OPERABLE_PERM, true);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Verify permission is revoked
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RevokePermissionWithKillTest003
 * @tc.desc: Revoke permission with default parameter (backward compatibility)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RevokePermissionKillTest, RevokePermissionWithKillTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionWithKillTest003");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // Grant permission first
    int ret = AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Revoke with default parameter (should behave like killProcess=true)
    ret = AccessTokenKit::RevokePermission(
        tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Verify permission is revoked
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RevokePermissionWithKillTest004
 * @tc.desc: Revoke permission with PERMISSION_COMPONENT_SET flag
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RevokePermissionKillTest, RevokePermissionWithKillTest004, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionWithKillTest004");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // Grant permission first
    int ret = AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.CAMERA", PERMISSION_COMPONENT_SET);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Revoke with killProcess=false and PERMISSION_COMPONENT_SET flag
    // Process should NOT be killed due to PERMISSION_COMPONENT_SET flag
    ret = AccessTokenKit::RevokePermission(
        tokenID, "ohos.permission.CAMERA", PERMISSION_COMPONENT_SET, OPERABLE_PERM, false);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Verify permission is revoked
    ret = AccessTokenKit::VerifyAccessToken(tokenID, "ohos.permission.CAMERA", false);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RevokePermissionWithKillTest005
 * @tc.desc: Revoke permission with invalid tokenID (abnormal test)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RevokePermissionKillTest, RevokePermissionWithKillTest005, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionWithKillTest005");

    AccessTokenID invalidTokenID = INVALID_TOKENID;

    // Try to revoke with invalid tokenID and killProcess=false
    int ret = AccessTokenKit::RevokePermission(
        invalidTokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED, OPERABLE_PERM, false);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    // Try to revoke with invalid tokenID and killProcess=true
    ret = AccessTokenKit::RevokePermission(
        invalidTokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED, OPERABLE_PERM, true);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: RevokePermissionWithKillTest006
 * @tc.desc: Revoke permission with invalid permission name (abnormal test)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RevokePermissionKillTest, RevokePermissionWithKillTest006, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionWithKillTest006");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // Try to revoke with invalid permission name and killProcess=false
    int ret = AccessTokenKit::RevokePermission(
        tokenID, "", PERMISSION_USER_FIXED, OPERABLE_PERM, false);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    // Try to revoke with non-existent permission and killProcess=true
    ret = AccessTokenKit::RevokePermission(
        tokenID, "ohos.permission.INVALID", PERMISSION_USER_FIXED, OPERABLE_PERM, true);
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RevokePermissionWithKillTest007
 * @tc.desc: Revoke permission multiple times with different killProcess values
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RevokePermissionKillTest, RevokePermissionWithKillTest007, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionWithKillTest007");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // Grant permission first
    int ret = AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    // 3: Revoke multiple times with different killProcess values
    for (int32_t i = 0; i < 3; i++) {
        // Grant
        ret = AccessTokenKit::GrantPermission(
            tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
        ASSERT_EQ(RET_SUCCESS, ret);

        // Revoke with killProcess=false
        ret = AccessTokenKit::RevokePermission(
            tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED, OPERABLE_PERM, false);
        ASSERT_EQ(RET_SUCCESS, ret);

        // Grant again
        ret = AccessTokenKit::GrantPermission(
            tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
        ASSERT_EQ(RET_SUCCESS, ret);

        // Revoke with killProcess=true
        ret = AccessTokenKit::RevokePermission(
            tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED, OPERABLE_PERM, true);
        ASSERT_EQ(RET_SUCCESS, ret);
    }

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RevokePermissionWithKillTest008
 * @tc.desc: Revoke permission for normal app (non-system app)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RevokePermissionKillTest, RevokePermissionWithKillTest008, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionWithKillTest008");

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
    MockHapToken mock("RevokePermissionWithKillTest008", reqPerm, false);

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // Try to revoke with normal app and killProcess=false
    int ret = AccessTokenKit::RevokePermission(
        tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED, OPERABLE_PERM, false);
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RevokePermissionWithKillTest009
 * @tc.desc: Revoke permission with render tokenID
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RevokePermissionKillTest, RevokePermissionWithKillTest009, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionWithKillTest009");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // Get render token
    uint64_t renderToken = AccessTokenKit::GetRenderTokenID(tokenID);
    ASSERT_NE(renderToken, INVALID_TOKENID);
    ASSERT_NE(renderToken, tokenID);

    // Try to revoke with render token and killProcess=false
    int ret = AccessTokenKit::RevokePermission(
        renderToken, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED, OPERABLE_PERM, false);
    EXPECT_EQ(ERR_TOKENID_NOT_EXIST, ret);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: RevokePermissionWithKillTest010
 * @tc.desc: Revoke permission with USER_GRANTED_PERM and OPERABLE_PERM
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(RevokePermissionKillTest, RevokePermissionWithKillTest010, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokePermissionWithKillTest010");

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

    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.MANUAL_ATM_SELF_USE", PERMISSION_USER_FIXED, OPERABLE_PERM));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(
        tokenID, "ohos.permission.MANUAL_ATM_SELF_USE"));

    // Revoke with OPERABLE_PERM and killProcess=false
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RevokePermission(
        tokenID, "ohos.permission.MANUAL_ATM_SELF_USE", PERMISSION_USER_FIXED, OPERABLE_PERM, false));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(
        tokenID, "ohos.permission.MANUAL_ATM_SELF_USE"));

    // Grant again
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(
        tokenID, "ohos.permission.MANUAL_ATM_SELF_USE", PERMISSION_USER_FIXED, OPERABLE_PERM));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(
        tokenID, "ohos.permission.MANUAL_ATM_SELF_USE"));

    // Revoke with OPERABLE_PERM and killProcess=true
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RevokePermission(
        tokenID, "ohos.permission.MANUAL_ATM_SELF_USE", PERMISSION_USER_FIXED, OPERABLE_PERM, true));
    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(
        tokenID, "ohos.permission.MANUAL_ATM_SELF_USE"));

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
