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

#include "permission_request_toggle_status_test.h"
#include "gtest/gtest.h"
#include <thread>
#include <unistd.h>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
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
static AccessTokenID g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
HapInfoParams g_infoManagerTestNormalInfoParms = TestCommon::GetInfoManagerTestNormalInfoParms();
HapInfoParams g_infoManagerTestSystemInfoParms = TestCommon::GetInfoManagerTestSystemInfoParms();
HapPolicyParams g_infoManagerTestPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();
};

void PermissionRequestToggleStatusTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();

    // clean up test cases
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestNormalInfoParms.userID,
                                            g_infoManagerTestNormalInfoParms.bundleName,
                                            g_infoManagerTestNormalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestSystemInfoParms.userID,
                                            g_infoManagerTestSystemInfoParms.bundleName,
                                            g_infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms,
                                                              TestCommon::GetTestPolicyParams());
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void PermissionRequestToggleStatusTest::TearDownTestCase()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestNormalInfoParms.userID,
                                            g_infoManagerTestNormalInfoParms.bundleName,
                                            g_infoManagerTestNormalInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestSystemInfoParms.userID,
                                            g_infoManagerTestSystemInfoParms.bundleName,
                                            g_infoManagerTestSystemInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
}

void PermissionRequestToggleStatusTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");

    setuid(0);
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

void PermissionRequestToggleStatusTest::TearDown()
{
}

/**
 * @tc.name: SetPermissionRequestToggleStatusAbnormalTest001
 * @tc.desc: Set permission request toggle status that userId, permission or status is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionRequestToggleStatusTest, SetPermissionRequestToggleStatusAbnormalTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionRequestToggleStatusAbnormalTest001");

    int32_t userID = 100;
    uint32_t status = PermissionRequestToggleStatus::CLOSED;

    // Permission name is invalid.
    int32_t ret = AccessTokenKit::SetPermissionRequestToggleStatus("", status, userID);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    // Status is invalid.
    status = 2;
    ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status, userID);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    // UserID is invalid.
    userID = -1;
    status = PermissionRequestToggleStatus::CLOSED;
    ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status, userID);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: SetPermissionRequestToggleStatus001
 * @tc.desc: SetPermissionRequestToggleStatus caller is a normal app, not a system app.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionRequestToggleStatusTest, SetPermissionRequestToggleStatus001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionRequestToggleStatus001");

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestNormalInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    int32_t ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestNormalInfoParms.userID);
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, ret);
}

/**
 * @tc.name: SetPermissionRequestToggleStatus002
 * @tc.desc: SetPermissionRequestToggleStatus caller is a system app without related permissions.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionRequestToggleStatusTest, SetPermissionRequestToggleStatus002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionRequestToggleStatus002");

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    int32_t selfUid = getuid();
    setuid(10001); // 10001： UID

    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    int32_t ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestSystemInfoParms.userID);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, ret);

    status = PermissionRequestToggleStatus::OPEN;
    ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestSystemInfoParms.userID);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, ret);

    // restore environment
    setuid(selfUid);
}

/**
 * @tc.name: SetPermissionRequestToggleStatusSpecTest003
 * @tc.desc: SetPermissionRequestToggleStatus caller is a system app with related permissions.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionRequestToggleStatusTest, SetPermissionRequestToggleStatusSpecTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionRequestToggleStatusSpecTest003");

    AccessTokenIDEx tokenIdEx = {0};

    PermissionDef infoManagerTestPermDef = {
        .permissionName = "ohos.permission.DISABLE_PERMISSION_DIALOG_TEST",
        .bundleName = "accesstoken_test",
        .grantMode = 1,
        .availableLevel = APL_NORMAL,
        .label = "label3",
        .labelId = 1,
        .description = "open the door",
        .descriptionId = 1,
        .availableType = MDM
    };

    PermissionStateFull infoManagerTestState = {
        .permissionName = "ohos.permission.DISABLE_PERMISSION_DIALOG",
        .isGeneral = true,
        .resDeviceID = {"local3"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {1}
    };

    HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain3",
        .permList = {infoManagerTestPermDef},
        .permStateList = {infoManagerTestState}
    };

    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms, infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    int32_t selfUid = getuid();
    setuid(10001); // 10001： UID

    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    int32_t ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestSystemInfoParms.userID);
    ASSERT_EQ(RET_SUCCESS, ret);

    status = PermissionRequestToggleStatus::OPEN;
    ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestSystemInfoParms.userID);
    ASSERT_EQ(RET_SUCCESS, ret);

    // restore environment
    setuid(selfUid);
}

/**
 * @tc.name: GetPermissionRequestToggleStatusAbnormalTest001
 * @tc.desc: Get permission request toggle status that userId, permission is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionRequestToggleStatusTest, GetPermissionRequestToggleStatusAbnormalTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionRequestToggleStatusAbnormalTest001");

    int32_t userID = 100;
    uint32_t status;

    // Permission name is invalid.
    int32_t ret = AccessTokenKit::GetPermissionRequestToggleStatus("", status, userID);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    // UserId is invalid.
    userID = -1;
    ret = AccessTokenKit::GetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status, userID);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: GetPermissionRequestToggleStatusSpecTest001
 * @tc.desc: GetPermissionRequestToggleStatus caller is a normal app, not a system app.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionRequestToggleStatusTest, GetPermissionRequestToggleStatusSpecTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionRequestToggleStatusSpecTest001");

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestNormalInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    uint32_t status;
    int32_t ret = AccessTokenKit::GetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestNormalInfoParms.userID);
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, ret);
}

/**
 * @tc.name: GetPermissionRequestToggleStatusSpecTest002
 * @tc.desc: GetPermissionRequestToggleStatus caller is a system app without related permissions.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionRequestToggleStatusTest, GetPermissionRequestToggleStatusSpecTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionRequestToggleStatusSpecTest002");

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    int32_t selfUid = getuid();
    setuid(10001); // 10001： UID

    uint32_t getStatus;
    int32_t ret = AccessTokenKit::GetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", getStatus,
        g_infoManagerTestSystemInfoParms.userID);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, ret);

    // restore environment
    setuid(selfUid);
}

static void AllocAndSetHapToken(void)
{
    AccessTokenIDEx tokenIdEx = {0};

    PermissionDef infoManagerTestPermDef1 = {
        .permissionName = "ohos.permission.DISABLE_PERMISSION_DIALOG_TEST",
        .bundleName = "accesstoken_test",
        .grantMode = 1,
        .availableLevel = APL_NORMAL,
        .label = "label3",
        .labelId = 1,
        .description = "open the door",
        .descriptionId = 1,
        .availableType = MDM
    };

    PermissionStateFull infoManagerTestState1 = {
        .permissionName = "ohos.permission.DISABLE_PERMISSION_DIALOG",
        .isGeneral = true,
        .resDeviceID = {"local3"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {1}
    };

    PermissionDef infoManagerTestPermDef2 = {
        .permissionName = "ohos.permission.GET_SENSITIVE_PERMISSIONS_TEST",
        .bundleName = "accesstoken_test",
        .grantMode = 1,
        .availableLevel = APL_NORMAL,
        .label = "label3",
        .labelId = 1,
        .description = "open the door",
        .descriptionId = 1,
        .availableType = MDM
    };

    PermissionStateFull infoManagerTestState2 = {
        .permissionName = "ohos.permission.GET_SENSITIVE_PERMISSIONS",
        .isGeneral = true,
        .resDeviceID = {"local3"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {1}
    };

    HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain3",
        .permList = {infoManagerTestPermDef1, infoManagerTestPermDef2},
        .permStateList = {infoManagerTestState1, infoManagerTestState2}
    };

    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms, infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));
}

/**
 * @tc.name: GetPermissionRequestToggleStatusSpecTest003
 * @tc.desc: GetPermissionRequestToggleStatus caller is a system app with related permissions.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionRequestToggleStatusTest, GetPermissionRequestToggleStatusSpecTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionRequestToggleStatusSpecTest003");

    AllocAndSetHapToken();

    int32_t selfUid = getuid();
    setuid(10001); // 10001： UID

    // Set a closed status value.
    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    int32_t ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestSystemInfoParms.userID);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Get a closed status value.
    uint32_t getStatus;
    ret = AccessTokenKit::GetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", getStatus,
        g_infoManagerTestSystemInfoParms.userID);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(PermissionRequestToggleStatus::CLOSED, getStatus);

    // Set a open status value.
    status = PermissionRequestToggleStatus::OPEN;
    ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestSystemInfoParms.userID);
    ASSERT_EQ(RET_SUCCESS, ret);

    // Get a open status value.
    ret = AccessTokenKit::GetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", getStatus,
        g_infoManagerTestSystemInfoParms.userID);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_EQ(PermissionRequestToggleStatus::OPEN, getStatus);

    // restore environment
    setuid(selfUid);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS