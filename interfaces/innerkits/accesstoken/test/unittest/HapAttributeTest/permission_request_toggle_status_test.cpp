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
HapInfoParams g_infoManagerTestNormalInfoParms = TestCommon::GetInfoManagerTestNormalInfoParms();
HapInfoParams g_infoManagerTestSystemInfoParms = TestCommon::GetInfoManagerTestSystemInfoParms();
HapPolicyParams g_infoManagerTestPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();
};

void PermissionRequestToggleStatusTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    // clean up test cases
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    reqPerm.emplace_back("ohos.permission.DISABLE_PERMISSION_DIALOG");
    g_mock = new (std::nothrow) MockHapToken("PermissionRequestToggleStatusTest", reqPerm, true);
}

void PermissionRequestToggleStatusTest::TearDownTestCase()
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
    TestCommon::TestPreparePermStateList(policy);

    AccessTokenIDEx tokenIdEx = {0};
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    EXPECT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
}

void PermissionRequestToggleStatusTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

/**
 * @tc.name: SetPermissionRequestToggleStatusAbnormalTest001
 * @tc.desc: Set permission request toggle status that userId, permission or status is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionRequestToggleStatusTest, SetPermissionRequestToggleStatusAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionRequestToggleStatusAbnormalTest001");

    int32_t userID = 100;
    uint32_t status = PermissionRequestToggleStatus::CLOSED;

    // Permission name is invalid.
    int32_t ret = AccessTokenKit::SetPermissionRequestToggleStatus("", status, userID);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    // Status is invalid.
    status = 2;
    ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status, userID);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    // UserID is invalid.
    userID = -1;
    status = PermissionRequestToggleStatus::CLOSED;
    ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status, userID);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
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
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.DISABLE_PERMISSION_DIALOG");
    MockHapToken mock("SetPermissionRequestToggleStatus001", reqPerm, false);

    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    int32_t ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestNormalInfoParms.userID);
    EXPECT_EQ(ERR_NOT_SYSTEM_APP, ret);
}

/**
 * @tc.name: SetPermissionRequestToggleStatus002
 * @tc.desc: SetPermissionRequestToggleStatus caller is a system app without permissions.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionRequestToggleStatusTest, SetPermissionRequestToggleStatus002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionRequestToggleStatus002");
    std::vector<std::string> reqPerm;
    MockHapToken mock("SetPermissionRequestToggleStatus002", reqPerm, true);

    int32_t selfUid = getuid();
    setuid(10001); // 10001： UID
    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    int32_t ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestSystemInfoParms.userID);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, ret);

    status = PermissionRequestToggleStatus::OPEN;
    ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestSystemInfoParms.userID);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, ret);

    // restore environment
    setuid(selfUid);
}

/**
 * @tc.name: SetPermissionRequestToggleStatusSpecTest003
 * @tc.desc: SetPermissionRequestToggleStatus caller is a system app with permissions.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionRequestToggleStatusTest, SetPermissionRequestToggleStatusSpecTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetPermissionRequestToggleStatusSpecTest003");
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.DISABLE_PERMISSION_DIALOG");
    MockHapToken mock("SetPermissionRequestToggleStatusSpecTest003", reqPerm, true);

    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    int32_t ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestSystemInfoParms.userID);
    EXPECT_EQ(RET_SUCCESS, ret);

    status = PermissionRequestToggleStatus::OPEN;
    ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestSystemInfoParms.userID);
    EXPECT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: GetPermissionRequestToggleStatusAbnormalTest001
 * @tc.desc: Get permission request toggle status that userId, permission is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionRequestToggleStatusTest, GetPermissionRequestToggleStatusAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionRequestToggleStatusAbnormalTest001");

    int32_t userID = 100;
    uint32_t status;

    // Permission name is invalid.
    int32_t ret = AccessTokenKit::GetPermissionRequestToggleStatus("", status, userID);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    // UserId is invalid.
    userID = -1;
    ret = AccessTokenKit::GetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status, userID);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
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
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.DISABLE_PERMISSION_DIALOG");
    MockHapToken mock("GetPermissionRequestToggleStatusSpecTest001", reqPerm, false);

    uint32_t status;
    int32_t ret = AccessTokenKit::GetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestNormalInfoParms.userID);
    EXPECT_EQ(ERR_NOT_SYSTEM_APP, ret);
}

/**
 * @tc.name: GetPermissionRequestToggleStatusSpecTest002
 * @tc.desc: GetPermissionRequestToggleStatus caller is a system app without permissions.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(PermissionRequestToggleStatusTest, GetPermissionRequestToggleStatusSpecTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionRequestToggleStatusSpecTest002");
    std::vector<std::string> reqPerm;
    MockHapToken mock("GetPermissionRequestToggleStatusSpecTest002", reqPerm, true);

    int32_t selfUid = getuid();
    setuid(10001); // 10001： UID

    uint32_t getStatus;
    int32_t ret = AccessTokenKit::GetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", getStatus,
        g_infoManagerTestSystemInfoParms.userID);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, ret);

    // restore environment
    setuid(selfUid);
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
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.DISABLE_PERMISSION_DIALOG");
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    MockHapToken mock("GetPermissionRequestToggleStatusSpecTest003", reqPerm, true);

    // Set a closed status value.
    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    int32_t ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestSystemInfoParms.userID);
    EXPECT_EQ(RET_SUCCESS, ret);

    // Get a closed status value.
    uint32_t getStatus;
    ret = AccessTokenKit::GetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", getStatus,
        g_infoManagerTestSystemInfoParms.userID);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PermissionRequestToggleStatus::CLOSED, getStatus);

    // Set a open status value.
    status = PermissionRequestToggleStatus::OPEN;
    ret = AccessTokenKit::SetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", status,
        g_infoManagerTestSystemInfoParms.userID);
    EXPECT_EQ(RET_SUCCESS, ret);

    // Get a open status value.
    ret = AccessTokenKit::GetPermissionRequestToggleStatus("ohos.permission.MICROPHONE", getStatus,
        g_infoManagerTestSystemInfoParms.userID);
    EXPECT_EQ(RET_SUCCESS, ret);
    EXPECT_EQ(PermissionRequestToggleStatus::OPEN, getStatus);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS