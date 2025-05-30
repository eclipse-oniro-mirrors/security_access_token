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

#include "get_permission_flag_test.h"
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
static const unsigned int TEST_TOKENID_INVALID = 0;
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static const int INVALID_PERMNAME_LEN = 260;
static const int CYCLE_TIMES = 100;
static const std::string PERMISSION_MICROPHONE = "ohos.permission.MICROPHONE";
static const std::string GRANT_SENSITIVE_PERMISSION = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
static MockHapToken* g_mock = nullptr;
}

void GetPermissionFlagTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    // clean up test cases
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    if (tokenID != INVALID_TOKENID) {
        TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    }

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back(GRANT_SENSITIVE_PERMISSION);
    g_mock = new (std::nothrow) MockHapToken("GetPermissionFlagTest", reqPerm, true);
}

void GetPermissionFlagTest::TearDownTestCase()
{
    // clean up test cases
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    if (tokenID != INVALID_TOKENID) {
        TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    }
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    SetSelfTokenID(g_selfTokenId);
    TestCommon::ResetTestEvironment();
}

void GetPermissionFlagTest::SetUp()
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
    PermissionStateFull permStatMicro = {
        .permissionName = PERMISSION_MICROPHONE,
        .isGeneral = true,
        .resDeviceID = {"device3"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
    };

    policy.permStateList.emplace_back(permStatMicro);

    AccessTokenIDEx tokenIdEx = {0};
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    EXPECT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
}

void GetPermissionFlagTest::TearDown()
{
    // clean up test cases
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    if (tokenID != INVALID_TOKENID) {
        TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    }
}

/**
 * @tc.name: GetPermissionFlagFuncTest001
 * @tc.desc: Get permission flag after grant permission.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionFlagTest, GetPermissionFlagFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionFlagFuncTest001");
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(
        RET_SUCCESS, AccessTokenKit::GrantPermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED));

    uint32_t flag;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, PERMISSION_MICROPHONE, flag));
    ASSERT_EQ(PERMISSION_USER_FIXED, flag);

    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: GetPermissionFlagAbnormalTest001
 * @tc.desc: Get permission flag that tokenID or permission is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionFlagTest, GetPermissionFlagAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionFlagAbnormalTest001");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    uint32_t flag;
    int ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.GAMMA", flag);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);

    ret = AccessTokenKit::GetPermissionFlag(tokenID, "", flag);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::GetPermissionFlag(tokenID, invalidPerm, flag);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = AccessTokenKit::GetPermissionFlag(TEST_TOKENID_INVALID, PERMISSION_MICROPHONE, flag);
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));

    ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.ALPHA", flag);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
}

/**
 * @tc.name: GetPermissionFlagSpecTest001
 * @tc.desc: GetPermissionFlag is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionFlagTest, GetPermissionFlagSpecTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionFlagSpecTest001");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    uint32_t flag;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GrantPermission(tokenID, PERMISSION_MICROPHONE, PERMISSION_USER_FIXED));

        ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, PERMISSION_MICROPHONE, flag));
        ASSERT_EQ(PERMISSION_USER_FIXED, flag);
    }
    ASSERT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: GetPermissionFlagSpecTest002
 * @tc.desc: GetPermissionFlag caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(GetPermissionFlagTest, GetPermissionFlagSpecTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionFlagSpecTest002");

    bool isSystemApp = false;
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back(GRANT_SENSITIVE_PERMISSION);
    MockHapToken mock("GetPermissionFlagSpecTest002", reqPerm, isSystemApp);

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    uint32_t flag;
    EXPECT_EQ(ERR_NOT_SYSTEM_APP, AccessTokenKit::GetPermissionFlag(tokenID, PERMISSION_MICROPHONE, flag));
}

/**
 * @tc.name: GetPermissionFlagSpecTest003
 * @tc.desc: GetPermissionFlag caller is system app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(GetPermissionFlagTest, GetPermissionFlagSpecTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionFlagSpecTest003");

    bool isSystemApp = true;
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back(GRANT_SENSITIVE_PERMISSION);
    MockHapToken mock("GetPermissionFlagSpecTest003", reqPerm, isSystemApp);

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(
        RET_SUCCESS, AccessTokenKit::GrantPermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED));

    uint32_t flag;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetPermissionFlag(tokenID, PERMISSION_MICROPHONE, flag));
    ASSERT_EQ(PERMISSION_USER_FIXED, flag);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS