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
    SECURITY_DOMAIN_ACCESSTOKEN, "GetPermissionFlagTest"};
static AccessTokenID g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const unsigned int TEST_TOKENID_INVALID = 0;
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static const int INVALID_PERMNAME_LEN = 260;
static const int CYCLE_TIMES = 100;
HapInfoParams g_infoManagerTestNormalInfoParms = TestCommon::GetInfoManagerTestNormalInfoParms();
HapInfoParams g_infoManagerTestSystemInfoParms = TestCommon::GetInfoManagerTestSystemInfoParms();
HapPolicyParams g_infoManagerTestPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();
};

void GetPermissionFlagTest::SetUpTestCase()
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

void GetPermissionFlagTest::TearDownTestCase()
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

void GetPermissionFlagTest::SetUp()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetUp ok.");

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

void GetPermissionFlagTest::TearDown()
{
}

/**
 * @tc.name: GetPermissionFlagFuncTest001
 * @tc.desc: Get permission flag after grant permission.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionFlagTest, GetPermissionFlagFuncTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetPermissionFlagFuncTest001");

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    uint32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.MICROPHONE", flag);
    ASSERT_EQ(PERMISSION_USER_FIXED, flag);
    ASSERT_EQ(RET_SUCCESS, ret);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: GetPermissionFlagAbnormalTest001
 * @tc.desc: Get permission flag that tokenID or permission is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionFlagTest, GetPermissionFlagAbnormalTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetPermissionFlagAbnormalTest001");

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    uint32_t flag;
    int ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.GAMMA", flag);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);

    ret = AccessTokenKit::GetPermissionFlag(tokenID, "", flag);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    std::string invalidPerm(INVALID_PERMNAME_LEN, 'a');
    ret = AccessTokenKit::GetPermissionFlag(tokenID, invalidPerm, flag);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = AccessTokenKit::GetPermissionFlag(TEST_TOKENID_INVALID, "ohos.permission.MICROPHONE", flag);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    ret = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);

    ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.ALPHA", flag);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
}

/**
 * @tc.name: GetPermissionFlagSpecTest001
 * @tc.desc: GetPermissionFlag is invoked multiple times.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetPermissionFlagTest, GetPermissionFlagSpecTest001, TestSize.Level0)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetPermissionFlagSpecTest001");

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    uint32_t flag;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        int32_t ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
        ASSERT_EQ(RET_SUCCESS, ret);

        ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.MICROPHONE", flag);
        ASSERT_EQ(RET_SUCCESS, ret);
        ASSERT_EQ(PERMISSION_USER_FIXED, flag);
    }
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: GetPermissionFlagSpecTest002
 * @tc.desc: GetPermissionFlag caller is normal app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(GetPermissionFlagTest, GetPermissionFlagSpecTest002, TestSize.Level0)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetPermissionFlagSpecTest002");

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestNormalInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);

    uint32_t flag;
    int ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.MICROPHONE", flag);
    ASSERT_EQ(ERR_NOT_SYSTEM_APP, ret);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: GetPermissionFlagSpecTest003
 * @tc.desc: GetPermissionFlag caller is system app.
 * @tc.type: FUNC
 * @tc.require: issueI66BH3
 */
HWTEST_F(GetPermissionFlagTest, GetPermissionFlagSpecTest003, TestSize.Level0)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetPermissionFlagSpecTest003");

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestSystemInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIDEx);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    int ret = AccessTokenKit::GrantPermission(tokenID, "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);

    uint32_t flag;
    ret = AccessTokenKit::GetPermissionFlag(tokenID, "ohos.permission.MICROPHONE", flag);
    ASSERT_EQ(PERMISSION_USER_FIXED, flag);
    ASSERT_EQ(RET_SUCCESS, ret);

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS