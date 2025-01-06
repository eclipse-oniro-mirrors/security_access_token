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

#include "user_policy_test.h"
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
static const int32_t INDEX_ZERO = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
HapInfoParams g_infoManagerTestInfoParms = TestCommon::GetInfoManagerTestInfoParms();
HapPolicyParams g_infoManagerTestPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();
};

void UserPolicyTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();

    // clean up test cases
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                            g_infoManagerTestInfoParms.bundleName,
                                            g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms,
                                                              TestCommon::GetTestPolicyParams());
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void UserPolicyTest::TearDownTestCase()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                            g_infoManagerTestInfoParms.bundleName,
                                            g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
}

void UserPolicyTest::SetUp()
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

void UserPolicyTest::TearDown()
{
}

/**
 * @tc.name: UserPolicyFuncTest001
 * @tc.desc: UserPolicyTest.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UserPolicyTest, UserPolicyFuncTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UserPolicyFuncTest001");

    setuid(0);
    const char **perms = new const char *[1];
    perms[INDEX_ZERO] = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
    uint64_t tokenID = TestCommon::GetNativeToken("TestCase", perms, 1);
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    delete[] perms;
    UserState user = {.userId = 100, .isActive = true}; // 100 is userId
    const std::vector<UserState> userList = { user };
    const std::vector<std::string> permList = { "ohos.permission.INTERNET" };
    int32_t ret = AccessTokenKit::InitUserPolicy(userList, permList);
    EXPECT_EQ(ret, 0);
    ret = AccessTokenKit::UpdateUserPolicy(userList);
    EXPECT_EQ(ret, 0);
    ret = AccessTokenKit::ClearUserPolicy();
    EXPECT_EQ(ret, 0);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS