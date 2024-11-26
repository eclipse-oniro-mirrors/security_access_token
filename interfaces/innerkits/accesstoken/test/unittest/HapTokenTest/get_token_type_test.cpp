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

#include "get_token_type_test.h"
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
    SECURITY_DOMAIN_ACCESSTOKEN, "GetTokenTypeTest"};
static AccessTokenID g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
HapInfoParams g_infoManagerTestInfoParms = TestCommon::GetInfoManagerTestInfoParms();
HapPolicyParams g_infoManagerTestPolicyPrams = TestCommon::GetInfoManagerTestPolicyPrams();
}

void GetTokenTypeTest::SetUpTestCase()
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

void GetTokenTypeTest::TearDownTestCase()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                            g_infoManagerTestInfoParms.bundleName,
                                            g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
}

void GetTokenTypeTest::SetUp()
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

void GetTokenTypeTest::TearDown()
{
}

/**
 * @tc.name: GetTokenTypeFuncTest001
 * @tc.desc: get the token type.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetTokenTypeTest, GetTokenTypeFuncTest001, TestSize.Level0)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetTokenTypeFuncTest001");

    // type = TOKEN_SHELL
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId("hdcd");
    int ret = AccessTokenKit::GetTokenType(tokenID);
    ASSERT_EQ(TOKEN_SHELL, ret);

    // type = TOKEN_NATIVE
    tokenID = AccessTokenKit::GetNativeTokenId("foundation");
    ret = AccessTokenKit::GetTokenType(tokenID);
    ASSERT_EQ(TOKEN_NATIVE, ret);

    // type = TOKEN_HAP
    tokenID = TestCommon::AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ret = AccessTokenKit::GetTokenType(tokenID);
    ASSERT_EQ(TOKEN_HAP, ret);
    tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                            g_infoManagerTestInfoParms.bundleName,
                                            g_infoManagerTestInfoParms.instIndex);
    ret = AccessTokenKit::DeleteToken(tokenID);
    if (tokenID != 0) {
        ASSERT_EQ(RET_SUCCESS, ret);
    }
}

/**
 * @tc.name: GetTokenTypeAbnormalTest001
 * @tc.desc: get the token type abnormal branch.
 * @tc.type: FUNC
 * @tc.require Issue I5RJBB
 */
HWTEST_F(GetTokenTypeTest, GetTokenTypeAbnormalTest001, TestSize.Level0)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetTokenTypeAbnormalTest001");

    AccessTokenID tokenID = 0;
    int32_t ret = AccessTokenKit::GetTokenType(tokenID);
    ASSERT_EQ(TOKEN_INVALID, ret);
}

/**
 * @tc.name: GetTokenTypeFlagAbnormalTest001
 * @tc.desc: cannot get token type with tokenID.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetTokenTypeTest, GetTokenTypeFlagAbnormalTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetTokenTypeFlagAbnormalTest001");

    AccessTokenID tokenID = 0;
    ATokenTypeEnum ret = AccessTokenKit::GetTokenTypeFlag(tokenID);
    ASSERT_EQ(ret, TOKEN_INVALID);
}

/**
 * @tc.name: GetTokenTypeFlagFuncTest001
 * @tc.desc: Get token type with native tokenID.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetTokenTypeTest, GetTokenTypeFlagFuncTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetTokenTypeFlagFuncTest001");

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = nullptr,
        .acls = nullptr,
        .processName = "GetTokenTypeFlag002",
        .aplStr = "system_core",
    };
    uint64_t tokenId01 = GetAccessTokenId(&infoInstance);

    AccessTokenID tokenID = tokenId01 & 0xffffffff;
    ATokenTypeEnum ret = AccessTokenKit::GetTokenTypeFlag(tokenID);
    ASSERT_EQ(ret, TOKEN_NATIVE);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS