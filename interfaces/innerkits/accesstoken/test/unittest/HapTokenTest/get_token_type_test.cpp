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

uint64_t BuildFullTokenId(uint32_t highBits, ATokenTypeEnum type, uint32_t toolFlag)
{
    AccessTokenIDInner innerId = {0};
    innerId.version = DEFAULT_TOKEN_VERSION;
    innerId.type = static_cast<uint32_t>(type);
    innerId.toolFlag = toolFlag;
    innerId.tokenUniqueID = 1;
    AccessTokenID tokenId = *reinterpret_cast<AccessTokenID*>(&innerId);
    return (static_cast<uint64_t>(highBits) << 32) | tokenId; // 32 is the lower bits
}
}

void GetTokenTypeTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    // clean up test cases
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

void GetTokenTypeTest::TearDownTestCase()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
    TestCommon::ResetTestEvironment();
}

void GetTokenTypeTest::SetUp()
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
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
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
    LOGI(ATM_DOMAIN, ATM_TAG, "GetTokenTypeFuncTest001");
    MockNativeToken mock("foundation");
    // type = TOKEN_SHELL
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId("hdcd");
    ASSERT_NE(INVALID_TOKENID, tokenID);
    EXPECT_EQ(TOKEN_SHELL, AccessTokenKit::GetTokenType(tokenID));

    // type = TOKEN_NATIVE
    tokenID = AccessTokenKit::GetNativeTokenId("foundation");
    EXPECT_EQ(TOKEN_NATIVE, AccessTokenKit::GetTokenType(tokenID));

    // type = TOKEN_HAP
    tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    EXPECT_EQ(TOKEN_HAP, AccessTokenKit::GetTokenType(tokenID));
}

/**
 * @tc.name: GetTokenTypeAbnormalTest001
 * @tc.desc: get the token type abnormal branch.
 * @tc.type: FUNC
 * @tc.require Issue I5RJBB
 */
HWTEST_F(GetTokenTypeTest, GetTokenTypeAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetTokenTypeAbnormalTest001");

    AccessTokenID tokenID = 0;
    EXPECT_EQ(TOKEN_INVALID, AccessTokenKit::GetTokenType(tokenID));
}

/**
 * @tc.name: GetTokenTypeFlagAbnormalTest001
 * @tc.desc: cannot get token type with tokenID.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetTokenTypeTest, GetTokenTypeFlagAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetTokenTypeFlagAbnormalTest001");

    AccessTokenID tokenID = 0;
    ATokenTypeEnum ret = AccessTokenKit::GetTokenTypeFlag(tokenID);
    EXPECT_EQ(ret, TOKEN_INVALID);
}

/**
 * @tc.name: GetTokenTypeFlagFuncTest001
 * @tc.desc: Get token type with native tokenID.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetTokenTypeTest, GetTokenTypeFlagFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetTokenTypeFlagFuncTest001");

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
    EXPECT_EQ(ret, TOKEN_NATIVE);
}

/**
 * @tc.name: IsCliToolTokenFuncTest001
 * @tc.desc: Identify cli tool token by tool flag and shell token type.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetTokenTypeTest, IsCliToolTokenFuncTest001, TestSize.Level0)
{
    EXPECT_TRUE(AccessTokenKit::IsCliToolToken(BuildFullTokenId(0, TOKEN_SHELL, 1)));
}

/**
 * @tc.name: IsCliToolTokenFuncTest002
 * @tc.desc: Shell token without tool flag is not a cli tool token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetTokenTypeTest, IsCliToolTokenFuncTest002, TestSize.Level0)
{
    EXPECT_FALSE(AccessTokenKit::IsCliToolToken(BuildFullTokenId(0, TOKEN_SHELL, 0)));
}

/**
 * @tc.name: IsCliToolTokenFuncTest003
 * @tc.desc: Non-shell tool token is not a cli tool token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetTokenTypeTest, IsCliToolTokenFuncTest003, TestSize.Level0)
{
    EXPECT_FALSE(AccessTokenKit::IsCliToolToken(BuildFullTokenId(0, TOKEN_HAP, 1)));
    EXPECT_FALSE(AccessTokenKit::IsCliToolToken(BuildFullTokenId(0, TOKEN_NATIVE, 1)));
}

/**
 * @tc.name: IsCliToolTokenAbnormalTest001
 * @tc.desc: Invalid token id returns false after low-bit masking.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetTokenTypeTest, IsCliToolTokenAbnormalTest001, TestSize.Level0)
{
    EXPECT_FALSE(AccessTokenKit::IsCliToolToken(INVALID_TOKENID));
    EXPECT_FALSE(AccessTokenKit::IsCliToolToken(static_cast<uint64_t>(1) << 32)); // 32 is low-bit size
}

/**
 * @tc.name: IsCliToolTokenFuncTest004
 * @tc.desc: High 32 bits do not affect cli tool token judgment.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetTokenTypeTest, IsCliToolTokenFuncTest004, TestSize.Level0)
{
    // 0x12345678 is ramdom tokenid
    EXPECT_TRUE(AccessTokenKit::IsCliToolToken(BuildFullTokenId(0x12345678, TOKEN_SHELL, 1)));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
