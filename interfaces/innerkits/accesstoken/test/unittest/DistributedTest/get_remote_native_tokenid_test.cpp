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

#include "get_remote_native_tokenid_test.h"
#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "test_common.h"
#include "token_setproc.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_sync_kit_interface.h"
#endif

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
namespace {
static uint64_t g_selfTokenId = 0;
static AccessTokenID g_testTokenID = 0;

static HapPolicyParams g_policyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
};

static HapInfoParams g_infoParms = {
    .userID = 1,
    .bundleName = "GetRemoteNativeTokenIDTest",
    .instIndex = 0,
    .appIDDesc = "test.bundle",
    .isSystemApp = true
};

#ifdef TOKEN_SYNC_ENABLE
static const int32_t FAKE_SYNC_RET = 0xabcdef;
class TokenSyncCallbackImpl : public TokenSyncKitInterface {
    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) const override
    {
        return FAKE_SYNC_RET;
    };

    int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) const override
    {
        return FAKE_SYNC_RET;
    };

    int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) const override
    {
        return FAKE_SYNC_RET;
    };
};
#endif
}
using namespace testing::ext;

void GetRemoteNativeTokenIDTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);
}

void GetRemoteNativeTokenIDTest::TearDownTestCase()
{
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
    GTEST_LOG_(INFO) << "PermStateChangeCallback,  tokenID is " << GetSelfTokenID();
    GTEST_LOG_(INFO) << "PermStateChangeCallback,  uid is " << getuid();
}

void GetRemoteNativeTokenIDTest::SetUp()
{
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(g_infoParms, g_policyPrams, tokenIdEx));

    g_testTokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, g_testTokenID);
    EXPECT_EQ(0, SetSelfTokenID(g_testTokenID));
}

void GetRemoteNativeTokenIDTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(
        g_infoParms.userID, g_infoParms.bundleName, g_infoParms.instIndex);
    TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}
#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: GetRemoteNativeTokenIDAbnormalTest001
 * @tc.desc: GetRemoteNativeTokenID with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetRemoteNativeTokenIDTest, GetRemoteNativeTokenIDAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetRemoteNativeTokenIDAbnormalTest001 start.");
    std::string device = "device";
    AccessTokenID tokenId = 123;
    ASSERT_EQ(INVALID_TOKENID, AccessTokenKit::GetRemoteNativeTokenID(device, tokenId));
}
#endif