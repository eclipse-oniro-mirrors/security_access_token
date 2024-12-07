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
#include "accesstoken_log.h"
#include "access_token_error.h"
#include "token_setproc.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_sync_kit_interface.h"
#endif

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "GetRemoteNativeTokenIDTest"};
static AccessTokenID g_selfTokenId = 0;
static AccessTokenIDEx g_testTokenIDEx = {0};
static int32_t g_selfUid;

static HapPolicyParams g_PolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
};

static HapInfoParams g_InfoParms = {
    .userID = 1,
    .bundleName = "ohos.test.bundle",
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
    g_selfUid = getuid();
}

void GetRemoteNativeTokenIDTest::TearDownTestCase()
{
    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    GTEST_LOG_(INFO) << "PermStateChangeCallback,  tokenID is " << GetSelfTokenID();
    GTEST_LOG_(INFO) << "PermStateChangeCallback,  uid is " << getuid();
}

void GetRemoteNativeTokenIDTest::SetUp()
{
    AccessTokenKit::AllocHapToken(g_InfoParms, g_PolicyPrams);

    g_testTokenIDEx = AccessTokenKit::GetHapTokenIDEx(g_InfoParms.userID,
                                                      g_InfoParms.bundleName,
                                                      g_InfoParms.instIndex);
    ASSERT_NE(INVALID_TOKENID, g_testTokenIDEx.tokenIDEx);
    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(g_testTokenIDEx.tokenIDEx));
    setuid(1234); // 1234: UID
}

void GetRemoteNativeTokenIDTest::TearDown()
{
    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    setuid(g_selfUid);
}
#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: GetRemoteNativeTokenIDAbnormalTest001
 * @tc.desc: GetRemoteNativeTokenID with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetRemoteNativeTokenIDTest, GetRemoteNativeTokenIDAbnormalTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetRemoteNativeTokenIDAbnormalTest001 start.");
    std::string device = "device";
    AccessTokenID tokenId = 123;
    ASSERT_EQ(INVALID_TOKENID, AccessTokenKit::GetRemoteNativeTokenID(device, tokenId));
}
#endif