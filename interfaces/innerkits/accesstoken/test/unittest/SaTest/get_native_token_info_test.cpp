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

#include "get_native_token_info_test.h"
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
    SECURITY_DOMAIN_ACCESSTOKEN, "GetNativeTokenInfoTest"};
static AccessTokenID g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int TEST_USER_ID = 0;
static int32_t g_selfUid;
};

void GetNativeTokenInfoTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();

    // clean up test cases
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);
}

void GetNativeTokenInfoTest::TearDownTestCase()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
}

void GetNativeTokenInfoTest::SetUp()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "SetUp ok.");

    setuid(0);
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
        .apiVersion = 8
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    TestCommon::TestPreparePermDefList(policy);
    TestCommon::TestPreparePermStateList(policy);

    AccessTokenKit::AllocHapToken(info, policy);
}

void GetNativeTokenInfoTest::TearDown()
{
}

/**
 * @tc.name: GetNativeTokenInfoAbnormalTest001
 * @tc.desc: cannot get native token with invalid tokenID.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetNativeTokenInfoTest, GetNativeTokenInfoAbnormalTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetNativeTokenInfoAbnormalTest001");
    AccessTokenID tokenID = 0;
    NativeTokenInfo findInfo;
    int ret = AccessTokenKit::GetNativeTokenInfo(tokenID, findInfo);
    ASSERT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: GetNativeTokenInfoAbnormalTest002
 * @tc.desc: GetNativeTokenInfo with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetNativeTokenInfoTest, GetNativeTokenInfoAbnormalTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetNativeTokenInfoAbnormalTest002");
    g_selfUid = getuid();
    setuid(1234); // 1234: UID

    AccessTokenID tokenId = 805920561; //805920561 is a native tokenId.
    NativeTokenInfo tokenInfo;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo));

    setuid(g_selfUid);
}

/**
 * @tc.name: GetNativeTokenInfoFuncTest001
 * @tc.desc: Get native token info success.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetNativeTokenInfoTest, GetNativeTokenInfoFuncTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetNativeTokenInfoFuncTest001");
    AccessTokenID tokenHap = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenHap);

    NativeTokenInfo nativeInfo;
    HapTokenInfo hapInfo;

    int ret = AccessTokenKit::GetHapTokenInfo(tokenHap, hapInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    AccessTokenID tokenNative = AccessTokenKit::GetNativeTokenId("token_sync_service");
    ASSERT_NE(INVALID_TOKENID, tokenNative);

    ret = AccessTokenKit::GetNativeTokenInfo(tokenNative, nativeInfo);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenKit::GetHapTokenInfo(tokenNative, hapInfo);
    ASSERT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);

    AccessTokenKit::DeleteToken(tokenHap);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS