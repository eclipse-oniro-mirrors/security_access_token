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
static int32_t g_selfUid;
};

void GetNativeTokenInfoTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    // clean up test cases
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
}

void GetNativeTokenInfoTest::TearDownTestCase()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);

    SetSelfTokenID(g_selfTokenId);
    TestCommon::ResetTestEvironment();
}

void GetNativeTokenInfoTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");

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
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    ASSERT_NE(tokenIdEx.tokenIdExStruct.tokenID, INVALID_TOKENID);
}

void GetNativeTokenInfoTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
}

/**
 * @tc.name: GetNativeTokenInfoAbnormalTest001
 * @tc.desc: cannot get native token with invalid tokenID(0).
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetNativeTokenInfoTest, GeTokenInfoAbnormalTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GeTokenInfoAbnormalTest001");
    AccessTokenID tokenID = 0;
    NativeTokenInfo nativeInfo;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::GetNativeTokenInfo(tokenID, nativeInfo));

    HapTokenInfo hapInfo;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::GetHapTokenInfo(tokenID, hapInfo));
}

/**
 * @tc.name: GetTokenInfoAbnormalTest002
 * @tc.desc: 1. cannot get native token with invalid tokenID(hap); 1. cannot get hap token with invalid tokenID(native)
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetNativeTokenInfoTest, GetTokenInfoAbnormalTest002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetNativeTokenInfoAbnormalTest002");
    MockNativeToken mock("accesstoken_service");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenHap = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenHap);
    AccessTokenID tokenNative = AccessTokenKit::GetNativeTokenId("token_sync_service");
    ASSERT_NE(INVALID_TOKENID, tokenNative);

    NativeTokenInfo nativeInfo;
    HapTokenInfo hapInfo;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::GetNativeTokenInfo(tokenHap, nativeInfo));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfo(tokenHap, hapInfo));


    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetNativeTokenInfo(tokenNative, nativeInfo));
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::GetHapTokenInfo(tokenNative, hapInfo));
}

/**
 * @tc.name: GetTokenInfoAbnormalTest003
 * @tc.desc: GetNativeTokenInfo with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(GetNativeTokenInfoTest, GetTokenInfoAbnormalTest003, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetNativeTokenInfoAbnormalTest002");
    g_selfUid = getuid();
    setuid(1234); // 1234: UID

    AccessTokenID tokenId = 805920561; //805920561 is a native tokenId.
    NativeTokenInfo tokenInfo;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo));

    HapTokenInfo hapInfo;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo));

    setuid(g_selfUid);
}

/**
 * @tc.name: GetNativeTokenInfoFuncTest001
 * @tc.desc: Get token info success.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetNativeTokenInfoTest, GetNativeTokenInfoFuncTest001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetNativeTokenInfoFuncTest001");
    MockNativeToken mock("accesstoken_service");
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenHap = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenHap);

    AccessTokenID tokenNative = AccessTokenKit::GetNativeTokenId("token_sync_service");
    ASSERT_NE(INVALID_TOKENID, tokenNative);

    NativeTokenInfo nativeInfo;
    HapTokenInfo hapInfo;

    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetHapTokenInfo(tokenHap, hapInfo));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetNativeTokenInfo(tokenNative, nativeInfo));


    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::GetNativeTokenInfo(tokenHap, nativeInfo));
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::GetHapTokenInfo(tokenNative, hapInfo));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS