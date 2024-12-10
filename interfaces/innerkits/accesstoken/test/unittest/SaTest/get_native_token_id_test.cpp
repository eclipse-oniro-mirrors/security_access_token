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

#include "get_native_token_id_test.h"
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
    SECURITY_DOMAIN_ACCESSTOKEN, "GetNativeTokenIdTest"};
static AccessTokenID g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int TEST_USER_ID = 0;
};

void GetNativeTokenIdTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();

    // clean up test cases
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);
}

void GetNativeTokenIdTest::TearDownTestCase()
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    SetSelfTokenID(g_selfTokenId);
}

void GetNativeTokenIdTest::SetUp()
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

void GetNativeTokenIdTest::TearDown()
{
}

/**
 * @tc.name: GetNativeTokenIdAbnormalTest001
 * @tc.desc: cannot get native tokenid with invalid processName.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetNativeTokenIdTest, GetNativeTokenIdAbnormalTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetNativeTokenIdAbnormalTest001");
    std::string processName = "";
    ASSERT_EQ(INVALID_TOKENID, AccessTokenKit::GetNativeTokenId(processName));

    processName = "invalid processName";
    ASSERT_EQ(INVALID_TOKENID, AccessTokenKit::GetNativeTokenId(processName));
}

/**
 * @tc.name: GetNativeTokenIdAbnormalTest002
 * @tc.desc: get native tokenid with hap.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetNativeTokenIdTest, GetNativeTokenIdAbnormalTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetNativeTokenIdAbnormalTest002");
    std::string processName = "hdcd";
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(RET_SUCCESS, SetSelfTokenID(tokenID));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::ReloadNativeTokenInfo());

    int32_t selfUid = getuid();
    setuid(10001); // 10001： UID

    ASSERT_EQ(INVALID_TOKENID, AccessTokenKit::GetNativeTokenId(processName));

    // restore environment
    setuid(selfUid);
    ASSERT_EQ(RET_SUCCESS, SetSelfTokenID(g_selfTokenId));
}

/**
 * @tc.name: GetNativeTokenIdAbnormalTest003
 * @tc.desc: Verify the GetNativeTokenId abnormal branch return nullptr proxy.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetNativeTokenIdTest, GetNativeTokenIdAbnormalTest003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetNativeTokenIdAbnormalTest003");
    int32_t gSelfUid = getuid();
    setuid(1234); // 1234: UID

    std::string processName = "hdcd";
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId(processName);
    ASSERT_EQ(INVALID_TOKENID, tokenID);

    setuid(gSelfUid);
    ASSERT_EQ(RET_SUCCESS, SetSelfTokenID(g_selfTokenId));
}

/**
 * @tc.name: GetNativeTokenIdFuncTest001
 * @tc.desc: get native tokenid with processName.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetNativeTokenIdTest, GetNativeTokenIdFuncTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetNativeTokenIdFuncTest001");
    std::string processName = "hdcd";
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId(processName);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    NativeTokenInfo tokenInfo;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetNativeTokenInfo(tokenID, tokenInfo));
    ASSERT_EQ(true, tokenInfo.processName == processName);
}

/**
 * @tc.name: GetNativeTokenIdFuncTest002
 * @tc.desc: get native tokenid with hap.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetNativeTokenIdTest, GetNativeTokenIdFuncTest002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetNativeTokenIdFuncTest002");
    std::string processName = "hdcd";
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    ASSERT_EQ(0, SetSelfTokenID(tokenID));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::ReloadNativeTokenInfo());

    tokenID = AccessTokenKit::GetNativeTokenId(processName);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    NativeTokenInfo tokenInfo;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetNativeTokenInfo(tokenID, tokenInfo));
    ASSERT_EQ(true, tokenInfo.processName == processName);

    ASSERT_EQ(0, SetSelfTokenID(g_selfTokenId));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS