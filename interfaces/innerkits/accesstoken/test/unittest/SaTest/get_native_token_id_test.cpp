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
};

void GetNativeTokenIdTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);
}

void GetNativeTokenIdTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    TestCommon::ResetTestEvironment();
}

void GetNativeTokenIdTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
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
HWTEST_F(GetNativeTokenIdTest, GetNativeTokenIdAbnormalTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetNativeTokenIdAbnormalTest001");
    MockNativeToken mock("accesstoken_service");
    std::string processName = "";
    EXPECT_EQ(INVALID_TOKENID, AccessTokenKit::GetNativeTokenId(processName));

    processName = "invalid processName";
    EXPECT_EQ(INVALID_TOKENID, AccessTokenKit::GetNativeTokenId(processName));
}

/**
 * @tc.name: GetNativeTokenIdAbnormalTest002
 * @tc.desc: get native tokenid with hap.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetNativeTokenIdTest, GetNativeTokenIdAbnormalTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetNativeTokenIdAbnormalTest002");
    std::string processName = "hdcd";
    std::vector<std::string> reqPerm;
    MockHapToken mock("GetNativeTokenIdAbnormalTest002", reqPerm, true);

    int32_t selfUid = getuid();
    setuid(10001); // 10001： UID

    ASSERT_EQ(INVALID_TOKENID, AccessTokenKit::GetNativeTokenId(processName));

    // restore environment
    setuid(selfUid);
}

/**
 * @tc.name: GetNativeTokenIdAbnormalTest003
 * @tc.desc: Verify the GetNativeTokenId abnormal branch return nullptr proxy.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetNativeTokenIdTest, GetNativeTokenIdAbnormalTest003, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetNativeTokenIdAbnormalTest003");
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
HWTEST_F(GetNativeTokenIdTest, GetNativeTokenIdFuncTest001, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetNativeTokenIdFuncTest001");
    MockNativeToken mock("accesstoken_service");

    std::string processName = "hdcd";
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId(processName);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    NativeTokenInfo tokenInfo;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetNativeTokenInfo(tokenID, tokenInfo));
    ASSERT_EQ(true, tokenInfo.processName == processName);
}

/**
 * @tc.name: GetNativeTokenIdFuncTest002
 * @tc.desc: get native tokenid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(GetNativeTokenIdTest, GetNativeTokenIdFuncTest002, TestSize.Level0)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetNativeTokenIdFuncTest002");
    std::string processName = "hdcd";
    MockNativeToken mock("accesstoken_service");

    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId(processName);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    NativeTokenInfo tokenInfo;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::GetNativeTokenInfo(tokenID, tokenInfo));
    ASSERT_EQ(true, tokenInfo.processName == processName);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS