/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include <unistd.h>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_kit.h"
#include "automation_control_types.h"
#include "test_common.h"
#include "tokenid_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static uint64_t g_selfTokenId = 0;
static const std::string TEST_BUNDLE_NAME = "AutomationControlAccessCheckTest";
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 12;
static constexpr AccessTokenID FAKE_TOKEN_ID = 1234;
};

class AutomationControlAccessCheckTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AutomationControlAccessCheckTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

void AutomationControlAccessCheckTest::TearDownTestCase()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
}

void AutomationControlAccessCheckTest::SetUp()
{
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
    EXPECT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(info, policy, tokenIdEx));
    EXPECT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
}

void AutomationControlAccessCheckTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

#ifndef ENABLE_AUTOMATION_CONTROL
HWTEST_F(AutomationControlAccessCheckTest, CheckAutomationControlAccessNotSupport001, TestSize.Level0)
{
    std::vector<AccessTokenID> targetList;
    targetList.emplace_back(FAKE_TOKEN_ID);
    std::vector<AutomationControlAccessDecision> decisions;
    int32_t ret = AccessTokenKit::CheckAutomationControlAccess(FAKE_TOKEN_ID, targetList, decisions);
    ASSERT_EQ(ret, AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT);
}
#else
/**
 * @tc.name: CheckAutomationControlAccess001
 * @tc.desc: Check access for target with no record returns POPUP_NEEDED.
 */
HWTEST_F(AutomationControlAccessCheckTest, CheckAutomationControlAccess001, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller, INVALID_TOKENID);

    HapInfoParams tgtInfo = {
        .userID = TEST_USER_ID, .bundleName = "Check001_tgt",
        .instIndex = 0, .appIDDesc = "appIDDesc", .apiVersion = DEFAULT_API_VERSION
    };
    HapPolicyParams policy = {.apl = APL_NORMAL, .domain = "domain"};
    AccessTokenID target = AccessTokenKit::AllocHapToken(tgtInfo, policy).tokenIdExStruct.tokenID;
    ASSERT_NE(target, INVALID_TOKENID);

    std::vector<AccessTokenID> targetList;
    targetList.emplace_back(target);
    std::vector<AutomationControlAccessDecision> decisions;
    int32_t ret = AccessTokenKit::CheckAutomationControlAccess(controller, targetList, decisions);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(decisions.size(), 1);
    EXPECT_EQ(decisions[0], POPUP_NEEDED);

    AccessTokenKit::DeleteToken(target);
}

/**
 * @tc.name: CheckAutomationControlAccess002
 * @tc.desc: Set ENABLED then check returns NO_POPUP_NEEDED_GRANTED.
 */
HWTEST_F(AutomationControlAccessCheckTest, CheckAutomationControlAccess002, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller, INVALID_TOKENID);

    HapInfoParams tgtInfo = {
        .userID = TEST_USER_ID, .bundleName = "Check002_tgt",
        .instIndex = 0, .appIDDesc = "appIDDesc", .apiVersion = DEFAULT_API_VERSION
    };
    HapPolicyParams policy = {.apl = APL_NORMAL, .domain = "domain"};
    AccessTokenID target = AccessTokenKit::AllocHapToken(tgtInfo, policy).tokenIdExStruct.tokenID;
    ASSERT_NE(target, INVALID_TOKENID);

    std::vector<AutomationControlTargetParam> setList;
    AutomationControlTargetParam param;
    param.targetTokenID = target;
    param.status = AUTOMATION_CONTROL_ENABLED;
    setList.emplace_back(param);
    std::vector<AutomationControlSetResult> setResults;
    AccessTokenKit::SetAutomationControlStatus(controller, setList, setResults);

    std::vector<AccessTokenID> targetList;
    targetList.emplace_back(target);
    std::vector<AutomationControlAccessDecision> decisions;
    int32_t ret = AccessTokenKit::CheckAutomationControlAccess(controller, targetList, decisions);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(decisions.size(), 1);
    EXPECT_EQ(decisions[0], NO_POPUP_NEEDED_GRANTED);

    AccessTokenKit::DeleteToken(target);
}

/**
 * @tc.name: CheckAutomationControlAccess003
 * @tc.desc: Set DISABLED then check returns NO_POPUP_NEEDED_DENIED.
 */
HWTEST_F(AutomationControlAccessCheckTest, CheckAutomationControlAccess003, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller, INVALID_TOKENID);

    HapInfoParams tgtInfo = {
        .userID = TEST_USER_ID, .bundleName = "Check003_tgt",
        .instIndex = 0, .appIDDesc = "appIDDesc", .apiVersion = DEFAULT_API_VERSION
    };
    HapPolicyParams policy = {.apl = APL_NORMAL, .domain = "domain"};
    AccessTokenID target = AccessTokenKit::AllocHapToken(tgtInfo, policy).tokenIdExStruct.tokenID;
    ASSERT_NE(target, INVALID_TOKENID);

    std::vector<AutomationControlTargetParam> setList;
    AutomationControlTargetParam param;
    param.targetTokenID = target;
    param.status = AUTOMATION_CONTROL_DISABLED;
    setList.emplace_back(param);
    std::vector<AutomationControlSetResult> setResults;
    AccessTokenKit::SetAutomationControlStatus(controller, setList, setResults);

    std::vector<AccessTokenID> targetList;
    targetList.emplace_back(target);
    std::vector<AutomationControlAccessDecision> decisions;
    int32_t ret = AccessTokenKit::CheckAutomationControlAccess(controller, targetList, decisions);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(decisions.size(), 1);
    EXPECT_EQ(decisions[0], NO_POPUP_NEEDED_DENIED);

    AccessTokenKit::DeleteToken(target);
}

/**
 * @tc.name: CheckAutomationControlAccess004
 * @tc.desc: Check with non-existent target returns TARGET_NOT_EXIST.
 */
HWTEST_F(AutomationControlAccessCheckTest, CheckAutomationControlAccess004, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller, INVALID_TOKENID);

    std::vector<AccessTokenID> targetList;
    targetList.emplace_back(FAKE_TOKEN_ID);
    std::vector<AutomationControlAccessDecision> decisions;
    int32_t ret = AccessTokenKit::CheckAutomationControlAccess(controller, targetList, decisions);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(decisions.size(), 1);
    EXPECT_EQ(decisions[0], TARGET_NOT_EXIST);
}

/**
 * @tc.name: CheckAutomationControlAccess005
 * @tc.desc: Check with non-existent controllerTokenID returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlAccessCheckTest, CheckAutomationControlAccess005, TestSize.Level0)
{
    MockNativeToken native("foundation");

    std::vector<AccessTokenID> targetList;
    targetList.emplace_back(FAKE_TOKEN_ID);
    std::vector<AutomationControlAccessDecision> decisions;
    int32_t ret = AccessTokenKit::CheckAutomationControlAccess(FAKE_TOKEN_ID, targetList, decisions);
    ASSERT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: CheckAutomationControlAccess006
 * @tc.desc: Check with controllerTokenID=0 returns ERR_PARAM_INVALID.
 */
HWTEST_F(AutomationControlAccessCheckTest, CheckAutomationControlAccess006, TestSize.Level0)
{
    std::vector<AccessTokenID> targetList;
    targetList.emplace_back(FAKE_TOKEN_ID);
    std::vector<AutomationControlAccessDecision> decisions;
    int32_t ret = AccessTokenKit::CheckAutomationControlAccess(0, targetList, decisions);
    ASSERT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: CheckAutomationControlAccess007
 * @tc.desc: Check with empty targetList returns ERR_PARAM_INVALID.
 */
HWTEST_F(AutomationControlAccessCheckTest, CheckAutomationControlAccess007, TestSize.Level0)
{
    std::vector<AccessTokenID> targetList;
    std::vector<AutomationControlAccessDecision> decisions;
    int32_t ret = AccessTokenKit::CheckAutomationControlAccess(FAKE_TOKEN_ID, targetList, decisions);
    ASSERT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: CheckAutomationControlAccess008
 * @tc.desc: Check with native token as controller returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlAccessCheckTest, CheckAutomationControlAccess008, TestSize.Level0)
{
    AccessTokenID nativeTokenId = TestCommon::GetNativeTokenIdFromProcess("foundation");

    std::vector<AccessTokenID> targetList;
    targetList.emplace_back(FAKE_TOKEN_ID);
    std::vector<AutomationControlAccessDecision> decisions;
    int32_t ret = AccessTokenKit::CheckAutomationControlAccess(nativeTokenId, targetList, decisions);
    ASSERT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: CheckAutomationControlAccess009
 * @tc.desc: Check with native token as target returns TARGET_NOT_EXIST per-element.
 */
HWTEST_F(AutomationControlAccessCheckTest, CheckAutomationControlAccess009, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller, INVALID_TOKENID);

    AccessTokenID nativeTokenId = TestCommon::GetNativeTokenIdFromProcess("foundation");

    std::vector<AccessTokenID> targetList;
    targetList.emplace_back(nativeTokenId);
    std::vector<AutomationControlAccessDecision> decisions;
    int32_t ret = AccessTokenKit::CheckAutomationControlAccess(controller, targetList, decisions);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(decisions.size(), 1u);
    EXPECT_EQ(decisions[0], TARGET_NOT_EXIST);
}

/**
 * @tc.name: CheckAutomationControlAccess010
 * @tc.desc: Check with mixed HAP and native targets returns per-element POPUP_NEEDED and INVALID_TOKEN_ID.
 */
HWTEST_F(AutomationControlAccessCheckTest, CheckAutomationControlAccess010, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller, INVALID_TOKENID);

    HapInfoParams tgtInfo = {
        .userID = TEST_USER_ID, .bundleName = "Check010_tgt",
        .instIndex = 0, .appIDDesc = "appIDDesc", .apiVersion = DEFAULT_API_VERSION
    };
    HapPolicyParams policy = {.apl = APL_NORMAL, .domain = "domain"};
    AccessTokenID validTarget = AccessTokenKit::AllocHapToken(tgtInfo, policy).tokenIdExStruct.tokenID;
    ASSERT_NE(validTarget, INVALID_TOKENID);
    AccessTokenID nativeTarget = TestCommon::GetNativeTokenIdFromProcess("foundation");

    std::vector<AccessTokenID> targetList;
    targetList.emplace_back(validTarget);
    targetList.emplace_back(nativeTarget);

    std::vector<AutomationControlAccessDecision> decisions;
    int32_t ret = AccessTokenKit::CheckAutomationControlAccess(controller, targetList, decisions);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(decisions.size(), 2u);
    EXPECT_EQ(decisions[0], POPUP_NEEDED);
    EXPECT_EQ(decisions[1], TARGET_NOT_EXIST);

    AccessTokenKit::DeleteToken(validTarget);
}

/**
 * @tc.name: CheckAutomationControlAccess011
 * @tc.desc: Check with targetList exceeding 1024 returns ERR_PARAM_INVALID.
 */
HWTEST_F(AutomationControlAccessCheckTest, CheckAutomationControlAccess011, TestSize.Level0)
{
    std::vector<AccessTokenID> targetList;
    for (int32_t i = 0; i < 1025; i++) {
        targetList.emplace_back(FAKE_TOKEN_ID);
    }
    std::vector<AutomationControlAccessDecision> decisions;
    int32_t ret = AccessTokenKit::CheckAutomationControlAccess(FAKE_TOKEN_ID, targetList, decisions);
    ASSERT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
