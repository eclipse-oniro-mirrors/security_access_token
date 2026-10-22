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
static const std::string TEST_BUNDLE_NAME = "AutomationControlTest";
static const int TEST_USER_ID = 0;
static constexpr int32_t DEFAULT_API_VERSION = 12;
static constexpr AccessTokenID FAKE_TOKEN_ID = 1234;
};

class AutomationControlTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AutomationControlTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

void AutomationControlTest::TearDownTestCase()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
}

void AutomationControlTest::SetUp()
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

void AutomationControlTest::TearDown()
{
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    TestCommon::DeleteTestHapToken(tokenID);
}

#ifndef ENABLE_AUTOMATION_CONTROL
HWTEST_F(AutomationControlTest, AutomationControlNotSupport001, TestSize.Level0)
{
    std::vector<AutomationControlTargetParam> targetList;
    AutomationControlTargetParam param;
    param.targetTokenID = FAKE_TOKEN_ID;
    param.status = AUTOMATION_CONTROL_ENABLED;
    targetList.emplace_back(param);
    std::vector<AutomationControlSetResult> results;
    int32_t ret = AccessTokenKit::SetAutomationControlStatus(FAKE_TOKEN_ID, targetList, results);
    ASSERT_EQ(ret, AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT);
}

HWTEST_F(AutomationControlTest, AutomationControlNotSupport002, TestSize.Level0)
{
    std::vector<AutomationControlTargetResult> results;
    int32_t ret = AccessTokenKit::GetAutomationControlTargets(FAKE_TOKEN_ID, results);
    ASSERT_EQ(ret, AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT);
}

HWTEST_F(AutomationControlTest, AutomationControlNotSupport003, TestSize.Level0)
{
    std::vector<AutomationControlControllerInfo> results;
    int32_t ret = AccessTokenKit::GetAutomationControlControllers(FAKE_TOKEN_ID, results);
    ASSERT_EQ(ret, AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT);
}
#else
/**
 * @tc.name: SetAutomationControlStatus001
 * @tc.desc: Set automation control status with valid controller and targets, verify SUCCESS.
 */
HWTEST_F(AutomationControlTest, SetAutomationControlStatus001, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller, INVALID_TOKENID);

    HapInfoParams tgtInfo = {
        .userID = TEST_USER_ID, .bundleName = "Set001_tgt",
        .instIndex = 0, .appIDDesc = "appIDDesc", .apiVersion = DEFAULT_API_VERSION
    };
    HapPolicyParams policy = {.apl = APL_NORMAL, .domain = "domain"};
    AccessTokenID target = AccessTokenKit::AllocHapToken(tgtInfo, policy).tokenIdExStruct.tokenID;
    ASSERT_NE(target, INVALID_TOKENID);

    std::vector<AutomationControlTargetParam> targetList;
    AutomationControlTargetParam param1;
    param1.targetTokenID = target;
    param1.status = AUTOMATION_CONTROL_ENABLED;
    targetList.emplace_back(param1);

    std::vector<AutomationControlSetResult> results;
    int32_t ret = AccessTokenKit::SetAutomationControlStatus(controller, targetList, results);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], AUTOMATION_CONTROL_SET_SUCCESS);

    std::vector<AutomationControlTargetResult> queryResults;
    ret = AccessTokenKit::GetAutomationControlTargets(controller, queryResults);
    ASSERT_EQ(ret, RET_SUCCESS);
    bool found = false;
    for (const auto& r : queryResults) {
        if (r.targetTokenID == target) {
            found = true;
            EXPECT_EQ(r.status, AUTOMATION_CONTROL_ENABLED);
            break;
        }
    }
    EXPECT_TRUE(found);

    AccessTokenKit::DeleteToken(target);
}

/**
 * @tc.name: SetAutomationControlStatus002
 * @tc.desc: Set deny then query returns the pair with DISABLED status.
 */
HWTEST_F(AutomationControlTest, SetAutomationControlStatus002, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller, INVALID_TOKENID);

    HapInfoParams tgtInfo = {
        .userID = TEST_USER_ID, .bundleName = "Set002_tgt",
        .instIndex = 0, .appIDDesc = "appIDDesc", .apiVersion = DEFAULT_API_VERSION
    };
    HapPolicyParams policy = {.apl = APL_NORMAL, .domain = "domain"};
    AccessTokenID target = AccessTokenKit::AllocHapToken(tgtInfo, policy).tokenIdExStruct.tokenID;
    ASSERT_NE(target, INVALID_TOKENID);

    std::vector<AutomationControlTargetParam> targetList;
    AutomationControlTargetParam param;
    param.targetTokenID = target;
    param.status = AUTOMATION_CONTROL_DISABLED;
    targetList.emplace_back(param);

    std::vector<AutomationControlSetResult> results;
    int32_t ret = AccessTokenKit::SetAutomationControlStatus(controller, targetList, results);
    ASSERT_EQ(ret, RET_SUCCESS);
    EXPECT_EQ(results[0], AUTOMATION_CONTROL_SET_SUCCESS);

    std::vector<AutomationControlTargetResult> queryResults;
    ret = AccessTokenKit::GetAutomationControlTargets(controller, queryResults);
    ASSERT_EQ(ret, RET_SUCCESS);
    bool found = false;
    for (const auto& r : queryResults) {
        if (r.targetTokenID == target) {
            found = true;
            EXPECT_EQ(r.status, AUTOMATION_CONTROL_DISABLED);
            break;
        }
    }
    EXPECT_TRUE(found);

    AccessTokenKit::DeleteToken(target);
}

/**
 * @tc.name: SetAutomationControlStatus003
 * @tc.desc: Set with non-existent target returns TOKEN_ID_NOT_EXIST.
 */
HWTEST_F(AutomationControlTest, SetAutomationControlStatus003, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller, INVALID_TOKENID);

    HapInfoParams tgtInfo = {
        .userID = TEST_USER_ID, .bundleName = "Set003_tgt",
        .instIndex = 0, .appIDDesc = "appIDDesc", .apiVersion = DEFAULT_API_VERSION
    };
    HapPolicyParams policy = {.apl = APL_NORMAL, .domain = "domain"};
    AccessTokenID validTarget = AccessTokenKit::AllocHapToken(tgtInfo, policy).tokenIdExStruct.tokenID;
    ASSERT_NE(validTarget, INVALID_TOKENID);

    std::vector<AutomationControlTargetParam> targetList;
    AutomationControlTargetParam param1;
    param1.targetTokenID = FAKE_TOKEN_ID;
    param1.status = AUTOMATION_CONTROL_ENABLED;
    targetList.emplace_back(param1);
    AutomationControlTargetParam param2;
    param2.targetTokenID = validTarget;
    param2.status = AUTOMATION_CONTROL_ENABLED;
    targetList.emplace_back(param2);

    std::vector<AutomationControlSetResult> results;
    int32_t ret = AccessTokenKit::SetAutomationControlStatus(controller, targetList, results);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(results.size(), 2);
    EXPECT_EQ(results[0], AUTOMATION_CONTROL_SET_TOKEN_ID_NOT_EXIST);
    EXPECT_EQ(results[1], AUTOMATION_CONTROL_SET_SUCCESS);

    AccessTokenKit::DeleteToken(validTarget);
}

/**
 * @tc.name: SetAutomationControlStatus004
 * @tc.desc: Set with controllerTokenID=0 returns ERR_PARAM_INVALID.
 */
HWTEST_F(AutomationControlTest, SetAutomationControlStatus004, TestSize.Level0)
{
    std::vector<AutomationControlTargetParam> targetList;
    AutomationControlTargetParam param;
    param.targetTokenID = FAKE_TOKEN_ID;
    param.status = AUTOMATION_CONTROL_ENABLED;
    targetList.emplace_back(param);

    std::vector<AutomationControlSetResult> results;
    int32_t ret = AccessTokenKit::SetAutomationControlStatus(0, targetList, results);
    ASSERT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: SetAutomationControlStatus005
 * @tc.desc: Set with empty targetList returns ERR_PARAM_INVALID.
 */
HWTEST_F(AutomationControlTest, SetAutomationControlStatus005, TestSize.Level0)
{
    std::vector<AutomationControlTargetParam> targetList;
    std::vector<AutomationControlSetResult> results;
    int32_t ret = AccessTokenKit::SetAutomationControlStatus(FAKE_TOKEN_ID, targetList, results);
    ASSERT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: SetAutomationControlStatus006
 * @tc.desc: Set with non-existent controllerTokenID returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlTest, SetAutomationControlStatus006, TestSize.Level0)
{
    MockNativeToken native("foundation");

    std::vector<AutomationControlTargetParam> targetList;
    AutomationControlTargetParam param;
    param.targetTokenID = FAKE_TOKEN_ID;
    param.status = AUTOMATION_CONTROL_ENABLED;
    targetList.emplace_back(param);

    std::vector<AutomationControlSetResult> results;
    int32_t ret = AccessTokenKit::SetAutomationControlStatus(FAKE_TOKEN_ID, targetList, results);
    ASSERT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: SetAutomationControlStatus007
 * @tc.desc: Set with native token as controller returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlTest, SetAutomationControlStatus007, TestSize.Level0)
{
    AccessTokenID nativeTokenId = TestCommon::GetNativeTokenIdFromProcess("foundation");

    std::vector<AutomationControlTargetParam> targetList;
    AutomationControlTargetParam param;
    param.targetTokenID = FAKE_TOKEN_ID;
    param.status = AUTOMATION_CONTROL_ENABLED;
    targetList.emplace_back(param);

    std::vector<AutomationControlSetResult> results;
    int32_t ret = AccessTokenKit::SetAutomationControlStatus(nativeTokenId, targetList, results);
    ASSERT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: SetAutomationControlStatus008
 * @tc.desc: Set with native token as target returns AUTOMATION_CONTROL_SET_TOKEN_ID_NOT_EXIST per-element.
 */
HWTEST_F(AutomationControlTest, SetAutomationControlStatus008, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller, INVALID_TOKENID);

    AccessTokenID nativeTokenId = TestCommon::GetNativeTokenIdFromProcess("foundation");

    std::vector<AutomationControlTargetParam> targetList;
    AutomationControlTargetParam param;
    param.targetTokenID = nativeTokenId;
    param.status = AUTOMATION_CONTROL_ENABLED;
    targetList.emplace_back(param);

    std::vector<AutomationControlSetResult> results;
    int32_t ret = AccessTokenKit::SetAutomationControlStatus(controller, targetList, results);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0], AUTOMATION_CONTROL_SET_TOKEN_ID_NOT_EXIST);
}

/**
 * @tc.name: SetAutomationControlStatus009
 * @tc.desc: Set with mixed HAP and native targets returns per-element SUCCESS and TOKEN_ID_NOT_EXIST.
 */
HWTEST_F(AutomationControlTest, SetAutomationControlStatus009, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller, INVALID_TOKENID);

    HapInfoParams tgtInfo = {
        .userID = TEST_USER_ID, .bundleName = "Set009_tgt",
        .instIndex = 0, .appIDDesc = "appIDDesc", .apiVersion = DEFAULT_API_VERSION
    };
    HapPolicyParams policy = {.apl = APL_NORMAL, .domain = "domain"};
    AccessTokenID validTarget = AccessTokenKit::AllocHapToken(tgtInfo, policy).tokenIdExStruct.tokenID;
    ASSERT_NE(validTarget, INVALID_TOKENID);
    AccessTokenID nativeTarget = TestCommon::GetNativeTokenIdFromProcess("foundation");

    std::vector<AutomationControlTargetParam> targetList;
    AutomationControlTargetParam hapParam;
    hapParam.targetTokenID = validTarget;
    hapParam.status = AUTOMATION_CONTROL_ENABLED;
    targetList.emplace_back(hapParam);
    AutomationControlTargetParam nativeParam;
    nativeParam.targetTokenID = nativeTarget;
    nativeParam.status = AUTOMATION_CONTROL_ENABLED;
    targetList.emplace_back(nativeParam);

    std::vector<AutomationControlSetResult> results;
    int32_t ret = AccessTokenKit::SetAutomationControlStatus(controller, targetList, results);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(results.size(), 2u);
    EXPECT_EQ(results[0], AUTOMATION_CONTROL_SET_SUCCESS);
    EXPECT_EQ(results[1], AUTOMATION_CONTROL_SET_TOKEN_ID_NOT_EXIST);

    AccessTokenKit::DeleteToken(validTarget);
}

/**
 * @tc.name: GetAutomationControlTargets001
 * @tc.desc: Query targets for a controller with no records returns empty list.
 */
HWTEST_F(AutomationControlTest, GetAutomationControlTargets001, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller, INVALID_TOKENID);

    std::vector<AutomationControlTargetResult> results;
    int32_t ret = AccessTokenKit::GetAutomationControlTargets(controller, results);
    ASSERT_EQ(ret, RET_SUCCESS);
    EXPECT_TRUE(results.empty());
}

/**
 * @tc.name: GetAutomationControlTargets002
 * @tc.desc: Query with native token as controller returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlTest, GetAutomationControlTargets002, TestSize.Level0)
{
    AccessTokenID nativeTokenId = TestCommon::GetNativeTokenIdFromProcess("foundation");

    std::vector<AutomationControlTargetResult> results;
    int32_t ret = AccessTokenKit::GetAutomationControlTargets(nativeTokenId, results);
    ASSERT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: GetAutomationControlTargets003
 * @tc.desc: Query with non-existent controllerTokenID returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlTest, GetAutomationControlTargets003, TestSize.Level0)
{
    MockNativeToken native("foundation");

    std::vector<AutomationControlTargetResult> results;
    int32_t ret = AccessTokenKit::GetAutomationControlTargets(FAKE_TOKEN_ID, results);
    ASSERT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: GetAutomationControlControllers001
 * @tc.desc: Set ENABLED and DISABLED, verify only ENABLED controller is returned.
 */
HWTEST_F(AutomationControlTest, GetAutomationControlControllers001, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller1 = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller1, INVALID_TOKENID);

    HapInfoParams ctrl2Info = {
        .userID = TEST_USER_ID, .bundleName = "GetC001_ctrl2",
        .instIndex = 0, .appIDDesc = "appIDDesc", .apiVersion = DEFAULT_API_VERSION
    };
    HapPolicyParams policy = {.apl = APL_NORMAL, .domain = "domain"};
    AccessTokenID controller2 = AccessTokenKit::AllocHapToken(ctrl2Info, policy).tokenIdExStruct.tokenID;
    ASSERT_NE(controller2, INVALID_TOKENID);

    HapInfoParams tgtInfo = {
        .userID = TEST_USER_ID, .bundleName = "GetC001_tgt",
        .instIndex = 0, .appIDDesc = "appIDDesc", .apiVersion = DEFAULT_API_VERSION
    };
    AccessTokenID target = AccessTokenKit::AllocHapToken(tgtInfo, policy).tokenIdExStruct.tokenID;
    ASSERT_NE(target, INVALID_TOKENID);

    // controller1 sets ENABLED
    std::vector<AutomationControlTargetParam> targetList1;
    AutomationControlTargetParam param1;
    param1.targetTokenID = target;
    param1.status = AUTOMATION_CONTROL_ENABLED;
    targetList1.emplace_back(param1);
    std::vector<AutomationControlSetResult> results1;
    AccessTokenKit::SetAutomationControlStatus(controller1, targetList1, results1);

    // controller2 sets DISABLED
    std::vector<AutomationControlTargetParam> targetList2;
    AutomationControlTargetParam param2;
    param2.targetTokenID = target;
    param2.status = AUTOMATION_CONTROL_DISABLED;
    targetList2.emplace_back(param2);
    std::vector<AutomationControlSetResult> results2;
    AccessTokenKit::SetAutomationControlStatus(controller2, targetList2, results2);

    // Query controllers - should only return controller1 (ENABLED)
    std::vector<AutomationControlControllerInfo> queryResults;
    int32_t ret = AccessTokenKit::GetAutomationControlControllers(target, queryResults);
    ASSERT_EQ(ret, RET_SUCCESS);
    bool foundCaller1 = false;
    bool foundCaller2 = false;
    for (const auto& r : queryResults) {
        if (r.controllerTokenID == controller1) {
            foundCaller1 = true;
        }
        if (r.controllerTokenID == controller2) {
            foundCaller2 = true;
        }
    }
    EXPECT_TRUE(foundCaller1);
    EXPECT_FALSE(foundCaller2);

    AccessTokenKit::DeleteToken(controller2);
    AccessTokenKit::DeleteToken(target);
}

/**
 * @tc.name: GetAutomationControlControllers002
 * @tc.desc: Query controllers for a target with no records returns empty list.
 */
HWTEST_F(AutomationControlTest, GetAutomationControlControllers002, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID targetToken = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(targetToken, INVALID_TOKENID);

    std::vector<AutomationControlControllerInfo> results;
    int32_t ret = AccessTokenKit::GetAutomationControlControllers(targetToken, results);
    ASSERT_EQ(ret, RET_SUCCESS);
    EXPECT_TRUE(results.empty());
}

/**
 * @tc.name: GetAutomationControlControllers003
 * @tc.desc: Query controllers with native token as target returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlTest, GetAutomationControlControllers003, TestSize.Level0)
{
    AccessTokenID nativeTokenId = TestCommon::GetNativeTokenIdFromProcess("foundation");

    std::vector<AutomationControlControllerInfo> results;
    int32_t ret = AccessTokenKit::GetAutomationControlControllers(nativeTokenId, results);
    ASSERT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: GetAutomationControlControllers004
 * @tc.desc: Query controllers with non-existent targetTokenID returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlTest, GetAutomationControlControllers004, TestSize.Level0)
{
    MockNativeToken native("foundation");

    std::vector<AutomationControlControllerInfo> results;
    int32_t ret = AccessTokenKit::GetAutomationControlControllers(FAKE_TOKEN_ID, results);
    ASSERT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: SetAutomationControlStatus010
 * @tc.desc: Set with targetList exceeding 1024 returns ERR_PARAM_INVALID.
 */
HWTEST_F(AutomationControlTest, SetAutomationControlStatus010, TestSize.Level0)
{
    std::vector<AutomationControlTargetParam> targetList;
    AutomationControlTargetParam param;
    param.targetTokenID = FAKE_TOKEN_ID;
    param.status = AUTOMATION_CONTROL_ENABLED;
    for (int32_t i = 0; i < 1025; i++) {
        targetList.emplace_back(param);
    }
    std::vector<AutomationControlSetResult> results;
    int32_t ret = AccessTokenKit::SetAutomationControlStatus(FAKE_TOKEN_ID, targetList, results);
    ASSERT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: SetAutomationControlStatus011
 * @tc.desc: Set then delete target token, verify GetTargets no longer returns it.
 */
HWTEST_F(AutomationControlTest, SetAutomationControlStatus011, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller, INVALID_TOKENID);

    HapInfoParams tgtInfo = {
        .userID = TEST_USER_ID, .bundleName = "Set011_tgt",
        .instIndex = 0, .appIDDesc = "appIDDesc", .apiVersion = DEFAULT_API_VERSION
    };
    HapPolicyParams policy = {.apl = APL_NORMAL, .domain = "domain"};
    AccessTokenID target = AccessTokenKit::AllocHapToken(tgtInfo, policy).tokenIdExStruct.tokenID;
    ASSERT_NE(target, INVALID_TOKENID);

    std::vector<AutomationControlTargetParam> targetList;
    AutomationControlTargetParam param;
    param.targetTokenID = target;
    param.status = AUTOMATION_CONTROL_ENABLED;
    targetList.emplace_back(param);
    std::vector<AutomationControlSetResult> results;
    int32_t ret = AccessTokenKit::SetAutomationControlStatus(controller, targetList, results);
    ASSERT_EQ(ret, RET_SUCCESS);
    EXPECT_EQ(results[0], AUTOMATION_CONTROL_SET_SUCCESS);

    std::vector<AutomationControlTargetResult> queryResults;
    ret = AccessTokenKit::GetAutomationControlTargets(controller, queryResults);
    ASSERT_EQ(ret, RET_SUCCESS);
    bool found = false;
    for (const auto& r : queryResults) {
        if (r.targetTokenID == target) { found = true; break; }
    }
    EXPECT_TRUE(found);

    ret = AccessTokenKit::DeleteToken(target);
    ASSERT_EQ(ret, RET_SUCCESS);

    std::vector<AutomationControlTargetResult> queryResults2;
    ret = AccessTokenKit::GetAutomationControlTargets(controller, queryResults2);
    ASSERT_EQ(ret, RET_SUCCESS);
    bool foundAfterDelete = false;
    for (const auto& r : queryResults2) {
        if (r.targetTokenID == target) { foundAfterDelete = true; break; }
    }
    EXPECT_FALSE(foundAfterDelete);
}

/**
 * @tc.name: SetAutomationControlStatus012
 * @tc.desc: Set then delete controller token, verify GetControllers no longer returns it.
 */
HWTEST_F(AutomationControlTest, SetAutomationControlStatus012, TestSize.Level0)
{
    MockNativeToken native("foundation");

    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenID controller = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(controller, INVALID_TOKENID);

    HapInfoParams tgtInfo = {
        .userID = TEST_USER_ID, .bundleName = "Set012_tgt",
        .instIndex = 0, .appIDDesc = "appIDDesc", .apiVersion = DEFAULT_API_VERSION
    };
    HapPolicyParams policy = {.apl = APL_NORMAL, .domain = "domain"};
    AccessTokenID target = AccessTokenKit::AllocHapToken(tgtInfo, policy).tokenIdExStruct.tokenID;
    ASSERT_NE(target, INVALID_TOKENID);

    std::vector<AutomationControlTargetParam> targetList;
    AutomationControlTargetParam param;
    param.targetTokenID = target;
    param.status = AUTOMATION_CONTROL_ENABLED;
    targetList.emplace_back(param);
    std::vector<AutomationControlSetResult> results;
    int32_t ret = AccessTokenKit::SetAutomationControlStatus(controller, targetList, results);
    ASSERT_EQ(ret, RET_SUCCESS);
    EXPECT_EQ(results[0], AUTOMATION_CONTROL_SET_SUCCESS);

    std::vector<AutomationControlControllerInfo> ctrlResults;
    ret = AccessTokenKit::GetAutomationControlControllers(target, ctrlResults);
    ASSERT_EQ(ret, RET_SUCCESS);
    bool found = false;
    for (const auto& r : ctrlResults) {
        if (r.controllerTokenID == controller) { found = true; break; }
    }
    EXPECT_TRUE(found);

    ret = AccessTokenKit::DeleteToken(controller);
    ASSERT_EQ(ret, RET_SUCCESS);

    std::vector<AutomationControlControllerInfo> ctrlResults2;
    ret = AccessTokenKit::GetAutomationControlControllers(target, ctrlResults2);
    ASSERT_EQ(ret, RET_SUCCESS);
    bool foundAfterDelete = false;
    for (const auto& r : ctrlResults2) {
        if (r.controllerTokenID == controller) { foundAfterDelete = true; break; }
    }
    EXPECT_FALSE(foundAfterDelete);

    AccessTokenKit::DeleteToken(target);
}

/**
 * @tc.name: GetAutomationControlTargets004
 * @tc.desc: Query with controllerTokenID=0 returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlTest, GetAutomationControlTargets004, TestSize.Level0)
{
    std::vector<AutomationControlTargetResult> results;
    int32_t ret = AccessTokenKit::GetAutomationControlTargets(0, results);
    ASSERT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: GetAutomationControlControllers005
 * @tc.desc: Query with targetTokenID=0 returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlTest, GetAutomationControlControllers005, TestSize.Level0)
{
    std::vector<AutomationControlControllerInfo> results;
    int32_t ret = AccessTokenKit::GetAutomationControlControllers(0, results);
    ASSERT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
