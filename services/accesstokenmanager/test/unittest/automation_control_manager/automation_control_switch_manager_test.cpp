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

#include <gtest/gtest.h>
#include <unistd.h>

#include "access_token.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_info_utils.h"
#include "atm_data_type.h"
#define private public
#include "automation_control_switch_manager.h"
#undef private
#include "automation_control_types.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "token_field_const.h"

#define private public
#include "accesstoken_manager_service.h"
#undef private

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace AccessToken {

static constexpr AccessTokenID FAKE_TOKEN_ID = 1234;
static constexpr AccessTokenID NON_HAP_TOKEN_ID = 0x08000001;

class AutomationControlSwitchManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp()
    {
        atManagerService_ = DelayedSingleton<AccessTokenManagerService>::GetInstance();
        ASSERT_NE(nullptr, atManagerService_);
        atManagerService_->Initialize();
    }
    void TearDown()
    {
        DelayedSingleton<AccessTokenManagerService>::DestroyInstance();
        atManagerService_ = nullptr;
    }

    std::shared_ptr<AccessTokenManagerService> atManagerService_;
};

static AccessTokenID AllocHapToken(const std::string& bundleName)
{
    HapInfoParams info = {
        .userID = 0,
        .bundleName = bundleName,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
        .apiVersion = 12
    };
    HapPolicy policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info, policy, tokenIdEx, undefValues);
    EXPECT_EQ(ret, RET_SUCCESS);
    return tokenIdEx.tokenIdExStruct.tokenID;
}

static void FreeHapToken(AccessTokenID tokenId)
{
    if (tokenId != INVALID_TOKENID) {
        AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId, false);
    }
}

static void SetStatus(uint32_t controller, uint32_t target, int32_t status)
{
    std::vector<uint32_t> targetTokenIds = {target};
    std::vector<int32_t> statusList = {status};
    std::vector<int32_t> results;
    AutomationControlSwitchManager::GetInstance().SetAutomationControlStatus(
        controller, targetTokenIds, statusList, results);
}

/**
 * @tc.name: AutomationControlSwitchManager001
 * @tc.desc: SetStatus ENABLED then GetTargets returns the pair with correct status.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager001, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr001_ctrl");
    AccessTokenID target = AllocHapToken("Mgr001_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(target, INVALID_TOKENID);

    SetStatus(controller, target, AUTOMATION_CONTROL_ENABLED);

    std::vector<uint32_t> targetTokenIds;
    std::vector<int32_t> statusList;
    std::vector<std::string> bundleNames;
    int32_t ret = AutomationControlSwitchManager::GetInstance().GetAutomationControlTargets(
        controller, targetTokenIds, statusList, bundleNames);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(targetTokenIds.size(), 1u);
    EXPECT_EQ(targetTokenIds[0], target);
    EXPECT_EQ(statusList[0], AUTOMATION_CONTROL_ENABLED);

    FreeHapToken(controller);
    FreeHapToken(target);
}

/**
 * @tc.name: AutomationControlSwitchManager002
 * @tc.desc: SetStatus DISABLED then GetTargets returns the pair with DISABLED status.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager002, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr002_ctrl");
    AccessTokenID target = AllocHapToken("Mgr002_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(target, INVALID_TOKENID);

    SetStatus(controller, target, AUTOMATION_CONTROL_DISABLED);

    std::vector<uint32_t> targetTokenIds;
    std::vector<int32_t> statusList;
    std::vector<std::string> bundleNames;
    int32_t ret = AutomationControlSwitchManager::GetInstance().GetAutomationControlTargets(
        controller, targetTokenIds, statusList, bundleNames);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(targetTokenIds.size(), 1u);
    EXPECT_EQ(statusList[0], AUTOMATION_CONTROL_DISABLED);

    FreeHapToken(controller);
    FreeHapToken(target);
}

/**
 * @tc.name: AutomationControlSwitchManager003
 * @tc.desc: Set ENABLED then GetControllers returns only ENABLED controller.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager003, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr003_ctrl");
    AccessTokenID target = AllocHapToken("Mgr003_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(target, INVALID_TOKENID);

    SetStatus(controller, target, AUTOMATION_CONTROL_ENABLED);

    std::vector<uint32_t> controllerTokenIds;
    std::vector<std::string> bundleNames;
    int32_t ret = AutomationControlSwitchManager::GetInstance().GetAutomationControlControllers(
        target, controllerTokenIds, bundleNames);
    ASSERT_EQ(ret, RET_SUCCESS);
    bool found = false;
    for (auto id : controllerTokenIds) {
        if (id == controller) { found = true; break; }
    }
    EXPECT_TRUE(found);

    FreeHapToken(controller);
    FreeHapToken(target);
}

/**
 * @tc.name: AutomationControlSwitchManager004
 * @tc.desc: Set DISABLED then GetControllers does NOT return the controller.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager004, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr004_ctrl");
    AccessTokenID target = AllocHapToken("Mgr004_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(target, INVALID_TOKENID);

    SetStatus(controller, target, AUTOMATION_CONTROL_DISABLED);

    std::vector<uint32_t> controllerTokenIds;
    std::vector<std::string> bundleNames;
    int32_t ret = AutomationControlSwitchManager::GetInstance().GetAutomationControlControllers(
        target, controllerTokenIds, bundleNames);
    ASSERT_EQ(ret, RET_SUCCESS);
    bool found = false;
    for (auto id : controllerTokenIds) {
        if (id == controller) { found = true; break; }
    }
    EXPECT_FALSE(found);

    FreeHapToken(controller);
    FreeHapToken(target);
}

/**
 * @tc.name: AutomationControlSwitchManager005
 * @tc.desc: ClearByTokenId as controller removes records, GetTargets returns empty.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager005, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr005_ctrl");
    AccessTokenID target = AllocHapToken("Mgr005_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(target, INVALID_TOKENID);

    SetStatus(controller, target, AUTOMATION_CONTROL_ENABLED);

    std::vector<uint32_t> ids;
    std::vector<int32_t> status;
    std::vector<std::string> names;
    AutomationControlSwitchManager::GetInstance().GetAutomationControlTargets(controller, ids, status, names);
    ASSERT_FALSE(ids.empty());

    // Delete DB records: controller dimension
    GenericValues delCond;
    delCond.Put(TokenFiledConst::FIELD_AUTOMATION_SOURCE_TOKEN_ID, static_cast<int32_t>(controller));
    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateDelInfoToVec(
        AtmDataType::ACCESSTOKEN_CONTROL_SWITCH, delCond, delInfoVec);
    AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, {});

    AutomationControlSwitchManager::GetInstance().ClearByTokenId(controller);

    std::vector<uint32_t> ids2;
    std::vector<int32_t> status2;
    std::vector<std::string> names2;
    int32_t ret = AutomationControlSwitchManager::GetInstance().GetAutomationControlTargets(
        controller, ids2, status2, names2);
    ASSERT_EQ(ret, RET_SUCCESS);
    EXPECT_TRUE(ids2.empty());

    FreeHapToken(controller);
    FreeHapToken(target);
}

/**
 * @tc.name: AutomationControlSwitchManager006
 * @tc.desc: ClearByTokenId as target removes records, GetControllers returns empty.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager006, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr006_ctrl");
    AccessTokenID target = AllocHapToken("Mgr006_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(target, INVALID_TOKENID);

    SetStatus(controller, target, AUTOMATION_CONTROL_ENABLED);

    std::vector<uint32_t> ctrlIds;
    std::vector<std::string> names;
    AutomationControlSwitchManager::GetInstance().GetAutomationControlControllers(target, ctrlIds, names);
    ASSERT_FALSE(ctrlIds.empty());

    // Delete DB records: target dimension
    GenericValues delCond;
    delCond.Put(TokenFiledConst::FIELD_AUTOMATION_TARGET_TOKEN_ID, static_cast<int32_t>(target));
    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateDelInfoToVec(
        AtmDataType::ACCESSTOKEN_CONTROL_SWITCH, delCond, delInfoVec);
    AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, {});

    AutomationControlSwitchManager::GetInstance().ClearByTokenId(target);

    std::vector<uint32_t> ctrlIds2;
    std::vector<std::string> names2;
    int32_t ret = AutomationControlSwitchManager::GetInstance().GetAutomationControlControllers(
        target, ctrlIds2, names2);
    ASSERT_EQ(ret, RET_SUCCESS);
    EXPECT_TRUE(ctrlIds2.empty());

    FreeHapToken(controller);
    FreeHapToken(target);
}

/**
 * @tc.name: AutomationControlSwitchManager007
 * @tc.desc: CheckAccess for unset target returns POPUP_NEEDED.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager007, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr007_ctrl");
    AccessTokenID target = AllocHapToken("Mgr007_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(target, INVALID_TOKENID);

    std::vector<uint32_t> targetList = {target};
    std::vector<int32_t> decisions;
    int32_t ret = AutomationControlSwitchManager::GetInstance().CheckAccess(
        controller, targetList, decisions);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(decisions.size(), 1u);
    EXPECT_EQ(decisions[0], static_cast<int32_t>(POPUP_NEEDED));

    FreeHapToken(controller);
    FreeHapToken(target);
}

/**
 * @tc.name: AutomationControlSwitchManager008
 * @tc.desc: CheckAccess after set ENABLED returns NO_POPUP_NEEDED_GRANTED.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager008, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr008_ctrl");
    AccessTokenID target = AllocHapToken("Mgr008_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(target, INVALID_TOKENID);

    SetStatus(controller, target, AUTOMATION_CONTROL_ENABLED);

    std::vector<uint32_t> targetList = {target};
    std::vector<int32_t> decisions;
    int32_t ret = AutomationControlSwitchManager::GetInstance().CheckAccess(
        controller, targetList, decisions);
    ASSERT_EQ(ret, RET_SUCCESS);
    EXPECT_EQ(decisions[0], static_cast<int32_t>(NO_POPUP_NEEDED_GRANTED));

    FreeHapToken(controller);
    FreeHapToken(target);
}

/**
 * @tc.name: AutomationControlSwitchManager009
 * @tc.desc: CheckAccess after set DISABLED returns NO_POPUP_NEEDED_DENIED.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager009, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr009_ctrl");
    AccessTokenID target = AllocHapToken("Mgr009_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(target, INVALID_TOKENID);

    SetStatus(controller, target, AUTOMATION_CONTROL_DISABLED);

    std::vector<uint32_t> targetList = {target};
    std::vector<int32_t> decisions;
    int32_t ret = AutomationControlSwitchManager::GetInstance().CheckAccess(
        controller, targetList, decisions);
    ASSERT_EQ(ret, RET_SUCCESS);
    EXPECT_EQ(decisions[0], static_cast<int32_t>(NO_POPUP_NEEDED_DENIED));

    FreeHapToken(controller);
    FreeHapToken(target);
}

/**
 * @tc.name: AutomationControlSwitchManager010
 * @tc.desc: GetTargets skips entries whose HapTokenInfo cannot be obtained.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager010, TestSize.Level0)
{
    auto& mgr = AutomationControlSwitchManager::GetInstance();
    AccessTokenID controller = AllocHapToken("Mgr010_ctrl");
    ASSERT_NE(controller, INVALID_TOKENID);

    AccessTokenID fakeTarget = FAKE_TOKEN_ID;
    {
        std::lock_guard<std::mutex> lock(mgr.switchCacheMutex_);
        mgr.switchCache_[controller][fakeTarget] = 1;
    }

    std::vector<uint32_t> targetTokenIds;
    std::vector<int32_t> statusList;
    std::vector<std::string> bundleNames;
    int32_t ret = mgr.GetAutomationControlTargets(controller, targetTokenIds, statusList, bundleNames);
    ASSERT_EQ(ret, RET_SUCCESS);
    bool foundFake = false;
    for (auto id : targetTokenIds) {
        if (id == fakeTarget) { foundFake = true; break; }
    }
    EXPECT_FALSE(foundFake);

    {
        std::lock_guard<std::mutex> lock(mgr.switchCacheMutex_);
        mgr.switchCache_[controller].erase(fakeTarget);
    }
    FreeHapToken(controller);
}

/**
 * @tc.name: AutomationControlSwitchManager011
 * @tc.desc: GetControllers skips entries whose HapTokenInfo cannot be obtained.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager011, TestSize.Level0)
{
    auto& mgr = AutomationControlSwitchManager::GetInstance();
    AccessTokenID target = AllocHapToken("Mgr011_target");
    ASSERT_NE(target, INVALID_TOKENID);

    AccessTokenID fakeController = FAKE_TOKEN_ID;

    // Write a DB record with an unregistered controller (HapTokenInfo unavailable)
    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_AUTOMATION_SOURCE_TOKEN_ID, static_cast<int32_t>(fakeController));
    addValue.Put(TokenFiledConst::FIELD_AUTOMATION_TARGET_TOKEN_ID, static_cast<int32_t>(target));
    addValue.Put(TokenFiledConst::FIELD_AUTOMATION_STATUS, AUTOMATION_CONTROL_ENABLED);
    addValue.Put(TokenFiledConst::FIELD_AUTOMATION_TIMESTAMP, 0);
    std::vector<GenericValues> addValues;
    addValues.emplace_back(addValue);
    std::vector<AddInfo> addInfoVec;
    AccessTokenInfoUtils::GenerateAddInfoToVec(
        AtmDataType::ACCESSTOKEN_CONTROL_SWITCH, addValues, addInfoVec);
    AccessTokenDbOperator::DeleteAndInsertValues({}, addInfoVec);

    std::vector<uint32_t> controllerTokenIds;
    std::vector<std::string> bundleNames;
    int32_t ret = mgr.GetAutomationControlControllers(target, controllerTokenIds, bundleNames);
    ASSERT_EQ(ret, RET_SUCCESS);
    bool foundFake = false;
    for (auto id : controllerTokenIds) {
        if (id == fakeController) { foundFake = true; break; }
    }
    EXPECT_FALSE(foundFake);

    // Cleanup: delete the DB record
    GenericValues delCond;
    delCond.Put(TokenFiledConst::FIELD_AUTOMATION_SOURCE_TOKEN_ID, static_cast<int32_t>(fakeController));
    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateDelInfoToVec(
        AtmDataType::ACCESSTOKEN_CONTROL_SWITCH, delCond, delInfoVec);
    AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, {});

    FreeHapToken(target);
}

/**
 * @tc.name: AutomationControlSwitchManager012
 * @tc.desc: SetStatus ENABLED then verify DB record has correct status and timestamp.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager012, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr012_ctrl");
    AccessTokenID target = AllocHapToken("Mgr012_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(target, INVALID_TOKENID);

    SetStatus(controller, target, AUTOMATION_CONTROL_ENABLED);

    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_AUTOMATION_SOURCE_TOKEN_ID,
        static_cast<int32_t>(controller));
    condition.Put(TokenFiledConst::FIELD_AUTOMATION_TARGET_TOKEN_ID,
        static_cast<int32_t>(target));
    std::vector<GenericValues> dbResults;
    int32_t dbRet = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_CONTROL_SWITCH, condition, dbResults);
    ASSERT_EQ(dbRet, RET_SUCCESS);
    ASSERT_EQ(dbResults.size(), 1u);
    EXPECT_EQ(static_cast<int32_t>(dbResults[0].Get(
        TokenFiledConst::FIELD_AUTOMATION_STATUS).GetInt64()), 1);
    EXPECT_GT(static_cast<int64_t>(dbResults[0].Get(
        TokenFiledConst::FIELD_AUTOMATION_TIMESTAMP).GetInt64()), 0);

    FreeHapToken(controller);
    FreeHapToken(target);
}

/**
 * @tc.name: AutomationControlSwitchManager013
 * @tc.desc: SetStatus DISABLED then verify DB record updated to status=0.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager013, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr013_ctrl");
    AccessTokenID target = AllocHapToken("Mgr013_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(target, INVALID_TOKENID);

    SetStatus(controller, target, AUTOMATION_CONTROL_ENABLED);
    SetStatus(controller, target, AUTOMATION_CONTROL_DISABLED);

    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_AUTOMATION_SOURCE_TOKEN_ID,
        static_cast<int32_t>(controller));
    condition.Put(TokenFiledConst::FIELD_AUTOMATION_TARGET_TOKEN_ID,
        static_cast<int32_t>(target));
    std::vector<GenericValues> dbResults;
    int32_t dbRet = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_CONTROL_SWITCH, condition, dbResults);
    ASSERT_EQ(dbRet, RET_SUCCESS);
    ASSERT_EQ(dbResults.size(), 1u);
    EXPECT_EQ(static_cast<int32_t>(dbResults[0].Get(
        TokenFiledConst::FIELD_AUTOMATION_STATUS).GetInt64()), 0);

    FreeHapToken(controller);
    FreeHapToken(target);
}

/**
 * @tc.name: AutomationControlSwitchManager014
 * @tc.desc: RemoveHapTokenInfo removes DB records (merged in transaction), verify Find returns empty.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager014, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr014_ctrl");
    AccessTokenID target = AllocHapToken("Mgr014_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(target, INVALID_TOKENID);

    SetStatus(controller, target, AUTOMATION_CONTROL_ENABLED);

    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_AUTOMATION_SOURCE_TOKEN_ID,
        static_cast<int32_t>(controller));
    std::vector<GenericValues> dbBefore;
    AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_CONTROL_SWITCH, condition, dbBefore);
    ASSERT_FALSE(dbBefore.empty());

    AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(controller, false);

    std::vector<GenericValues> dbAfter;
    int32_t dbRet = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_CONTROL_SWITCH, condition, dbAfter);
    ASSERT_EQ(dbRet, RET_SUCCESS);
    EXPECT_TRUE(dbAfter.empty());

    FreeHapToken(target);
}

/**
 * @tc.name: AutomationControlSwitchManager015
 * @tc.desc: Set with non-HAP target returns INVALID_TOKEN_ID and writes no DB record.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager015, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr015_ctrl");
    ASSERT_NE(controller, INVALID_TOKENID);

    std::vector<uint32_t> targetTokenIds = {NON_HAP_TOKEN_ID};
    std::vector<int32_t> statusList = {AUTOMATION_CONTROL_ENABLED};
    std::vector<int32_t> results;
    int32_t ret = AutomationControlSwitchManager::GetInstance().SetAutomationControlStatus(
        controller, targetTokenIds, statusList, results);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0], static_cast<int32_t>(AUTOMATION_CONTROL_SET_TOKEN_ID_NOT_EXIST));

    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_AUTOMATION_TARGET_TOKEN_ID,
        static_cast<int32_t>(NON_HAP_TOKEN_ID));
    std::vector<GenericValues> dbResults;
    AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_CONTROL_SWITCH, condition, dbResults);
    EXPECT_TRUE(dbResults.empty());

    FreeHapToken(controller);
}

/**
 * @tc.name: AutomationControlSwitchManager016
 * @tc.desc: Set with mixed HAP and non-HAP targets returns per-element SUCCESS and INVALID_TOKEN_ID.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager016, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr016_ctrl");
    AccessTokenID validTarget = AllocHapToken("Mgr016_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(validTarget, INVALID_TOKENID);

    std::vector<uint32_t> targetTokenIds = {validTarget, NON_HAP_TOKEN_ID};
    std::vector<int32_t> statusList = {AUTOMATION_CONTROL_ENABLED, AUTOMATION_CONTROL_ENABLED};
    std::vector<int32_t> results;
    int32_t ret = AutomationControlSwitchManager::GetInstance().SetAutomationControlStatus(
        controller, targetTokenIds, statusList, results);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(results.size(), 2u);
    EXPECT_EQ(results[0], static_cast<int32_t>(AUTOMATION_CONTROL_SET_SUCCESS));
    EXPECT_EQ(results[1], static_cast<int32_t>(AUTOMATION_CONTROL_SET_TOKEN_ID_NOT_EXIST));

    FreeHapToken(controller);
    FreeHapToken(validTarget);
}

/**
 * @tc.name: AutomationControlSwitchManager017
 * @tc.desc: CheckAccess with non-HAP target returns INVALID_TOKEN_ID.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager017, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr017_ctrl");
    ASSERT_NE(controller, INVALID_TOKENID);

    std::vector<uint32_t> targetList = {NON_HAP_TOKEN_ID};
    std::vector<int32_t> decisions;
    int32_t ret = AutomationControlSwitchManager::GetInstance().CheckAccess(
        controller, targetList, decisions);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(decisions.size(), 1u);
    EXPECT_EQ(decisions[0], static_cast<int32_t>(TARGET_NOT_EXIST));

    FreeHapToken(controller);
}

/**
 * @tc.name: AutomationControlSwitchManager018
 * @tc.desc: CheckAccess with mixed HAP and non-HAP targets returns per-element POPUP_NEEDED and INVALID_TOKEN_ID.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager018, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr018_ctrl");
    AccessTokenID validTarget = AllocHapToken("Mgr018_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(validTarget, INVALID_TOKENID);

    std::vector<uint32_t> targetList = {validTarget, NON_HAP_TOKEN_ID};
    std::vector<int32_t> decisions;
    int32_t ret = AutomationControlSwitchManager::GetInstance().CheckAccess(
        controller, targetList, decisions);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(decisions.size(), 2u);
    EXPECT_EQ(decisions[0], static_cast<int32_t>(POPUP_NEEDED));
    EXPECT_EQ(decisions[1], static_cast<int32_t>(TARGET_NOT_EXIST));

    FreeHapToken(controller);
    FreeHapToken(validTarget);
}

// --- Manager boundary tests (019-030) ---

/**
 * @tc.name: AutomationControlSwitchManager019
 * @tc.desc: Set with controllerTokenId=0 returns ERR_PARAM_INVALID.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager019, TestSize.Level0)
{
    std::vector<uint32_t> targetTokenIds = {FAKE_TOKEN_ID};
    std::vector<int32_t> statusList = {AUTOMATION_CONTROL_ENABLED};
    std::vector<int32_t> results;
    int32_t ret = AutomationControlSwitchManager::GetInstance().SetAutomationControlStatus(
        0, targetTokenIds, statusList, results);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: AutomationControlSwitchManager020
 * @tc.desc: Set with empty targetList returns ERR_PARAM_INVALID.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager020, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr020_ctrl");
    ASSERT_NE(controller, INVALID_TOKENID);

    std::vector<uint32_t> targetTokenIds;
    std::vector<int32_t> statusList;
    std::vector<int32_t> results;
    int32_t ret = AutomationControlSwitchManager::GetInstance().SetAutomationControlStatus(
        controller, targetTokenIds, statusList, results);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);

    FreeHapToken(controller);
}

/**
 * @tc.name: AutomationControlSwitchManager021
 * @tc.desc: Set with targetList exceeding 1024 returns ERR_PARAM_INVALID.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager021, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr021_ctrl");
    ASSERT_NE(controller, INVALID_TOKENID);

    std::vector<uint32_t> targetTokenIds(1025, FAKE_TOKEN_ID);
    std::vector<int32_t> statusList(1025, AUTOMATION_CONTROL_ENABLED);
    std::vector<int32_t> results;
    int32_t ret = AutomationControlSwitchManager::GetInstance().SetAutomationControlStatus(
        controller, targetTokenIds, statusList, results);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);

    FreeHapToken(controller);
}

/**
 * @tc.name: AutomationControlSwitchManager022
 * @tc.desc: Set with non-HAP controller returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager022, TestSize.Level0)
{
    std::vector<uint32_t> targetTokenIds = {FAKE_TOKEN_ID};
    std::vector<int32_t> statusList = {AUTOMATION_CONTROL_ENABLED};
    std::vector<int32_t> results;
    int32_t ret = AutomationControlSwitchManager::GetInstance().SetAutomationControlStatus(
        NON_HAP_TOKEN_ID, targetTokenIds, statusList, results);
    EXPECT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: AutomationControlSwitchManager023
 * @tc.desc: GetTargets with controllerTokenId=0 returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager023, TestSize.Level0)
{
    std::vector<uint32_t> targetTokenIds;
    std::vector<int32_t> statusList;
    std::vector<std::string> bundleNames;
    int32_t ret = AutomationControlSwitchManager::GetInstance().GetAutomationControlTargets(
        0, targetTokenIds, statusList, bundleNames);
    EXPECT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: AutomationControlSwitchManager024
 * @tc.desc: GetTargets with non-HAP controller returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager024, TestSize.Level0)
{
    std::vector<uint32_t> targetTokenIds;
    std::vector<int32_t> statusList;
    std::vector<std::string> bundleNames;
    int32_t ret = AutomationControlSwitchManager::GetInstance().GetAutomationControlTargets(
        NON_HAP_TOKEN_ID, targetTokenIds, statusList, bundleNames);
    EXPECT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: AutomationControlSwitchManager025
 * @tc.desc: GetControllers with targetTokenId=0 returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager025, TestSize.Level0)
{
    std::vector<uint32_t> controllerTokenIds;
    std::vector<std::string> bundleNames;
    int32_t ret = AutomationControlSwitchManager::GetInstance().GetAutomationControlControllers(
        0, controllerTokenIds, bundleNames);
    EXPECT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: AutomationControlSwitchManager026
 * @tc.desc: GetControllers with non-HAP target returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager026, TestSize.Level0)
{
    std::vector<uint32_t> controllerTokenIds;
    std::vector<std::string> bundleNames;
    int32_t ret = AutomationControlSwitchManager::GetInstance().GetAutomationControlControllers(
        NON_HAP_TOKEN_ID, controllerTokenIds, bundleNames);
    EXPECT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: AutomationControlSwitchManager027
 * @tc.desc: Check with controllerTokenId=0 returns ERR_PARAM_INVALID.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager027, TestSize.Level0)
{
    std::vector<uint32_t> targetList = {FAKE_TOKEN_ID};
    std::vector<int32_t> decisions;
    int32_t ret = AutomationControlSwitchManager::GetInstance().CheckAccess(
        0, targetList, decisions);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.name: AutomationControlSwitchManager028
 * @tc.desc: Check with empty targetList returns ERR_PARAM_INVALID.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager028, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr028_ctrl");
    ASSERT_NE(controller, INVALID_TOKENID);

    std::vector<uint32_t> targetList;
    std::vector<int32_t> decisions;
    int32_t ret = AutomationControlSwitchManager::GetInstance().CheckAccess(
        controller, targetList, decisions);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);

    FreeHapToken(controller);
}

/**
 * @tc.name: AutomationControlSwitchManager029
 * @tc.desc: Check with targetList exceeding 1024 returns ERR_PARAM_INVALID.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager029, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr029_ctrl");
    ASSERT_NE(controller, INVALID_TOKENID);

    std::vector<uint32_t> targetList(1025, FAKE_TOKEN_ID);
    std::vector<int32_t> decisions;
    int32_t ret = AutomationControlSwitchManager::GetInstance().CheckAccess(
        controller, targetList, decisions);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);

    FreeHapToken(controller);
}

/**
 * @tc.name: AutomationControlSwitchManager030
 * @tc.desc: Check with non-HAP controller returns ERR_TOKENID_NOT_EXIST.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager030, TestSize.Level0)
{
    std::vector<uint32_t> targetList = {FAKE_TOKEN_ID};
    std::vector<int32_t> decisions;
    int32_t ret = AutomationControlSwitchManager::GetInstance().CheckAccess(
        NON_HAP_TOKEN_ID, targetList, decisions);
    EXPECT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

/**
 * @tc.name: AutomationControlSwitchManager031
 * @tc.desc: Set with mismatched targetTokenIds and statusList size returns ERR_PARAM_INVALID.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager031, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr031_ctrl");
    ASSERT_NE(controller, INVALID_TOKENID);

    std::vector<uint32_t> targetTokenIds = {FAKE_TOKEN_ID};
    std::vector<int32_t> statusList;
    std::vector<int32_t> results;
    int32_t ret = AutomationControlSwitchManager::GetInstance().SetAutomationControlStatus(
        controller, targetTokenIds, statusList, results);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);

    FreeHapToken(controller);
}

/**
 * @tc.name: AutomationControlSwitchManager032
 * @tc.desc: Set with invalid status value returns ERR_PARAM_INVALID.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager032, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr032_ctrl");
    ASSERT_NE(controller, INVALID_TOKENID);

    std::vector<uint32_t> targetTokenIds = {FAKE_TOKEN_ID};
    std::vector<int32_t> statusList = {2};  // invalid status
    std::vector<int32_t> results;
    int32_t ret = AutomationControlSwitchManager::GetInstance().SetAutomationControlStatus(
        controller, targetTokenIds, statusList, results);
    EXPECT_EQ(ret, AccessTokenError::ERR_PARAM_INVALID);

    FreeHapToken(controller);
}

/**
 * @tc.name: AutomationControlSwitchManager033
 * @tc.desc: GetTargets filters out RESERVED target, restores on ACTIVE.
 */
HWTEST_F(AutomationControlSwitchManagerTest, AutomationControlSwitchManager033, TestSize.Level0)
{
    AccessTokenID controller = AllocHapToken("Mgr033_ctrl");
    AccessTokenID target = AllocHapToken("Mgr033_target");
    ASSERT_NE(controller, INVALID_TOKENID);
    ASSERT_NE(target, INVALID_TOKENID);

    SetStatus(controller, target, AUTOMATION_CONTROL_ENABLED);

    // ACTIVE: GetTargets returns target
    std::vector<uint32_t> ids;
    std::vector<int32_t> status;
    std::vector<std::string> names;
    AutomationControlSwitchManager::GetInstance().GetAutomationControlTargets(
        controller, ids, status, names);
    EXPECT_FALSE(ids.empty());

    // Mark target as RESERVED
    AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(target, TokenIdStatus::RESERVED);

    // RESERVED: GetTargets filters out target
    std::vector<uint32_t> ids2;
    std::vector<int32_t> status2;
    std::vector<std::string> names2;
    int32_t ret = AutomationControlSwitchManager::GetInstance().GetAutomationControlTargets(
        controller, ids2, status2, names2);
    EXPECT_EQ(ret, RET_SUCCESS);
    EXPECT_TRUE(ids2.empty());

    // Restore target to ACTIVE
    AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(target, TokenIdStatus::ACTIVE);

    // ACTIVE restored: GetTargets returns target again
    std::vector<uint32_t> ids3;
    std::vector<int32_t> status3;
    std::vector<std::string> names3;
    AutomationControlSwitchManager::GetInstance().GetAutomationControlTargets(
        controller, ids3, status3, names3);
    EXPECT_FALSE(ids3.empty());

    FreeHapToken(controller);
    FreeHapToken(target);
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
