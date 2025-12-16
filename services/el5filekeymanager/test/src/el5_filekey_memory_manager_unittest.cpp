/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "el5_filekey_memory_manager_unittest.h"

#include "el5_memory_manager.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
namespace {
constexpr int32_t MAX_RUNNING_NUM = 256;
constexpr int64_t EXTRA_PARAM = 3;
constexpr int32_t SA_READY_TO_UNLOAD = 0;
constexpr int32_t SA_REFUSE_TO_UNLOAD = -1;
const std::string LOW_MEMORY_PARAM = "resourceschedule.memmgr.low.memory.prepare";
} // namespace

void El5FilekeyMemoryManagerTest::SetUp()
{
    el5FilekeyManagerServiceAbility_ =
        std::make_shared<El5FilekeyManagerServiceAbility>(EL5_FILEKEY_MANAGER_SERVICE_ID, false);
}

/**
 * @tc.name: MemoryManagerTest001
 * @tc.desc: test OnIdle
 * @tc.type: FUNC
 * @tc.require: issueICIZZE
 */
HWTEST_F(El5FilekeyMemoryManagerTest, MemoryManagerTest001, TestSize.Level1)
{
    OHOS::SystemAbilityOnDemandReason reason1(OHOS::OnDemandReasonId::PARAM, "test", "true", EXTRA_PARAM);
    EXPECT_EQ(SA_READY_TO_UNLOAD, el5FilekeyManagerServiceAbility_->OnIdle(reason1));

    El5MemoryManager::GetInstance().SetIsAllowUnloadService(false);
    OHOS::SystemAbilityOnDemandReason reason2(OHOS::OnDemandReasonId::PARAM, LOW_MEMORY_PARAM, "true", EXTRA_PARAM);
    EXPECT_EQ(SA_REFUSE_TO_UNLOAD, el5FilekeyManagerServiceAbility_->OnIdle(reason2));

    for (int32_t i = 0; i <= MAX_RUNNING_NUM + 1; i++) {
        El5MemoryManager::GetInstance().AddFunctionRuningNum();
    }
    EXPECT_EQ(SA_REFUSE_TO_UNLOAD, el5FilekeyManagerServiceAbility_->OnIdle(reason2));

    El5MemoryManager::GetInstance().SetIsAllowUnloadService(true);
    EXPECT_EQ(SA_REFUSE_TO_UNLOAD, el5FilekeyManagerServiceAbility_->OnIdle(reason2));

    for (int32_t i = 0; i <= MAX_RUNNING_NUM + 1; i++) {
        El5MemoryManager::GetInstance().DecreaseFunctionRuningNum();
    }
    EXPECT_EQ(SA_READY_TO_UNLOAD, el5FilekeyManagerServiceAbility_->OnIdle(reason2));
}

/**
 * @tc.name: Onstart001
 * @tc.desc: test onStart
 * @tc.type: FUNC
 * @tc.require: issueICIZZE
 */
HWTEST_F(El5FilekeyMemoryManagerTest, Onstart001, TestSize.Level1)
{
    OHOS::SystemAbilityOnDemandReason reason1(OHOS::OnDemandReasonId::PARAM, "usual.event.SCREEN_LOCKED",
        "true", EXTRA_PARAM);
    el5FilekeyManagerServiceAbility_->service_ = nullptr;
    el5FilekeyManagerServiceAbility_->OnStop();
    el5FilekeyManagerServiceAbility_->OnAddSystemAbility(1, "test");
    el5FilekeyManagerServiceAbility_->OnStart(reason1);
    EXPECT_NE(el5FilekeyManagerServiceAbility_->service_, nullptr);

    el5FilekeyManagerServiceAbility_->OnStart(reason1);
    EXPECT_NE(el5FilekeyManagerServiceAbility_->service_, nullptr);
    el5FilekeyManagerServiceAbility_->OnStop();
    el5FilekeyManagerServiceAbility_->OnAddSystemAbility(1, "test");
    el5FilekeyManagerServiceAbility_->service_ = nullptr;
    reason1.SetName("usual.event.USER_REMOVED");
    el5FilekeyManagerServiceAbility_->OnStart(reason1);
    EXPECT_NE(el5FilekeyManagerServiceAbility_->service_, nullptr);

    el5FilekeyManagerServiceAbility_->service_ = nullptr;
    reason1.SetName("usual.event.USER_STOPPED");
    el5FilekeyManagerServiceAbility_->OnStart(reason1);
    EXPECT_NE(el5FilekeyManagerServiceAbility_->service_, nullptr);

    el5FilekeyManagerServiceAbility_->service_ = nullptr;
    reason1.SetName("usual.event.USER_REMOVED");
    el5FilekeyManagerServiceAbility_->OnStart(reason1);
    EXPECT_NE(el5FilekeyManagerServiceAbility_->service_, nullptr);
    
    reason1.SetValue("1");
    el5FilekeyManagerServiceAbility_->service_ = nullptr;
    el5FilekeyManagerServiceAbility_->OnStart(reason1);
    EXPECT_NE(el5FilekeyManagerServiceAbility_->service_, nullptr);
}
