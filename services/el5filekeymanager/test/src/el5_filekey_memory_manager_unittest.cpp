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
} // namespace

void El5FilekeyMemoryManagerTest::SetUp()
{
    el5FilekeyManagerServiceAbility_ =
        std::make_shared<El5FilekeyManagerServiceAbility>(EL5_FILEKEY_MANAGER_SERVICE_ID, false);
}

/**
 * @tc.name: MemoryManagerTest001
 * @tc.desc: test AddFunctionRuningNum and DecreaseFunctionRuningNum.
 * @tc.type: FUNC
 * @tc.require: issueICIZZE
 */
HWTEST_F(El5FilekeyMemoryManagerTest, MemoryManagerTest001, TestSize.Level1)
{
    El5MemoryManager::GetInstance().SetIsDelayedToUnload(false);
    OHOS::SystemAbilityOnDemandReason reason(OHOS::OnDemandReasonId::PARAM, "test", "true", EXTRA_PARAM);
    for (int32_t i = 0; i <= MAX_RUNNING_NUM + 1; i++) {
        El5MemoryManager::GetInstance().AddFunctionRuningNum();
    }
    EXPECT_EQ(SA_REFUSE_TO_UNLOAD, el5FilekeyManagerServiceAbility_->OnIdle(reason));
    for (int32_t i = 0; i <= MAX_RUNNING_NUM + 1; i++) {
        El5MemoryManager::GetInstance().DecreaseFunctionRuningNum();
    }
    EXPECT_EQ(SA_READY_TO_UNLOAD, el5FilekeyManagerServiceAbility_->OnIdle(reason));
}

/**
 * @tc.name: MemoryManagerTest002
 * @tc.desc: test SetIsDelayedToUnload and IsDelayedToUnload.
 * @tc.type: FUNC
 * @tc.require: issueICIZZE
 */
HWTEST_F(El5FilekeyMemoryManagerTest, MemoryManagerTest002, TestSize.Level1)
{
    El5MemoryManager::GetInstance().SetIsDelayedToUnload(true);
    OHOS::SystemAbilityOnDemandReason reason(OHOS::OnDemandReasonId::PARAM, "test", "true", EXTRA_PARAM);
    EXPECT_EQ(SA_READY_TO_UNLOAD, el5FilekeyManagerServiceAbility_->OnIdle(reason));
    El5MemoryManager::GetInstance().SetIsDelayedToUnload(false);
}
