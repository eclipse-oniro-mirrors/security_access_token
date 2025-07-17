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

#include "el5_filkey_manager_subscriber.h"

#include "common_event_support.h"
#include "el5_filekey_manager_log.h"
#include "el5_filekey_manager_service.h"
#include "el5_memory_manager.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr uint32_t SCREEN_ON_DELAY_TIME = 30 * 1000; // 30s
}

El5FilekeyManagerSubscriber::El5FilekeyManagerSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo)
{
}

void El5FilekeyManagerSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    auto want = data.GetWant();
    std::string action = want.GetAction();
    LOG_INFO("Receive event %{public}s.", action.c_str());
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) {
        DelayedSingleton<El5FilekeyManagerService>::GetInstance()->PostDelayedUnloadTask(SCREEN_ON_DELAY_TIME);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED) {
        El5MemoryManager::GetInstance().SetIsAllowUnloadService(false);
        // cancel unload task when screen is locked
        DelayedSingleton<El5FilekeyManagerService>::GetInstance()->CancelDelayedUnloadTask();
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
