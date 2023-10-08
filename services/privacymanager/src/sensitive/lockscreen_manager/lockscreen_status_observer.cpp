/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "lockscreen_status_observer.h"

#include <map>
#include <string>

#include <unistd.h>
#include "accesstoken_log.h"

#include "common_event_subscribe_info.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "permission_record_manager.h"

#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "LockScreenStatusObserver"
};
static std::map<std::string, LockScreenStatusChangeType> g_actionMap = {
    {EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED, LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED},
    {EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED, LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED},
};
static bool g_isRegistered = false;
}

void LockscreenObserver::RegisterEvent()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "RegisterEvent start");
    if (g_isRegistered) {
        return;
    }

    auto skill = std::make_shared<EventFwk::MatchingSkills>();
    for (const auto &actionPair : g_actionMap) {
        skill->AddEvent(actionPair.first);
    }
    auto info = std::make_shared<EventFwk::CommonEventSubscribeInfo>(*skill);
    auto hub = std::make_shared<LockscreenObserver>(*info);
    const auto result = EventFwk::CommonEventManager::SubscribeCommonEvent(hub);
    if (!result) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "RegisterEvent result is err");
        return;
    }
    g_isRegistered = true;
}

void LockscreenObserver::UnRegisterEvent()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "UnregisterEvent start");
    auto skill = std::make_shared<EventFwk::MatchingSkills>();
    for (const auto &actionPair : g_actionMap) {
        skill->AddEvent(actionPair.first);
    }
    auto info = std::make_shared<EventFwk::CommonEventSubscribeInfo>(*skill);
    auto hub = std::make_shared<LockscreenObserver>(*info);
    const auto result = EventFwk::CommonEventManager::UnSubscribeCommonEvent(hub);
    if (!result) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UnregisterEvent result is err");
        return;
    }
    g_isRegistered = false;
}

void LockscreenObserver::OnReceiveEvent(const EventFwk::CommonEventData& event)
{
    const auto want = event.GetWant();
    const auto action = want.GetAction();
    if (g_actionMap.find(action) == g_actionMap.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "no event found");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "OnReceiveEvent action:%{public}d", g_actionMap[action]);
    PermissionRecordManager::GetInstance().NotifyLockScreenStatusChange(g_actionMap[action]);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS