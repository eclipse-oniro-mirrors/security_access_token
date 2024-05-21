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
#include "privacy_common_event_subscriber.h"

#include <unistd.h>
#include "accesstoken_log.h"

#include "common_event_subscribe_info.h"
#include "permission_record_manager.h"
#include "permission_used_record_cache.h"

#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
#ifdef COMMON_EVENT_SERVICE_ENABLE
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyCommonEventSubscriber"
};

static bool g_isRegistered = false;

static std::shared_ptr<PrivacyCommonEventSubscriber> g_subscriber = nullptr;
}

void PrivacyCommonEventSubscriber::RegisterEvent()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "RegisterEvent start");
    if (g_isRegistered) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "status observer already registered");
        return;
    }

    auto skill = std::make_shared<EventFwk::MatchingSkills>();
    skill->AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    skill->AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
    skill->AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    skill->AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    skill->AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    skill->AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED);
    skill->AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SHUTDOWN);
    auto info = std::make_shared<EventFwk::CommonEventSubscribeInfo>(*skill);
    g_subscriber = std::make_shared<PrivacyCommonEventSubscriber>(*info);
    const auto result = EventFwk::CommonEventManager::SubscribeCommonEvent(g_subscriber);
    if (!result) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "RegisterEvent result is err");
        return;
    }
    g_isRegistered = true;
}

void PrivacyCommonEventSubscriber::UnRegisterEvent()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "UnregisterEvent start");
    const auto result = EventFwk::CommonEventManager::UnSubscribeCommonEvent(g_subscriber);
    if (!result) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UnregisterEvent result is err");
        return;
    }
    g_isRegistered = false;
}

void PrivacyCommonEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData& event)
{
    const auto want = event.GetWant();
    const auto action = want.GetAction();
    ACCESSTOKEN_LOG_INFO(LABEL, "receive event(%{public}s)", action.c_str());
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) {
        PermissionRecordManager::GetInstance()
            .SetLockScreenStatus(LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED) {
        PermissionRecordManager::GetInstance()
            .SetLockScreenStatus(LockScreenStatusChangeType::PERM_ACTIVE_IN_LOCKED);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        PermissionRecordManager::GetInstance().ExecuteAllCameraExecuteCallback();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
        PermissionRecordManager::GetInstance().ExecuteAllCameraExecuteCallback();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED) {
        uint32_t tokenId = static_cast<uint32_t>(want.GetParams().GetIntParam("accessTokenId", 0));
        ACCESSTOKEN_LOG_INFO(LABEL, "Receive package uninstall: tokenId=%{public}d.", tokenId);
        PermissionRecordManager::GetInstance().RemovePermissionUsedRecords(tokenId, "");
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SHUTDOWN) {
        // when receive shut down power event, store the cache data to database immediately
        PermissionUsedRecordCache::GetInstance().PersistPendingRecordsImmediately();
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "action is invalid.");
    }
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS