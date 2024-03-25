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
#include "package_uninstall_observer.h"

#include "accesstoken_log.h"
#ifdef COMMON_EVENT_SERVICE_ENABLE
#include "common_event_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_support.h"
#endif // COMMON_EVENT_SERVICE_ENABLE
#include "permission_record_manager.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
#ifdef COMMON_EVENT_SERVICE_ENABLE
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PackageUninstallObserver"
};

static bool g_isRegistered = false;

static std::shared_ptr<PackageUninstallObserver> g_packageUninstallObserver = nullptr;
}

void PackageUninstallObserver::RegisterEvent()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Register Pkg Uninstall Event start.");
    if (g_isRegistered) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "Package uninstall observer already registered.");
        return;
    }

    auto skill = std::make_shared<EventFwk::MatchingSkills>();
    skill->AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    skill->AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED);
    auto info = std::make_shared<EventFwk::CommonEventSubscribeInfo>(*skill);
    g_packageUninstallObserver = std::make_shared<PackageUninstallObserver>(*info);
    const auto result = EventFwk::CommonEventManager::SubscribeCommonEvent(g_packageUninstallObserver);
    if (!result) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Registe Event failed.");
        return;
    }
    g_isRegistered = true;
}

void PackageUninstallObserver::UnRegisterEvent()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Unregist event start.");
    const auto result = EventFwk::CommonEventManager::UnSubscribeCommonEvent(g_packageUninstallObserver);
    if (!result) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Unregiste event failed.");
        return;
    }
    g_isRegistered = false;
}

void PackageUninstallObserver::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &event)
{
    const auto want = event.GetWant();
    const auto action = want.GetAction();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED) {
        uint32_t tokenId = want.GetParams().GetIntParam("accessTokenId", 0);
        if (tokenId == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Get token id failed.");
            return;
        }
        ACCESSTOKEN_LOG_INFO(LABEL, "Receive package uninstall: tokenId=%{public}d.", tokenId);
        PermissionRecordManager::GetInstance().RemovePermissionUsedRecords(tokenId, "");
    }
}
#endif // COMMON_EVENT_SERVICE_ENABLE
} // AccessToken
} // Security
} // OHOS