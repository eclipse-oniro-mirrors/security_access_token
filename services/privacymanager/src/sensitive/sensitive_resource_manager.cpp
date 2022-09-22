/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "sensitive_resource_manager.h"
#include <semaphore.h>
#include "accesstoken_log.h"
#include "active_change_response_info.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "SensitiveResourceManager"
};
static const size_t MAX_CALLBACK_SIZE = 200;
}

SensitiveResourceManager& SensitiveResourceManager::GetInstance()
{
    static SensitiveResourceManager instance;
    return instance;
}

SensitiveResourceManager::SensitiveResourceManager()
{
}

SensitiveResourceManager::~SensitiveResourceManager()
{
}

bool SensitiveResourceManager::InitProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);

    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbilityManager is null");
        return false;
    }

    sptr<IRemoteObject> object = systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (object == nullptr) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "GetSystemAbility %{public}d is null", APP_MGR_SERVICE_ID);
        return false;
    }

    appMgrProxy_ = iface_cast<AppExecFwk::IAppMgr>(object);
    if (appMgrProxy_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "iface_cast get null");
        return false;
    }

    return true;
}

OHOS::sptr<OHOS::AppExecFwk::IAppMgr> SensitiveResourceManager::GetAppManagerProxy()
{
    if (appMgrProxy_ == nullptr) {
        if (!InitProxy()) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "InitProxy failed");
            return nullptr;
        }
    }

    return appMgrProxy_;
}

bool SensitiveResourceManager::GetAppStatus(const std::string& pkgName, int32_t& status)
{
    auto appMgrProxy = GetAppManagerProxy();
    if (appMgrProxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetAppManagerProxy failed");
        return false;
    }

    std::vector<AppExecFwk::AppStateData> foreGroundAppList;
    appMgrProxy->GetForegroundApplications(foreGroundAppList);

    status = PERM_ACTIVE_IN_BACKGROUND;
    if (std::any_of(foreGroundAppList.begin(), foreGroundAppList.end(),
        [pkgName](const auto& foreGroundApp) { return foreGroundApp.bundleName == pkgName; })) {
        status = PERM_ACTIVE_IN_FOREGROUND;       
    }
    return true;
}

bool SensitiveResourceManager::RegisterAppStatusChangeCallback(uint32_t tokenId, OnAppStatusChangeCallback callback)
{
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback could not be null.");
        return false;
    }
    
    std::lock_guard<std::mutex> lock(appStatusMutex_);
    auto iter = std::find_if(appStateCallbacks_.begin(), appStateCallbacks_.end(),
        [callback](const sptr<ApplicationStatusChangeCallback>& rec) {
        return callback == rec->GetCallback();
    });
    if (iter != appStateCallbacks_.end()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "callback is already registered, add TokenId(%{public}d).", tokenId);
        (*iter)->AddTokenId(tokenId);
        return true;
    }

    if (appStateCallbacks_.size() >= MAX_CALLBACK_SIZE) {
        ACCESSTOKEN_LOG_INFO(LABEL, "callback counts reach the max.");
        return false;
    }

    sptr<ApplicationStatusChangeCallback> listener = new (std::nothrow) ApplicationStatusChangeCallback();
    if (listener == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new fail.");
        return false;
    }
    listener->SetCallback(callback);
    listener->AddTokenId(tokenId);

    auto appMgrProxy = GetAppManagerProxy();
    if (appMgrProxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetAppManagerProxy failed");
        return false;
    }

    appStateCallbacks_.emplace_back(listener);
    appMgrProxy->RegisterApplicationStateObserver(listener);

    ACCESSTOKEN_LOG_INFO(LABEL, "register callback(%{public}p),  add TokenId(%{public}d).", callback, tokenId);

    return true;
}

bool SensitiveResourceManager::UnRegisterAppStatusChangeCallback(uint32_t tokenId, OnAppStatusChangeCallback callback)
{
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback could not be null.");
        return false;
    }
    
    std::lock_guard<std::mutex> lock(appStatusMutex_);
    auto iter = std::find_if(appStateCallbacks_.begin(), appStateCallbacks_.end(),
        [callback](const sptr<ApplicationStatusChangeCallback>& rec) {
        return callback == rec->GetCallback();
    });
    if (iter == appStateCallbacks_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback is not found.");
        return false;
    }

    auto appMgrProxy = GetAppManagerProxy();
    if (appMgrProxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetAppManagerProxy failed");
        return false;
    }

    (*iter)->RemoveTokenId(tokenId);
    if (!(*iter)->IsHasListener()) {
        appMgrProxy->UnregisterApplicationStateObserver(*iter);
        appStateCallbacks_.erase(iter);
    }
    
    ACCESSTOKEN_LOG_INFO(LABEL, "unregister callback(%{public}p).", callback);

    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
