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
#include "app_manager_access_client.h"
#include <unistd.h>

#include "accesstoken_log.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AppManagerAccessClient"
};
} // namespace

AppManagerAccessClient& AppManagerAccessClient::GetInstance()
{
    static AppManagerAccessClient instance;
    return instance;
}

AppManagerAccessClient::AppManagerAccessClient()
{}

AppManagerAccessClient::~AppManagerAccessClient()
{}

int32_t AppManagerAccessClient::RegisterApplicationStateObserver(const sptr<IApplicationStateObserver>& observer)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Entry");
    if (observer == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "AudioPolicyManager: callback is nullptr");
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return -1;
    }
    std::vector<std::string> bundleNameList;
    return proxy->RegisterApplicationStateObserver(observer, bundleNameList);
}

int32_t AppManagerAccessClient::UnregisterApplicationStateObserver(const sptr<IApplicationStateObserver> &observer)
{
    if (observer == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "AudioPolicyManager: callback is nullptr");
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return -1;
    }
    return proxy->UnregisterApplicationStateObserver(observer);
}

int32_t AppManagerAccessClient::GetForegroundApplications(std::vector<AppStateData>& list)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return -1;
    }
    return proxy->GetForegroundApplications(list);
}

void AppManagerAccessClient::InitProxy()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbilityManager is null");
        return;
    }
    auto appManagerSa = sam->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (appManagerSa == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbility %{public}d is null",
            APP_MGR_SERVICE_ID);
        return;
    }

    serviceDeathObserver_ = new (std::nothrow) AppMgrDeathRecipient();
    if (serviceDeathObserver_ != nullptr) {
        appManagerSa->AddDeathRecipient(serviceDeathObserver_);
    }

    proxy_ = iface_cast<IAppMgr>(appManagerSa);
    if (proxy_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "iface_cast get null");
    }
}

void AppManagerAccessClient::RegisterDeathCallbak(const std::shared_ptr<AppManagerDeathCallback>& callback)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "AppManagerAccessClient: callback is nullptr");
        return;
    }
    appManagerDeathCallbackList_.emplace_back(callback);
}

void AppManagerAccessClient::OnRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    for (size_t i = 0; i < appManagerDeathCallbackList_.size(); i++) {
        appManagerDeathCallbackList_[i]->NotifyAppManagerDeath();
    }

    proxy_ = nullptr;
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
    PrivacySecCompEnhanceAgent::GetInstance().OnAppMgrRemoteDiedHandle();
#endif

sptr<IAppMgr> AppManagerAccessClient::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr) {
        InitProxy();
    }
    return proxy_;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
