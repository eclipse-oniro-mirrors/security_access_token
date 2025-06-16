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
#include "background_task_manager_access_client.h"

#include "accesstoken_common_log.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t ERROR = -1;
std::recursive_mutex g_instanceMutex;
} // namespace

BackgroundTaskManagerAccessClient& BackgroundTaskManagerAccessClient::GetInstance()
{
    static BackgroundTaskManagerAccessClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            BackgroundTaskManagerAccessClient* tmp = new (std::nothrow) BackgroundTaskManagerAccessClient();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

BackgroundTaskManagerAccessClient::BackgroundTaskManagerAccessClient()
{}

BackgroundTaskManagerAccessClient::~BackgroundTaskManagerAccessClient()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ReleaseProxy();
}

int32_t BackgroundTaskManagerAccessClient::SubscribeBackgroundTask(const sptr<IBackgroundTaskSubscriber>& subscriber)
{
    if (subscriber == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Callback is nullptr.");
        return ERROR;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return ERROR;
    }
    return proxy->SubscribeBackgroundTask(subscriber);
}

int32_t BackgroundTaskManagerAccessClient::UnsubscribeBackgroundTask(const sptr<IBackgroundTaskSubscriber>& subscriber)
{
    if (subscriber == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Callback is nullptr.");
        return ERROR;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return ERROR;
    }
    return proxy->UnsubscribeBackgroundTask(subscriber);
}

int32_t BackgroundTaskManagerAccessClient::GetContinuousTaskApps(
    std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>> &list)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return ERROR;
    }
    return proxy->GetContinuousTaskApps(list);
}

void BackgroundTaskManagerAccessClient::InitProxy()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetSystemAbilityManager is null");
        return;
    }
    auto backgroundTaskManagerSa = sam->GetSystemAbility(BACKGROUND_TASK_MANAGER_SERVICE_ID);
    if (backgroundTaskManagerSa == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetSystemAbility %{public}d is null",
            BACKGROUND_TASK_MANAGER_SERVICE_ID);
        return;
    }

    serviceDeathObserver_ = new (std::nothrow) BackgroundTaskMgrDeathRecipient();
    if (serviceDeathObserver_ != nullptr) {
        backgroundTaskManagerSa->AddDeathRecipient(serviceDeathObserver_);
    }

    proxy_ = new (std::nothrow) BackgroundTaskManagerAccessProxy(backgroundTaskManagerSa);
    if (proxy_ == nullptr || proxy_->AsObject() == nullptr || proxy_->AsObject()->IsObjectDead()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Iface_cast get null");
    }
}

void BackgroundTaskManagerAccessClient::OnRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ReleaseProxy();
}

sptr<IBackgroundTaskMgr> BackgroundTaskManagerAccessClient::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr || proxy_->AsObject() == nullptr || proxy_->AsObject()->IsObjectDead()) {
        InitProxy();
    }
    return proxy_;
}

void BackgroundTaskManagerAccessClient::ReleaseProxy()
{
    if ((proxy_ != nullptr) && (proxy_->AsObject() != nullptr) && (serviceDeathObserver_ != nullptr)) {
        proxy_->AsObject()->RemoveDeathRecipient(serviceDeathObserver_);
    }
    proxy_ = nullptr;
    serviceDeathObserver_ = nullptr;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
