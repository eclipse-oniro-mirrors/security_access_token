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

#include "accesstoken_log.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "BackgourndTaskManagerAccessClient"
};
std::recursive_mutex g_instanceMutex;
} // namespace

BackgourndTaskManagerAccessClient& BackgourndTaskManagerAccessClient::GetInstance()
{
    static BackgourndTaskManagerAccessClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new BackgourndTaskManagerAccessClient();
        }
    }
    return *instance;
}

BackgourndTaskManagerAccessClient::BackgourndTaskManagerAccessClient()
{}

BackgourndTaskManagerAccessClient::~BackgourndTaskManagerAccessClient()
{}

int32_t BackgourndTaskManagerAccessClient::SubscribeBackgroundTask(const sptr<IBackgroundTaskSubscriber>& subscriber)
{
    if (subscriber == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Callback is nullptr.");
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return -1;
    }
    return proxy->SubscribeBackgroundTask(subscriber);
}

int32_t BackgourndTaskManagerAccessClient::UnsubscribeBackgroundTask(const sptr<IBackgroundTaskSubscriber>& subscriber)
{
    if (subscriber == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Callback is nullptr.");
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return -1;
    }
    return proxy->UnsubscribeBackgroundTask(subscriber);
}

int32_t BackgourndTaskManagerAccessClient::GetContinuousTaskApps(
    std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>> &list)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return -1;
    }
    return proxy->GetContinuousTaskApps(list);
}

void BackgourndTaskManagerAccessClient::InitProxy()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbilityManager is null");
        return;
    }
    auto backgroundTaskManagerSa = sam->GetSystemAbility(BACKGROUND_TASK_MANAGER_SERVICE_ID);
    if (backgroundTaskManagerSa == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbility %{public}d is null",
            BACKGROUND_TASK_MANAGER_SERVICE_ID);
        return;
    }

    serviceDeathObserver_ = new (std::nothrow) BackgroundTaskMgrDeathRecipient();
    if (serviceDeathObserver_ != nullptr) {
        backgroundTaskManagerSa->AddDeathRecipient(serviceDeathObserver_);
    }

    proxy_ = iface_cast<IBackgroundTaskMgr>(backgroundTaskManagerSa);
    if (proxy_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "iface_cast get null");
    }
}

void BackgourndTaskManagerAccessClient::OnRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    proxy_ = nullptr;
}

sptr<IBackgroundTaskMgr> BackgourndTaskManagerAccessClient::GetProxy()
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
