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
#include "power_manager_client.h"
#include <unistd.h>

#include "accesstoken_log.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "PowerMgrClient"
};
std::mutex g_instanceMutex;
} // namespace

PowerMgrClient& PowerMgrClient::GetInstance()
{
    static PowerMgrClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new PowerMgrClient();
        }
    }
    return *instance;
}

PowerMgrClient::PowerMgrClient()
{}

PowerMgrClient::~PowerMgrClient()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ReleaseProxy();
}

bool PowerMgrClient::IsScreenOn()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Entry");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Proxy is null");
        return false;
    }
    return proxy->IsScreenOn();
}

void PowerMgrClient::InitProxy()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbilityManager is null");
        return;
    }
    auto powerManagerSa = sam->GetSystemAbility(POWER_MANAGER_SERVICE_ID);
    if (powerManagerSa == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbility %{public}d is null",
            POWER_MANAGER_SERVICE_ID);
        return;
    }

    serviceDeathObserver_ = sptr<PowerMgrDeathRecipient>::MakeSptr();
    if (serviceDeathObserver_ != nullptr) {
        powerManagerSa->AddDeathRecipient(serviceDeathObserver_);
    }

    proxy_ = new PowerMgrProxy(powerManagerSa);
    if (proxy_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Iface_cast get null");
    }
}

void PowerMgrClient::OnRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ReleaseProxy();
}

sptr<IPowerMgr> PowerMgrClient::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr) {
        InitProxy();
    }
    return proxy_;
}

void PowerMgrClient::ReleaseProxy()
{
    if (proxy_ != nullptr && serviceDeathObserver_ != nullptr) {
        proxy_->AsObject()->RemoveDeathRecipient(serviceDeathObserver_);
    }
    proxy_ = nullptr;
    serviceDeathObserver_ = nullptr;
}

void PowerMgrDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& object)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OnRemoteDied");
    PowerMgrClient::GetInstance().OnRemoteDiedHandle();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

