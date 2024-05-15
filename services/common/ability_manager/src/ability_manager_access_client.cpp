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
#include "ability_manager_access_client.h"
#include "access_token_error.h"
#include "accesstoken_log.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AbilityManagerAccessClient"
};
std::recursive_mutex g_instanceMutex;
} // namespace

AbilityManagerAccessClient& AbilityManagerAccessClient::GetInstance()
{
    static AbilityManagerAccessClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new AbilityManagerAccessClient();
        }
    }
    return *instance;
}

AbilityManagerAccessClient::AbilityManagerAccessClient()
{}

AbilityManagerAccessClient::~AbilityManagerAccessClient()
{}

int32_t AbilityManagerAccessClient::StartAbility(
    const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken, int requestCode, int32_t userId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Start ability %{public}s, userId:%{public}d",
        want.GetElement().GetAbilityName().c_str(), userId);
    return proxy->StartAbility(want, callerToken, userId, requestCode);
}

void AbilityManagerAccessClient::InitProxy()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbilityManager is null");
        return;
    }
    auto abilityManagerSa = sam->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
    if (abilityManagerSa == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbility %{public}d is null", ABILITY_MGR_SERVICE_ID);
        return;
    }

    serviceDeathObserver_ = new (std::nothrow) AbilityManagerAccessDeathRecipient();
    if (serviceDeathObserver_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Create AbilityManagerAccessDeathRecipient failed");
        return;
    }

    if (!abilityManagerSa->IsProxyObject()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not proxy object");
        return;
    }
    if (!abilityManagerSa->AddDeathRecipient(serviceDeathObserver_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Add death recipient failed");
        return;
    }

    proxy_ = iface_cast<IAbilityManager>(abilityManagerSa);
    if (proxy_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "iface_cast get null");
    }
}

void AbilityManagerAccessClient::OnRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    proxy_ = nullptr;
}

sptr<IAbilityManager> AbilityManagerAccessClient::GetProxy()
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

