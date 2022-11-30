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
#include "ability_manager_privacy_client.h"
#include "accesstoken_log.h"
#include "iservice_registry.h"
#include "privacy_error.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "AbilityManagerPrivacyClient"
};
} // namespace

AbilityManagerPrivacyClient& AbilityManagerPrivacyClient::GetInstance()
{
    static AbilityManagerPrivacyClient instance;
    return instance;
}

AbilityManagerPrivacyClient::AbilityManagerPrivacyClient()
{}

AbilityManagerPrivacyClient::~AbilityManagerPrivacyClient()
{}

int32_t AbilityManagerPrivacyClient::StartAbility(
    const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken, int requestCode, int32_t userId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Start ability %{public}s, userId:%{public}d",
        want.GetElement().GetAbilityName().c_str(), userId);
    return proxy->StartAbility(want, callerToken, userId, requestCode);
}

void AbilityManagerPrivacyClient::InitProxy()
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

    auto deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new AbilityManagerPrivacyDeathRecipient());
    if (deathRecipient_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Create AbilityManagerPrivacyDeathRecipient failed");
        return;
    }

    if (!abilityManagerSa->IsProxyObject()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not proxy object");
        return;
    }
    if (!abilityManagerSa->AddDeathRecipient(deathRecipient_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Add death recipient failed");
        return;
    }

    proxy_ = iface_cast<IAbilityManager>(abilityManagerSa);
    if (proxy_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "iface_cast get null");
    }
}

void AbilityManagerPrivacyClient::OnRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    proxy_ = nullptr;
}

sptr<IAbilityManager> AbilityManagerPrivacyClient::GetProxy()
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

