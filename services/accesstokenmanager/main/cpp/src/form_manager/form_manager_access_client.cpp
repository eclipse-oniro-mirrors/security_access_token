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
#include "form_manager_access_client.h"
#include <unistd.h>

#include "accesstoken_log.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "FormManagerAccessClient"
};
std::recursive_mutex g_instanceMutex;
} // namespace

FormManagerAccessClient& FormManagerAccessClient::GetInstance()
{
    static FormManagerAccessClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new FormManagerAccessClient();
        }
    }
    return *instance;
}

FormManagerAccessClient::FormManagerAccessClient()
{}

FormManagerAccessClient::~FormManagerAccessClient()
{}

int32_t FormManagerAccessClient::RegisterAddObserver(
    const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    if (callerToken == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Callback is nullptr.");
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null.");
        return -1;
    }
    return proxy->RegisterAddObserver(bundleName, callerToken);
}

int32_t FormManagerAccessClient::RegisterRemoveObserver(
    const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    if (callerToken == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Callback is nullptr.");
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null.");
        return -1;
    }
    return proxy->RegisterRemoveObserver(bundleName, callerToken);
}

bool FormManagerAccessClient::HasFormVisible(const uint32_t tokenId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null.");
        return false;
    }
    return proxy->HasFormVisible(tokenId);
}

void FormManagerAccessClient::InitProxy()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbilityManager is null.");
        return;
    }
    auto formManagerSa = sam->GetSystemAbility(FORM_MGR_SERVICE_ID);
    if (formManagerSa == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbility %{public}d is null.",
            APP_MGR_SERVICE_ID);
        return;
    }

    serviceDeathObserver_ = new (std::nothrow) FormMgrDeathRecipient();
    if (serviceDeathObserver_ != nullptr) {
        formManagerSa->AddDeathRecipient(serviceDeathObserver_);
    }

    proxy_ = iface_cast<IFormMgr>(formManagerSa);
    if (proxy_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "iface_cast get null.");
    }
}

void FormManagerAccessClient::OnRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    proxy_ = nullptr;
}

sptr<IFormMgr> FormManagerAccessClient::GetProxy()
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
