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
std::recursive_mutex g_instanceMutex;
} // namespace

AppManagerAccessClient& AppManagerAccessClient::GetInstance()
{
    static AppManagerAccessClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            AppManagerAccessClient* tmp = new AppManagerAccessClient();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

AppManagerAccessClient::AppManagerAccessClient()
{}

AppManagerAccessClient::~AppManagerAccessClient()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ReleaseProxy();
}

int32_t AppManagerAccessClient::GetForegroundApplications(std::vector<AppStateData>& list)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Proxy is null");
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

    proxy_ = new AppManagerAccessProxy(appManagerSa);
    if (proxy_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Iface_cast get null");
    }
}

sptr<IAppMgr> AppManagerAccessClient::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr) {
        InitProxy();
    }
    return proxy_;
}

void AppManagerAccessClient::ReleaseProxy()
{
    proxy_ = nullptr;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

