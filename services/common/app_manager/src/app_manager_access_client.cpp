/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "accesstoken_common_log.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t ERROR = -1;
std::recursive_mutex g_instanceMutex;
std::u16string DESCRIPTOR = u"ohos.appexecfwk.AppMgr";
constexpr int32_t CYCLE_LIMIT = 1000;
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

int32_t AppManagerAccessClient::RegisterApplicationStateObserver(const sptr<IApplicationStateObserver>& observer)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Entry");
    if (observer == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Callback is nullptr.");
        return ERROR;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return ERROR;
    }
    std::vector<std::string> bundleNameList;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(DESCRIPTOR)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed");
        return ERROR;
    }
    if (!data.WriteRemoteObject(observer->AsObject())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Observer write failed.");
        return ERROR;
    }
    if (!data.WriteStringVector(bundleNameList)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "BundleNameList write failed.");
        return ERROR;
    }
    int32_t error = proxy->SendRequest(
        static_cast<uint32_t>(AppManagerAccessClient::Message::REGISTER_APPLICATION_STATE_OBSERVER),
        data, reply, option);
    if (error != ERR_NONE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "RegisterAppStatus failed, error: %{public}d", error);
        return ERROR;
    }
    return reply.ReadInt32();
}

int32_t AppManagerAccessClient::UnregisterApplicationStateObserver(const sptr<IApplicationStateObserver> &observer)
{
    if (observer == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Callback is nullptr.");
        return ERROR;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return ERROR;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(DESCRIPTOR)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed");
        return ERROR;
    }
    if (!data.WriteRemoteObject(observer->AsObject())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Observer write failed.");
        return ERROR;
    }
    int32_t error = proxy->SendRequest(
        static_cast<uint32_t>(AppManagerAccessClient::Message::UNREGISTER_APPLICATION_STATE_OBSERVER),
        data, reply, option);
    if (error != ERR_NONE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Set microphoneMute failed, error: %d", error);
        return error;
    }
    return reply.ReadInt32();
}

int32_t AppManagerAccessClient::GetForegroundApplications(std::vector<AppStateData>& list)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return ERROR;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(DESCRIPTOR)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed");
        return ERROR;
    }
    int32_t error = proxy->SendRequest(
        static_cast<uint32_t>(AppManagerAccessClient::Message::GET_FOREGROUND_APPLICATIONS), data, reply, option);
    if (error != ERR_NONE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetForegroundApplications failed, error: %{public}d", error);
        return error;
    }
    uint32_t infoSize = reply.ReadUint32();
    if (infoSize > CYCLE_LIMIT) {
        LOGE(ATM_DOMAIN, ATM_TAG, "InfoSize is too large");
        return ERROR;
    }
    for (uint32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<AppStateData> info(reply.ReadParcelable<AppStateData>());
        if (info != nullptr) {
            list.emplace_back(*info);
        }
    }
    return reply.ReadInt32();
}

void AppManagerAccessClient::InitProxy()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetSystemAbilityManager is null");
        return;
    }
    auto appManagerSa = sam->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (appManagerSa == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetSystemAbility %{public}d is null",
            APP_MGR_SERVICE_ID);
        return;
    }

    serviceDeathObserver_ = sptr<AppMgrDeathRecipient>::MakeSptr();
    if (serviceDeathObserver_ != nullptr) {
        appManagerSa->AddDeathRecipient(serviceDeathObserver_);
    }

    proxy_ = appManagerSa;
}

void AppManagerAccessClient::RegisterDeathCallback(const std::shared_ptr<AppManagerDeathCallback>& callback)
{
    std::lock_guard<std::mutex> lock(deathCallbackMutex_);
    if (callback == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AppManagerAccessClient: Callback is nullptr.");
        return;
    }
    appManagerDeathCallbackList_.emplace_back(callback);
}

void AppManagerAccessClient::OnRemoteDiedHandle()
{
    std::vector<std::shared_ptr<AppManagerDeathCallback>> tmpCallbackList;
    {
        std::lock_guard<std::mutex> lock(deathCallbackMutex_);
        tmpCallbackList.assign(appManagerDeathCallbackList_.begin(), appManagerDeathCallbackList_.end());
    }

    for (size_t i = 0; i < tmpCallbackList.size(); i++) {
        tmpCallbackList[i]->NotifyAppManagerDeath();
    }
    {
        std::lock_guard<std::mutex> lock(proxyMutex_);
        ReleaseProxy();
    }
}

sptr<IRemoteObject> AppManagerAccessClient::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr || proxy_->IsObjectDead()) {
        InitProxy();
    }
    return proxy_;
}

void AppManagerAccessClient::ReleaseProxy()
{
    if (proxy_ != nullptr && serviceDeathObserver_ != nullptr) {
        proxy_->RemoveDeathRecipient(serviceDeathObserver_);
    }
    proxy_ = nullptr;
    serviceDeathObserver_ = nullptr;
}

void AppManagerAccessClient::AppMgrDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& object)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "%{public}s called", __func__);
    AppManagerAccessClient::GetInstance().OnRemoteDiedHandle();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

