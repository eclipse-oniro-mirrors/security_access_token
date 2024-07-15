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

#include "el5_filekey_manager_client.h"

#include "el5_filekey_manager_load_callback.h"
#include "el5_filekey_manager_log.h"
#include "el5_filekey_manager_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t LOAD_SA_TIMEOUT_MS = 5000;
}
El5FilekeyManagerClient::El5FilekeyManagerClient()
{
}

El5FilekeyManagerClient::~El5FilekeyManagerClient()
{
}

El5FilekeyManagerClient& El5FilekeyManagerClient::GetInstance()
{
    static El5FilekeyManagerClient instance;
    return instance;
}

int32_t El5FilekeyManagerClient::AcquireAccess(DataLockType type)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOG_ERROR("Get proxy failed, proxy is null.");
        return EFM_ERR_SA_GET_PROXY;
    }
    return proxy->AcquireAccess(type);
}

int32_t El5FilekeyManagerClient::ReleaseAccess(DataLockType type)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOG_ERROR("Get proxy failed, proxy is null.");
        return EFM_ERR_SA_GET_PROXY;
    }
    return proxy->ReleaseAccess(type);
}

int32_t El5FilekeyManagerClient::GenerateAppKey(uint32_t uid, const std::string& bundleName, std::string& keyId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOG_ERROR("Get proxy failed, proxy is null.");
        return EFM_ERR_SA_GET_PROXY;
    }
    return proxy->GenerateAppKey(uid, bundleName, keyId);
}

int32_t El5FilekeyManagerClient::DeleteAppKey(const std::string& keyId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOG_ERROR("Get proxy failed, proxy is null.");
        return EFM_ERR_SA_GET_PROXY;
    }
    return proxy->DeleteAppKey(keyId);
}

int32_t El5FilekeyManagerClient::GetUserAppKey(int32_t userId, bool getAllFlag,
    std::vector<std::pair<int32_t, std::string>>& keyInfos)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOG_ERROR("Get proxy failed, proxy is null.");
        return EFM_ERR_SA_GET_PROXY;
    }
    return proxy->GetUserAppKey(userId, getAllFlag, keyInfos);
}

int32_t El5FilekeyManagerClient::ChangeUserAppkeysLoadInfo(int32_t userId,
    std::vector<std::pair<std::string, bool>> &loadInfos)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOG_ERROR("Get proxy failed, proxy is null.");
        return EFM_ERR_SA_GET_PROXY;
    }
    return proxy->ChangeUserAppkeysLoadInfo(userId, loadInfos);
}

int32_t El5FilekeyManagerClient::SetFilePathPolicy()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOG_ERROR("Get proxy failed, proxy is null.");
        return EFM_ERR_SA_GET_PROXY;
    }
    return proxy->SetFilePathPolicy();
}

int32_t El5FilekeyManagerClient::RegisterCallback(const sptr<El5FilekeyCallbackInterface> &callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOG_ERROR("Get proxy failed, proxy is null.");
        return EFM_ERR_SA_GET_PROXY;
    }
    return proxy->RegisterCallback(callback);
}

sptr<El5FilekeyManagerInterface> El5FilekeyManagerClient::GetProxy()
{
    std::unique_lock<std::mutex> lock(proxyMutex_);
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        LOG_ERROR("Get system ability manager failed.");
        return nullptr;
    }
    if (proxy_ == nullptr) {
        auto el5FilekeyService = systemAbilityManager->CheckSystemAbility(EL5_FILEKEY_MANAGER_SERVICE_ID);
        if (el5FilekeyService != nullptr) {
            deathRecipient_ = new (std::nothrow) El5FilekeyManagerDeathRecipient();
            if (deathRecipient_ != nullptr) {
                el5FilekeyService->AddDeathRecipient(deathRecipient_);
            }

            proxy_ = iface_cast<El5FilekeyManagerInterface>(el5FilekeyService);
            if (proxy_ == nullptr) {
                LOG_ERROR("Cast proxy failed, iface_cast get null.");
            }
            return proxy_;
        }
    }

    // LoadEl5FilekeyManagerService
    sptr<El5FilekeyManagerLoadCallback> loadCallback = new El5FilekeyManagerLoadCallback();
    if (loadCallback == nullptr) {
        LOG_ERROR("Load service failed, loadCallback is nullptr.");
        return nullptr;
    }
    int32_t ret = systemAbilityManager->LoadSystemAbility(EL5_FILEKEY_MANAGER_SERVICE_ID, loadCallback);
    if (ret != ERR_OK) {
        LOG_ERROR("Load el5_filekey_service failed.");
        return nullptr;
    }
    // wait for LoadSystemAbility
    LOG_INFO("wait for LoadSystemAbility");
    auto waitStatus = proxyConVar_.wait_for(lock, std::chrono::milliseconds(LOAD_SA_TIMEOUT_MS),
        [this]() { return proxy_ != nullptr; });
    if (!waitStatus) {
        LOG_WARN("wait for LoadSystemAbility timeout");
        return nullptr;
    }
    LOG_INFO("El5FilekeyManagerClient GetProxy success");

    return proxy_;
}

void El5FilekeyManagerClient::LoadSystemAbilitySuccess(const sptr<IRemoteObject> &remoteObject)
{
    LOG_INFO("El5FilekeyManagerClient LoadSystemAbilitySuccess");
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (remoteObject == nullptr) {
        LOG_ERROR("After loading el5_filekey_service, remoteObject is null.");
        proxy_ = nullptr;
        return;
    }

    deathRecipient_ = new (std::nothrow) El5FilekeyManagerDeathRecipient();
    if (deathRecipient_ != nullptr) {
        remoteObject->AddDeathRecipient(deathRecipient_);
    }

    proxy_ = iface_cast<El5FilekeyManagerInterface>(remoteObject);
    if (proxy_ == nullptr) {
        LOG_ERROR("After loading el5_filekey_service, iface_cast get null.");
    }
    proxyConVar_.notify_one();
}

void El5FilekeyManagerClient::LoadSystemAbilityFail()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    LOG_ERROR("Load el5_filekey_service failed.");
    proxy_ = nullptr;
    proxyConVar_.notify_one();
}

void El5FilekeyManagerClient::OnRemoteDiedHandle()
{
    LOG_INFO("Remote died.");
    std::lock_guard<std::mutex> lock(proxyMutex_);
    proxy_ = nullptr;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
