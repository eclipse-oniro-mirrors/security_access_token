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

#include "el5_filekey_manager_log.h"
#include "el5_filekey_manager_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t LOAD_SA_TIMEOUT_SECOND = 4;
constexpr int32_t LOAD_SA_RETRY_TIMES = 5;
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

int32_t El5FilekeyManagerClient::DeleteAppKey(const std::string& bundleName, int32_t userId)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOG_ERROR("Get proxy failed, proxy is null.");
        return EFM_ERR_SA_GET_PROXY;
    }
    return proxy->DeleteAppKey(bundleName, userId);
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

    auto el5FilekeyService = systemAbilityManager->GetSystemAbility(EL5_FILEKEY_MANAGER_SERVICE_ID);
    if (el5FilekeyService != nullptr) {
        LOG_INFO("get el5 filekey manager proxy success");
        return iface_cast<El5FilekeyManagerInterface>(el5FilekeyService);
    }

    for (int i = 0; i <= LOAD_SA_RETRY_TIMES; i++) {
        auto el5FilekeyService =
            systemAbilityManager->LoadSystemAbility(EL5_FILEKEY_MANAGER_SERVICE_ID, LOAD_SA_TIMEOUT_SECOND);
        if (el5FilekeyService != nullptr) {
            LOG_INFO("load el5 filekey manager success");
            return iface_cast<El5FilekeyManagerInterface>(el5FilekeyService);
        }
        LOG_INFO("load el5 filekey manager failed, retry count:%{public}d", i);
    }
    LOG_ERROR("get el5 filekey manager proxy failed");
    return nullptr;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
