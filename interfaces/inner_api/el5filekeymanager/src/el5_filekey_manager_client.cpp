/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "el5_filekey_manager_client.h"

#include "el5_filekey_manager_log.h"
#include "el5_filekey_manager_interface_proxy.h"
#include "el5_filekey_manager_error.h"
#include "app_key_load_info.h"
#include "user_app_key_info.h"
#include "iservice_registry.h"
#include "refbase.h"
#include "system_ability_definition.h"
#include "sys_binder.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t LOAD_SA_TIMEOUT_SECOND = 4;
constexpr int32_t LOAD_SA_RETRY_TIMES = 5;
constexpr int32_t SA_REQUEST_RETRY_TIMES = 3;
static const int32_t SENDREQ_FAIL_ERR = 32;
static const std::vector<int32_t> RETRY_CODE_LIST = { BR_DEAD_REPLY, BR_FAILED_REPLY, SENDREQ_FAIL_ERR };
}
El5FilekeyManagerClient::El5FilekeyManagerClient() {}

El5FilekeyManagerClient::~El5FilekeyManagerClient() {}

El5FilekeyManagerClient &El5FilekeyManagerClient::GetInstance()
{
    static El5FilekeyManagerClient instance;
    return instance;
}

int32_t El5FilekeyManagerClient::AcquireAccess(DataLockType type)
{
    std::function<int32_t(sptr<El5FilekeyManagerInterface> &)> func = [&](sptr<El5FilekeyManagerInterface> &proxy) {
        return proxy->AcquireAccess(type);
    };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t El5FilekeyManagerClient::ReleaseAccess(DataLockType type)
{
    std::function<int32_t(sptr<El5FilekeyManagerInterface> &)> func = [&](sptr<El5FilekeyManagerInterface> &proxy) {
        return proxy->ReleaseAccess(type);
    };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t El5FilekeyManagerClient::GenerateAppKey(uint32_t uid, const std::string &bundleName, std::string &keyId)
{
    std::function<int32_t(sptr<El5FilekeyManagerInterface> &)> func = [&](sptr<El5FilekeyManagerInterface> &proxy) {
        return proxy->GenerateAppKey(uid, bundleName, keyId);
    };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t El5FilekeyManagerClient::DeleteAppKey(const std::string &bundleName, int32_t userId)
{
    std::function<int32_t(sptr<El5FilekeyManagerInterface> &)> func = [&](sptr<El5FilekeyManagerInterface> &proxy) {
        return proxy->DeleteAppKey(bundleName, userId);
    };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t El5FilekeyManagerClient::GetUserAppKey(int32_t userId, bool getAllFlag,
    std::vector<std::pair<int32_t, std::string>> &keyInfos)
{
    std::vector<UserAppKeyInfo> userAppKeyInfos;
    std::function<int32_t(sptr<El5FilekeyManagerInterface> &)> func = [&](sptr<El5FilekeyManagerInterface> &proxy) {
        return proxy->GetUserAppKey(userId, getAllFlag, userAppKeyInfos);
    };
    int32_t ret = CallProxyWithRetry(func, __FUNCTION__, SA_REQUEST_RETRY_TIMES);
    for (auto const &it : userAppKeyInfos) {
        keyInfos.emplace_back(std::make_pair(it.first, it.second));
    }
    return ret;
}

int32_t El5FilekeyManagerClient::ChangeUserAppkeysLoadInfo(int32_t userId,
    std::vector<std::pair<std::string, bool>> &loadInfos)
{
    std::vector<AppKeyLoadInfo> appKeyLoadInfos;
    for (auto &it : loadInfos) {
        appKeyLoadInfos.emplace_back(AppKeyLoadInfo(it.first, it.second));
    }
    std::function<int32_t(sptr<El5FilekeyManagerInterface> &)> func = [&](sptr<El5FilekeyManagerInterface> &proxy) {
        return proxy->ChangeUserAppkeysLoadInfo(userId, appKeyLoadInfos);
    };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t El5FilekeyManagerClient::SetFilePathPolicy()
{
    std::function<int32_t(sptr<El5FilekeyManagerInterface> &)> func = [&](sptr<El5FilekeyManagerInterface> &proxy) {
        return proxy->SetFilePathPolicy();
    };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t El5FilekeyManagerClient::RegisterCallback(const sptr<El5FilekeyCallbackInterface> &callback)
{
    std::function<int32_t(sptr<El5FilekeyManagerInterface> &)> func = [&](sptr<El5FilekeyManagerInterface> &proxy) {
        return proxy->RegisterCallback(callback);
    };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t El5FilekeyManagerClient::GenerateGroupIDKey(uint32_t uid, const std::string &groupID, std::string &keyId)
{
    std::function<int32_t(sptr<El5FilekeyManagerInterface> &)> func = [&](sptr<El5FilekeyManagerInterface> &proxy) {
        return proxy->GenerateGroupIDKey(uid, groupID, keyId);
    };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t El5FilekeyManagerClient::DeleteGroupIDKey(uint32_t uid, const std::string &groupID)
{
    std::function<int32_t(sptr<El5FilekeyManagerInterface> &)> func = [&](sptr<El5FilekeyManagerInterface> &proxy) {
        return proxy->DeleteGroupIDKey(uid, groupID);
    };
    return CallProxyWithRetry(func, __FUNCTION__);
}

int32_t El5FilekeyManagerClient::QueryAppKeyState(DataLockType type)
{
    std::function<int32_t(sptr<El5FilekeyManagerInterface> &)> func = [&](sptr<El5FilekeyManagerInterface> &proxy) {
        return proxy->QueryAppKeyState(type);
    };
    return CallProxyWithRetry(func, __FUNCTION__);
}

sptr<El5FilekeyManagerInterface> El5FilekeyManagerClient::GetProxy()
{
    std::unique_lock<std::mutex> lock(proxyMutex_);
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        LOG_ERROR("Get system ability manager failed.");
        return nullptr;
    }

    auto el5FilekeyService = systemAbilityManager->CheckSystemAbility(EL5_FILEKEY_MANAGER_SERVICE_ID);
    if (el5FilekeyService != nullptr) {
        LOG_INFO("get el5 filekey manager proxy success");
        return iface_cast<El5FilekeyManagerInterface>(el5FilekeyService);
    }

    for (int i = 0; i <= LOAD_SA_RETRY_TIMES; i++) {
        el5FilekeyService =
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

int32_t El5FilekeyManagerClient::CallProxyWithRetry(
    const std::function<int32_t(sptr<El5FilekeyManagerInterface> &)> &func, const char *funcName, int32_t retryTimes)
{
    LOG_INFO("call proxy with retry function:%s", funcName);
    auto proxy = GetProxy();
    if (proxy != nullptr) {
        int32_t ret = func(proxy);
        if (!IsRequestNeedRetry(ret)) {
            return ret;
        }
        LOG_WARN("First try cal %{public}s failed ret:%{public}d. Begin retry", funcName, ret);
    } else {
        LOG_WARN("First try call %{public}s failed, proxy is NULL. Begin retry.", funcName);
    }

    for (int32_t i = 0; i < retryTimes; i++) {
        proxy = GetProxy();
        if (proxy == nullptr) {
            LOG_WARN("Get proxy %{public}s failed, retry time = %{public}d.", funcName, i);
            continue;
        }
        int32_t ret = func(proxy);
        if (!IsRequestNeedRetry(ret)) {
            return ret;
        }
        LOG_WARN("Call %{public}s failed, retry time = %{public}d, result = %{public}d", funcName, i, ret);
    }
    LOG_ERROR("Retry call service %{public}s error, tried %{public}d times.", funcName, retryTimes);
    return EFM_ERR_REMOTE_CONNECTION;
}

bool El5FilekeyManagerClient::IsRequestNeedRetry(int32_t ret)
{
    auto it = std::find(RETRY_CODE_LIST.begin(), RETRY_CODE_LIST.end(), ret);
    return it != RETRY_CODE_LIST.end();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
