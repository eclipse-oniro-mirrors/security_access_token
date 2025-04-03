/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "sec_comp_enhance_agent.h"

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "accesstoken_info_manager.h"
#include "app_manager_access_client.h"
#include "ipc_skeleton.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
}
void AppUsingSecCompStateObserver::OnProcessDied(const ProcessData &processData)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "OnProcessDied pid %{public}d", processData.pid);
    SecCompEnhanceAgent::GetInstance().RemoveSecCompEnhance(processData.pid);
}

void SecCompAppManagerDeathCallback::NotifyAppManagerDeath()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "AppManagerDeath called");

    SecCompEnhanceAgent::GetInstance().OnAppMgrRemoteDiedHandle();
}

SecCompEnhanceAgent& SecCompEnhanceAgent::GetInstance()
{
    static SecCompEnhanceAgent* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            SecCompEnhanceAgent* tmp = new SecCompEnhanceAgent();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

void SecCompEnhanceAgent::InitAppObserver()
{
    if (observer_ != nullptr) {
        return;
    }
    observer_ = new (std::nothrow) AppUsingSecCompStateObserver();
    if (observer_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New observer failed.");
        return;
    }
    if (AppManagerAccessClient::GetInstance().RegisterApplicationStateObserver(observer_) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Register observer failed.");
        observer_ = nullptr;
        return;
    }
    if (appManagerDeathCallback_ == nullptr) {
        appManagerDeathCallback_ = std::make_shared<SecCompAppManagerDeathCallback>();
        AppManagerAccessClient::GetInstance().RegisterDeathCallback(appManagerDeathCallback_);
    }
}

SecCompEnhanceAgent::SecCompEnhanceAgent()
{
    InitAppObserver();
}

SecCompEnhanceAgent::~SecCompEnhanceAgent()
{
    if (observer_ != nullptr) {
        AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(observer_);
        observer_ = nullptr;
    }
}

void SecCompEnhanceAgent::OnAppMgrRemoteDiedHandle()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "OnAppMgrRemoteDiedHandle.");
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    secCompEnhanceData_.clear();
    observer_ = nullptr;
}

void SecCompEnhanceAgent::RemoveSecCompEnhance(int pid)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    for (auto iter = secCompEnhanceData_.begin(); iter != secCompEnhanceData_.end(); ++iter) {
        if (iter->pid == pid) {
            secCompEnhanceData_.erase(iter);
            LOGI(ATM_DOMAIN, ATM_TAG, "Remove pid %{public}d data.", pid);
            return;
        }
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "Not found pid %{public}d data.", pid);
    return;
}

int32_t SecCompEnhanceAgent::RegisterSecCompEnhance(const SecCompEnhanceData& enhanceData)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    InitAppObserver();
    int pid = IPCSkeleton::GetCallingPid();
    if (std::any_of(secCompEnhanceData_.begin(), secCompEnhanceData_.end(),
        [pid](const auto& e) { return e.pid == pid; })) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Register sec comp enhance exist, pid %{public}d.", pid);
            return AccessTokenError::ERR_CALLBACK_ALREADY_EXIST;
    }
    SecCompEnhanceData enhance;
    enhance.callback = enhanceData.callback;
    enhance.pid = pid;
    enhance.token = IPCSkeleton::GetCallingTokenID();
    enhance.challenge = enhanceData.challenge;
    enhance.sessionId = enhanceData.sessionId;
    enhance.seqNum = enhanceData.seqNum;
    if (memcpy_s(enhance.key, AES_KEY_STORAGE_LEN, enhanceData.key, AES_KEY_STORAGE_LEN) != EOK) {
        return AccessTokenError::ERR_CALLBACK_ALREADY_EXIST;
    }
    secCompEnhanceData_.emplace_back(enhance);
    LOGI(ATM_DOMAIN, ATM_TAG, "Register sec comp enhance success, pid %{public}d, total %{public}u.",
        pid, static_cast<uint32_t>(secCompEnhanceData_.size()));
    return RET_SUCCESS;
}

int32_t SecCompEnhanceAgent::UpdateSecCompEnhance(int32_t pid, uint32_t seqNum)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    InitAppObserver();
    for (auto iter = secCompEnhanceData_.begin(); iter != secCompEnhanceData_.end(); ++iter) {
        if (iter->pid == pid) {
            iter->seqNum = seqNum;
            LOGI(ATM_DOMAIN, ATM_TAG, "Update pid=%{public}d data successful.", pid);
            return RET_SUCCESS;
        }
    }
    return ERR_PARAM_INVALID;
}

int32_t SecCompEnhanceAgent::GetSecCompEnhance(int32_t pid, SecCompEnhanceData& enhanceData)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    InitAppObserver();
    for (auto iter = secCompEnhanceData_.begin(); iter != secCompEnhanceData_.end(); ++iter) {
        if (iter->pid == pid) {
            enhanceData = *iter;
            LOGI(ATM_DOMAIN, ATM_TAG, "Get pid %{public}d data.", pid);
            return RET_SUCCESS;
        }
    }
    return ERR_PARAM_INVALID;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
