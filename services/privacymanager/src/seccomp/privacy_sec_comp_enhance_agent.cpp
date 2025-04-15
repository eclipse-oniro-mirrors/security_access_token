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
#include "privacy_sec_comp_enhance_agent.h"

#include "access_token.h"
#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "app_manager_access_client.h"
#include "ipc_skeleton.h"
#include "privacy_error.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::string SCENE_BOARD_PKG_NAME = "com.ohos.sceneboard";
std::recursive_mutex g_instanceMutex;
}
void PrivacyAppUsingSecCompStateObserver::OnProcessDied(const ProcessData &processData)
{
    LOGI(PRI_DOMAIN, PRI_TAG, "OnProcessDied pid %{public}d", processData.pid);
    PrivacySecCompEnhanceAgent::GetInstance().RemoveSecCompEnhance(processData.pid);
}

void PrivacySecCompAppManagerDeathCallback::NotifyAppManagerDeath()
{
    LOGI(PRI_DOMAIN, PRI_TAG, "AppManagerDeath called");

    PrivacySecCompEnhanceAgent::GetInstance().OnAppMgrRemoteDiedHandle();
}

PrivacySecCompEnhanceAgent& PrivacySecCompEnhanceAgent::GetInstance()
{
    static PrivacySecCompEnhanceAgent* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            PrivacySecCompEnhanceAgent* tmp = new PrivacySecCompEnhanceAgent();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

void PrivacySecCompEnhanceAgent::InitAppObserver()
{
    if (observer_ != nullptr) {
        return;
    }
    observer_ = new (std::nothrow) PrivacyAppUsingSecCompStateObserver();
    if (observer_ == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "New observer failed.");
        return;
    }
    if (AppManagerAccessClient::GetInstance().RegisterApplicationStateObserver(observer_) != 0) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Register observer failed.");
        observer_ = nullptr;
        return;
    }
    if (appManagerDeathCallback_ == nullptr) {
        appManagerDeathCallback_ = std::make_shared<PrivacySecCompAppManagerDeathCallback>();
        AppManagerAccessClient::GetInstance().RegisterDeathCallback(appManagerDeathCallback_);
    }
}

PrivacySecCompEnhanceAgent::PrivacySecCompEnhanceAgent()
{
    InitAppObserver();
}

PrivacySecCompEnhanceAgent::~PrivacySecCompEnhanceAgent()
{
    if (observer_ != nullptr) {
        AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(observer_);
        observer_ = nullptr;
    }
}

void PrivacySecCompEnhanceAgent::OnAppMgrRemoteDiedHandle()
{
    LOGI(PRI_DOMAIN, PRI_TAG, "OnAppMgrRemoteDiedHandle.");
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    secCompEnhanceData_.clear();
    observer_ = nullptr;
}

void PrivacySecCompEnhanceAgent::RemoveSecCompEnhance(int pid)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    for (auto iter = secCompEnhanceData_.begin(); iter != secCompEnhanceData_.end(); ++iter) {
        if (iter->pid == pid) {
            secCompEnhanceData_.erase(iter);
            LOGI(PRI_DOMAIN, PRI_TAG, "Remove pid %{public}d data.", pid);
            return;
        }
    }
    LOGE(PRI_DOMAIN, PRI_TAG, "Not found pid %{public}d data.", pid);
    return;
}

int32_t PrivacySecCompEnhanceAgent::RegisterSecCompEnhance(const SecCompEnhanceData& enhanceData)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    InitAppObserver();
    int pid = IPCSkeleton::GetCallingPid();
    if (std::any_of(secCompEnhanceData_.begin(), secCompEnhanceData_.end(),
        [pid](const auto& e) { return e.pid == pid; })) {
            LOGE(PRI_DOMAIN, PRI_TAG, "Register sec comp enhance exist, pid %{public}d.", pid);
            return PrivacyError::ERR_CALLBACK_ALREADY_EXIST;
    }
    SecCompEnhanceData enhance;
    enhance.callback = enhanceData.callback;
    enhance.pid = pid;
    enhance.token = IPCSkeleton::GetCallingTokenID();
    enhance.challenge = enhanceData.challenge;
    enhance.sessionId = enhanceData.sessionId;
    enhance.seqNum = enhanceData.seqNum;
    enhance.isSceneBoard = false;
    if (memcpy_s(enhance.key, AES_KEY_STORAGE_LEN, enhanceData.key, AES_KEY_STORAGE_LEN) != EOK) {
        return PrivacyError::ERR_CALLBACK_ALREADY_EXIST;
    }
    HapTokenInfo info;
    if (AccessTokenKit::GetHapTokenInfo(enhance.token, info) == AccessTokenKitRet::RET_SUCCESS) {
        if (info.bundleName == SCENE_BOARD_PKG_NAME) {
            enhance.isSceneBoard = true;
        }
    }
    secCompEnhanceData_.emplace_back(enhance);
    LOGI(PRI_DOMAIN, PRI_TAG, "Register sec comp enhance success, pid %{public}d, total %{public}u.",
        pid, static_cast<uint32_t>(secCompEnhanceData_.size()));
    return RET_SUCCESS;
}

int32_t PrivacySecCompEnhanceAgent::UpdateSecCompEnhance(int32_t pid, uint32_t seqNum)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    InitAppObserver();
    for (auto iter = secCompEnhanceData_.begin(); iter != secCompEnhanceData_.end(); ++iter) {
        if (iter->pid == pid) {
            iter->seqNum = seqNum;
            LOGI(PRI_DOMAIN, PRI_TAG, "Update pid=%{public}d data successful.", pid);
            return RET_SUCCESS;
        }
    }
    return ERR_PARAM_INVALID;
}

int32_t PrivacySecCompEnhanceAgent::GetSecCompEnhance(int32_t pid, SecCompEnhanceData& enhanceData)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    InitAppObserver();
    for (auto iter = secCompEnhanceData_.begin(); iter != secCompEnhanceData_.end(); ++iter) {
        if (iter->pid == pid) {
            enhanceData = *iter;
            LOGI(PRI_DOMAIN, PRI_TAG, "Get pid %{public}d data.", pid);
            return RET_SUCCESS;
        }
    }
    return ERR_PARAM_INVALID;
}

int32_t PrivacySecCompEnhanceAgent::GetSpecialSecCompEnhance(const std::string& bundleName,
    std::vector<SecCompEnhanceData>& enhanceList)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    for (auto iter = secCompEnhanceData_.begin(); iter != secCompEnhanceData_.end(); iter++) {
        if ((*iter).isSceneBoard) {
            enhanceList.emplace_back(*iter);
        }
    }
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
