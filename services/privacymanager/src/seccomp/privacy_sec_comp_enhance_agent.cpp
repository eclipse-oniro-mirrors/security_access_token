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
#include "accesstoken_log.h"
#include "app_manager_access_client.h"
#include "ipc_skeleton.h"
#include "privacy_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacySecCompEnhanceAgent"
};
}
void PrivacyAppUsingSecCompStateObserver::OnProcessDied(const ProcessData &processData)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OnProcessDied die pid %{public}d", processData.pid);

    int pid = processData.pid;
    PrivacySecCompEnhanceAgent::GetInstance().RemoveSecCompEnhance(pid);
}

void PrivacySecCompAppManagerDeathCallback::NotifyAppManagerDeath()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "PrivacySecComp AppManagerDeath called");

    PrivacySecCompEnhanceAgent::GetInstance().OnAppMgrRemoteDiedHandle();
}

PrivacySecCompEnhanceAgent& PrivacySecCompEnhanceAgent::GetInstance()
{
    static PrivacySecCompEnhanceAgent instance;
    return instance;
}

void PrivacySecCompEnhanceAgent::InitAppObserver()
{
    if (observer_ != nullptr) {
        return;
    }
    observer_ = new (std::nothrow) PrivacyAppUsingSecCompStateObserver();
    if (observer_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new observer failed.");
        return;
    }
    if (AppManagerAccessClient::GetInstance().RegisterApplicationStateObserver(observer_) != 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "register observer failed.");
        observer_ = nullptr;
        return;
    }
    appManagerDeathCallback_ = std::make_shared<PrivacySecCompAppManagerDeathCallback>();
    AppManagerAccessClient::GetInstance().RegisterDeathCallbak(appManagerDeathCallback_);
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
    ACCESSTOKEN_LOG_INFO(LABEL, "OnAppMgrRemoteDiedHandle.");
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
            ACCESSTOKEN_LOG_INFO(LABEL, "remove pid %{public}d data.", pid);
            return;
        }
    }
    ACCESSTOKEN_LOG_ERROR(LABEL, "not found pid %{public}d data.", pid);
    return;
}

int32_t PrivacySecCompEnhanceAgent::RegisterSecCompEnhance(const SecCompEnhanceData& enhanceData)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    InitAppObserver();
    if (isRecoverd) {
        ACCESSTOKEN_LOG_INFO(LABEL, "need register sec comp enhance redirect.");
        return PrivacyError::ERR_CALLBACK_REGIST_REDIRECT;
    }
    int pid = IPCSkeleton::GetCallingPid();
    if (std::any_of(secCompEnhanceData_.begin(), secCompEnhanceData_.end(),
        [pid](const auto& e) { return e.pid == pid; })) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "register sec comp enhance exist, pid %{public}d.", pid);
            return PrivacyError::ERR_CALLBACK_ALREADY_EXIST;
    }
    SecCompEnhanceData enhance;
    enhance.callback = enhanceData.callback;
    enhance.pid = pid;
    enhance.challenge = enhanceData.challenge;
    secCompEnhanceData_.emplace_back(enhance);
    ACCESSTOKEN_LOG_INFO(LABEL, "register sec comp enhance success, pid %{public}d, total %{public}u.",
        pid, static_cast<uint32_t>(secCompEnhanceData_.size()));
    return RET_SUCCESS;
}

int32_t PrivacySecCompEnhanceAgent::DepositSecCompEnhance(const std::vector<SecCompEnhanceData>& enhanceList)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    InitAppObserver();
    secCompEnhanceData_.assign(enhanceList.begin(), enhanceList.end());
    ACCESSTOKEN_LOG_INFO(LABEL, "Deposit sec comp enhance size %{public}u.", static_cast<uint32_t>(enhanceList.size()));
    isRecoverd = false;
    return RET_SUCCESS;
}

int32_t PrivacySecCompEnhanceAgent::RecoverSecCompEnhance(std::vector<SecCompEnhanceData>& enhanceList)
{
    std::lock_guard<std::mutex> lock(secCompEnhanceMutex_);
    InitAppObserver();
    ACCESSTOKEN_LOG_INFO(LABEL, "Recover sec comp enhance size %{public}u.",
        static_cast<uint32_t>(secCompEnhanceData_.size()));
    enhanceList.assign(secCompEnhanceData_.begin(), secCompEnhanceData_.end());
    secCompEnhanceData_.clear();
    isRecoverd = true;
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
