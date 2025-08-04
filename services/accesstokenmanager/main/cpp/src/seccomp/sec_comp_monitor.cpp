/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "sec_comp_monitor.h"

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "accesstoken_info_manager.h"
#include "app_manager_access_client.h"
#include "ipc_skeleton.h"
#include "securec.h"
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
#include "sec_comp_enhance_agent.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static std::mutex g_instanceMutex;
constexpr int32_t APP_STATE_CACHED = 100;
}
void SecCompUsageObserver::OnProcessDied(const ProcessData &processData)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "OnProcessDied pid %{public}d", processData.pid);
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
    SecCompEnhanceAgent::GetInstance().RemoveSecCompEnhance(processData.pid);
#endif
    SecCompMonitor::GetInstance().RemoveProcessFromForegroundList(processData.pid);
}

void SecCompUsageObserver::OnProcessStateChanged(const ProcessData &processData)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "OnChange pid=%{public}d.", processData.pid);

    if (processData.state != AppProcessState::APP_STATE_BACKGROUND) {
        return;
    }
    SecCompMonitor::GetInstance().RemoveProcessFromForegroundList(processData.pid);
}

void SecCompUsageObserver::OnAppCacheStateChanged(const AppStateData &appStateData)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "OnAppCacheStateChanged pid %{public}d", appStateData.pid);
    if (appStateData.state != APP_STATE_CACHED) {
        return;
    }

    SecCompMonitor::GetInstance().RemoveProcessFromForegroundList(appStateData.pid);
}

void SecCompAppManagerDeathCallback::NotifyAppManagerDeath()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "AppManagerDeath called");

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
    SecCompEnhanceAgent::GetInstance().OnAppMgrRemoteDiedHandle();
#endif
    SecCompMonitor::GetInstance().OnAppMgrRemoteDiedHandle();
}

bool SecCompMonitor::IsToastShownNeeded(int32_t pid)
{
    std::lock_guard<std::mutex> lock(appfgLock_);
    InitAppObserver();
    auto iter = appsInForeground_.find(pid);
    if (iter != appsInForeground_.end()) {
        return false;
    }

    appsInForeground_.insert(pid);
    return true;
}

void SecCompMonitor::RemoveProcessFromForegroundList(int32_t pid)
{
    std::lock_guard<std::mutex> lock(appfgLock_);
    auto iter = appsInForeground_.find(pid);
    if (iter == appsInForeground_.end()) {
        return;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Process pid=%{public}d removed from foreground list.", pid);
    appsInForeground_.erase(pid);
}

SecCompMonitor& SecCompMonitor::GetInstance()
{
    static SecCompMonitor* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            SecCompMonitor* tmp = new (std::nothrow) SecCompMonitor();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

void SecCompMonitor::InitAppObserver()
{
    {
        std::lock_guard<std::mutex> lock(observerMutex_);
        if (observer_ != nullptr) {
            return;
        }
        observer_ = new (std::nothrow) SecCompUsageObserver();
        if (observer_ == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "New observer failed.");
            return;
        }
        if (AppManagerAccessClient::GetInstance().RegisterApplicationStateObserver(observer_) != 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Register observer failed.");
            observer_ = nullptr;
            return;
        }
    }
    {
        std::lock_guard<std::mutex> lock(appManagerDeathMutex_);
        if (appManagerDeathCallback_ == nullptr) {
            appManagerDeathCallback_ = std::make_shared<SecCompAppManagerDeathCallback>();
            AppManagerAccessClient::GetInstance().RegisterDeathCallback(appManagerDeathCallback_);
        }
    }
}

SecCompMonitor::SecCompMonitor()
{
    InitAppObserver();
}

SecCompMonitor::~SecCompMonitor()
{
    std::lock_guard<std::mutex> lock(observerMutex_);
    if (observer_ != nullptr) {
        (void)AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(observer_);
        observer_ = nullptr;
    }
}

void SecCompMonitor::OnAppMgrRemoteDiedHandle()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "OnAppMgrRemoteDiedHandle.");
    std::lock_guard<std::mutex> lock(observerMutex_);
    if (observer_ != nullptr) {
        (void)AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(observer_);
        observer_ = nullptr;
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
