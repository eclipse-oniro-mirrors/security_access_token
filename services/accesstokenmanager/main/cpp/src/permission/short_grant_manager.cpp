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

#include "short_grant_manager.h"

#include <chrono>
#include <iostream>
#include <thread>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "app_manager_access_client.h"
#include "permission_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::recursive_mutex g_instanceMutex;
static constexpr int32_t DEFAULT_MAX_TIME_MILLISECONDS = 30 * 60; // 30 minutes
static constexpr int32_t DEFAULT_MAX_ONCE_TIME_MILLISECONDS = 5 * 60; // 5 minutes
static const std::string TASK_NAME_SHORT_GRANT_PERMISSION = "atm_permission_manager_short_grant";
static const std::vector<std::string> g_shortGrantPermission = {
    "ohos.permission.SHORT_TERM_WRITE_IMAGEVIDEO"
};

ShortGrantManager& ShortGrantManager::GetInstance()
{
    static ShortGrantManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            ShortGrantManager* tmp = new (std::nothrow) ShortGrantManager();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

void ShortPermAppManagerDeathCallback::NotifyAppManagerDeath()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ShortGrantManager AppManagerDeath called");

    ShortGrantManager::GetInstance().OnAppMgrRemoteDiedHandle();
}

void ShortPermAppStateObserver::OnAppStopped(const AppStateData &appStateData)
{
    if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED)) {
        uint32_t tokenID = appStateData.accessTokenId;
        LOGI(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d died.", tokenID);
        
        ShortGrantManager::GetInstance().ClearShortPermissionByTokenID(tokenID);
    }
}

void ShortGrantManager::OnAppMgrRemoteDiedHandle()
{
    std::unique_lock<std::mutex> lck(shortGrantDataMutex_);
    auto item = shortGrantData_.begin();
    while (item != shortGrantData_.end()) {
        if (PermissionManager::GetInstance().UpdatePermission(
            item->tokenID, item->permissionName, false, PERMISSION_USER_FIXED, false) != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d revoke permission:%{public}s failed!",
                item->tokenID, item->permissionName.c_str());
        }
        std::string taskName = TASK_NAME_SHORT_GRANT_PERMISSION + std::to_string(item->tokenID) + item->permissionName;
        ShortGrantManager::GetInstance().CancelTaskOfPermissionRevoking(taskName);
        ++item;
    }
    shortGrantData_.clear();
    LOGI(ATM_DOMAIN, ATM_TAG, "shortGrantData_ clear!");
    appStopCallBack_ = nullptr;
}

ShortGrantManager::~ShortGrantManager()
{
    UnRegisterAppStopListener();
}

#ifdef EVENTHANDLER_ENABLE
void ShortGrantManager::InitEventHandler()
{
    auto eventRunner = AppExecFwk::EventRunner::Create(true, AppExecFwk::ThreadMode::FFRT);
    if (!eventRunner) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create a shortGrantEventRunner.");
        return;
    }
    eventHandler_ = std::make_shared<AccessEventHandler>(eventRunner);
}

std::shared_ptr<AccessEventHandler> ShortGrantManager::GetEventHandler()
{
    std::lock_guard<std::mutex> lock(eventHandlerLock_);
    if (eventHandler_ == nullptr) {
        InitEventHandler();
    }
    return eventHandler_;
}
#endif

bool ShortGrantManager::CancelTaskOfPermissionRevoking(const std::string& taskName)
{
#ifdef EVENTHANDLER_ENABLE
    auto eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fail to get EventHandler");
        return false;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Revoke permission task name:%{public}s", taskName.c_str());
    eventHandler->ProxyRemoveTask(taskName);
    return true;
#else
    LOGW(ATM_DOMAIN, ATM_TAG, "EventHandler is not existed");
    return false;
#endif
}

int ShortGrantManager::RefreshPermission(AccessTokenID tokenID, const std::string& permission, uint32_t onceTime)
{
    if (tokenID == 0 || onceTime == 0 || onceTime > DEFAULT_MAX_ONCE_TIME_MILLISECONDS || onceTime > maxTime_) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Input invalid, tokenID: %{public}d, onceTime %{public}u!", tokenID, onceTime);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    std::string taskName = TASK_NAME_SHORT_GRANT_PERMISSION + std::to_string(tokenID) + permission;
    std::unique_lock<std::mutex> lck(shortGrantDataMutex_);

    auto iter = std::find_if(
        shortGrantData_.begin(), shortGrantData_.end(), [tokenID, permission](const PermTimerData& data) {
        return data.tokenID == tokenID && data.permissionName == permission;
    });

    if (iter == shortGrantData_.end()) {
        auto iterator = std::find(g_shortGrantPermission.begin(), g_shortGrantPermission.end(), permission);
        if (iterator == g_shortGrantPermission.end()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Permission is not available to short grant: %{public}s!", permission.c_str());
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        PermTimerData data;
        data.tokenID = tokenID;
        data.permissionName = permission;
        data.firstGrantTimes = GetCurrentTime();
        data.revokeTimes = data.firstGrantTimes + onceTime;
        int32_t ret = PermissionManager::GetInstance().GrantPermission(tokenID, permission, PERMISSION_USER_FIXED);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "GrantPermission failed result %{public}d", ret);
            return ret;
        }
        shortGrantData_.emplace_back(data);
        ShortGrantManager::GetInstance().ScheduleRevokeTask(tokenID, permission, taskName, onceTime);
        RegisterAppStopListener();
        return RET_SUCCESS;
    }

    uint32_t maxRemainedTime = maxTime_ > (GetCurrentTime() - iter->firstGrantTimes) ?
        (maxTime_ - (GetCurrentTime() - iter->firstGrantTimes)) : 0;
    uint32_t currRemainedTime = iter->revokeTimes > GetCurrentTime() ?
        (iter->revokeTimes - GetCurrentTime()) : 0;
    uint32_t cancelTimes = (maxRemainedTime > onceTime) ? onceTime : maxRemainedTime;
    if (cancelTimes > currRemainedTime) {
        iter->revokeTimes = GetCurrentTime() + cancelTimes;
        ShortGrantManager::GetInstance().CancelTaskOfPermissionRevoking(taskName);
        int32_t ret = PermissionManager::GetInstance().GrantPermission(tokenID, permission, PERMISSION_USER_FIXED);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "GrantPermission failed result %{public}d", ret);
            return ret;
        }
        ShortGrantManager::GetInstance().ScheduleRevokeTask(iter->tokenID, iter->permissionName, taskName, cancelTimes);
    }
    RegisterAppStopListener();
    return RET_SUCCESS;
}

void ShortGrantManager::ClearShortPermissionData(AccessTokenID tokenID, const std::string& permission)
{
    std::unique_lock<std::mutex> lck(shortGrantDataMutex_);
    auto item = shortGrantData_.begin();
    while (item != shortGrantData_.end()) {
        if (item->tokenID == tokenID && item->permissionName == permission) {
            // revoke without kill the app
            if (PermissionManager::GetInstance().UpdatePermission(
                tokenID, permission, false, PERMISSION_USER_FIXED, false) != RET_SUCCESS) {
                LOGE(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d revoke permission:%{public}s failed!",
                    tokenID, permission.c_str());
                return;
            }
            // clear data
            shortGrantData_.erase(item);
            if (shortGrantData_.empty()) {
                UnRegisterAppStopListener();
            }
            break;
        } else {
            ++item;
        }
    }
}

void ShortGrantManager::ClearShortPermissionByTokenID(AccessTokenID tokenID)
{
    std::unique_lock<std::mutex> lck(shortGrantDataMutex_);
    auto item = shortGrantData_.begin();
    while (item != shortGrantData_.end()) {
        if (item->tokenID == tokenID) {
            if (PermissionManager::GetInstance().UpdatePermission(
                tokenID, item->permissionName, false, PERMISSION_USER_FIXED, false) != RET_SUCCESS) {
                LOGE(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d revoke permission:%{public}s failed!",
                    tokenID, item->permissionName.c_str());
                return;
            }
            // clear task and data
            std::string taskName = TASK_NAME_SHORT_GRANT_PERMISSION + std::to_string(tokenID) + item->permissionName;
            ShortGrantManager::GetInstance().CancelTaskOfPermissionRevoking(taskName);
            item = shortGrantData_.erase(item);
        } else {
            ++item;
        }
    }
    if (shortGrantData_.empty()) {
        UnRegisterAppStopListener();
    }
}

void ShortGrantManager::ScheduleRevokeTask(AccessTokenID tokenID, const std::string& permission,
    const std::string& taskName, uint32_t cancelTimes)
{
#ifdef EVENTHANDLER_ENABLE
    auto eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fail to get EventHandler");
        return;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Add permission task name:%{public}s", taskName.c_str());

    std::function<void()> delayed = ([tokenID, permission]() {
        ShortGrantManager::GetInstance().ClearShortPermissionData(tokenID, permission);
        LOGI(ATM_DOMAIN, ATM_TAG,
            "Token: %{public}d, permission: %{public}s, delay revoke permission end.", tokenID, permission.c_str());
    });
    LOGI(ATM_DOMAIN, ATM_TAG, "cancelTimes %{public}d", cancelTimes);
    eventHandler->ProxyPostTask(delayed, taskName, cancelTimes * 1000); // 1000 means to ms
    return;
#else
    LOGW(ATM_DOMAIN, ATM_TAG, "eventHandler is not existed");
    return;
#endif
}

uint32_t ShortGrantManager::GetCurrentTime()
{
    return static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch() / std::chrono::seconds(1));
}

bool ShortGrantManager::IsShortGrantPermission(const std::string& permissionName)
{
    auto it = find(g_shortGrantPermission.begin(), g_shortGrantPermission.end(), permissionName);
    if (it == g_shortGrantPermission.end()) {
        return false;
    }
    return true;
}

void ShortGrantManager::RegisterAppStopListener()
{
    {
        std::lock_guard<std::mutex> lock(appManagerDeathMutex_);
        if (appManagerDeathCallback_ == nullptr) {
            appManagerDeathCallback_ = std::make_shared<ShortPermAppManagerDeathCallback>();
            if (appManagerDeathCallback_ == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Register appManagerDeathCallback failed.");
                return;
            }
            AppManagerAccessClient::GetInstance().RegisterDeathCallback(appManagerDeathCallback_);
        }
    }
    {
        std::lock_guard<std::mutex> lock(appStopCallbackMutex_);
        if (appStopCallBack_ == nullptr) {
            appStopCallBack_ = new (std::nothrow) ShortPermAppStateObserver();
            if (appStopCallBack_ == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Register appStopCallBack failed.");
                return;
            }
            int ret = AppManagerAccessClient::GetInstance().RegisterApplicationStateObserver(appStopCallBack_);
            if (ret != ERR_OK) {
                LOGI(ATM_DOMAIN, ATM_TAG, "Register appStopCallBack %{public}d.", ret);
            }
        }
    }
}

void ShortGrantManager::UnRegisterAppStopListener()
{
    std::lock_guard<std::mutex> lock(appStopCallbackMutex_);
    if (appStopCallBack_ != nullptr) {
        int32_t ret = AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(appStopCallBack_);
        if (ret != ERR_OK) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Unregister appStopCallback %{public}d.", ret);
        }
        appStopCallBack_= nullptr;
    }
}

ShortGrantManager::ShortGrantManager() : maxTime_(DEFAULT_MAX_TIME_MILLISECONDS)
{}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS