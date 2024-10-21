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
#include "permission_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "ShortGrantManager"};
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
            instance = new ShortGrantManager();
        }
    }
    return *instance;
}

void ShortGrantManager::InitEventHandler(const std::shared_ptr<AccessEventHandler>& eventHandler)
{
    eventHandler_ = eventHandler;
}

bool ShortGrantManager::CancelTaskOfPermissionRevoking(const std::string& taskName)
{
#ifdef EVENTHANDLER_ENABLE
    if (eventHandler_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to get EventHandler");
        return false;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "Revoke permission task name:%{public}s", taskName.c_str());
    eventHandler_->ProxyRemoveTask(taskName);
    return true;
#else
    ACCESSTOKEN_LOG_WARN(LABEL, "EventHandler is not existed");
    return false;
#endif
}

int ShortGrantManager::RefreshPermission(AccessTokenID tokenID, const std::string& permission, uint32_t onceTime)
{
    if (tokenID == 0 || onceTime == 0 || onceTime > DEFAULT_MAX_ONCE_TIME_MILLISECONDS || onceTime > maxTime_) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "Input invalid, tokenID is: %{public}d, onceTime is %{public}u!", tokenID, onceTime);
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
            ACCESSTOKEN_LOG_ERROR(LABEL, "Permission is not available to short grant: %{public}s!", permission.c_str());
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        PermTimerData data;
        data.tokenID = tokenID;
        data.permissionName = permission;
        data.firstGrantTimes = GetCurrentTime();
        data.revokeTimes = data.firstGrantTimes + onceTime;
        shortGrantData_.emplace_back(data);
        int32_t ret = PermissionManager::GetInstance().GrantPermission(tokenID, permission, PERMISSION_USER_FIXED);
        if (ret != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GrantPermission failed result %{public}d", ret);
            return ret;
        }
        ShortGrantManager::GetInstance().ScheduleRevokeTask(tokenID, permission, taskName, onceTime);
        return RET_SUCCESS;
    }

    uint32_t maxRemainedTime = maxTime_ > (GetCurrentTime() - iter->firstGrantTimes) ?
        maxTime_ - (GetCurrentTime() - iter->firstGrantTimes) : 0;
    uint32_t currRemainedTime = iter->revokeTimes > GetCurrentTime() ? iter->revokeTimes - GetCurrentTime() : 0;
    uint32_t cancelTimes = (maxRemainedTime > onceTime) ? onceTime : maxRemainedTime;
    if (cancelTimes > currRemainedTime) {
        iter->revokeTimes = GetCurrentTime() + cancelTimes;
        ShortGrantManager::GetInstance().CancelTaskOfPermissionRevoking(taskName);
        int32_t ret = PermissionManager::GetInstance().GrantPermission(tokenID, permission, PERMISSION_USER_FIXED);
        if (ret != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GrantPermission failed result %{public}d", ret);
            return ret;
        }
        ShortGrantManager::GetInstance().ScheduleRevokeTask(iter->tokenID, iter->permissionName, taskName, cancelTimes);
    }
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
                ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID:%{public}d revoke permission:%{public}s failed!",
                    tokenID, permission.c_str());
                return;
            }
            // clear data
            shortGrantData_.erase(item);
            break;
        } else {
            ++item;
        }
    }
}

void ShortGrantManager::ScheduleRevokeTask(AccessTokenID tokenID, const std::string& permission,
    const std::string& taskName, uint32_t cancelTimes)
{
#ifdef EVENTHANDLER_ENABLE
    if (eventHandler_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to get EventHandler");
        return;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "Add permission task name:%{public}s", taskName.c_str());

    std::function<void()> delayed = ([tokenID, permission]() {
        ShortGrantManager::GetInstance().ClearShortPermissionData(tokenID, permission);
        ACCESSTOKEN_LOG_INFO(LABEL,
            "Token: %{public}d, permission: %{public}s, delay revoke permission end.", tokenID, permission.c_str());
    });
    eventHandler_->ProxyPostTask(delayed, taskName, cancelTimes * 1000); // 1000 means to ms
    return;
#else
    ACCESSTOKEN_LOG_WARN(LABEL, "eventHandler is not existed");
    return;
#endif
}

uint32_t ShortGrantManager::GetCurrentTime()
{
    return static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch() / std::chrono::seconds(1));
}

bool IsShortGrantPermission(const std::string& permissionName)
{
    auto it = find(g_shortGrantPermission.begin(), g_shortGrantPermission.end(), permissionName);
    if (it == g_shortGrantPermission.end()) {
        return false;
    }
    return true;
}

ShortGrantManager::ShortGrantManager() : maxTime_(DEFAULT_MAX_TIME_MILLISECONDS)
{}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS