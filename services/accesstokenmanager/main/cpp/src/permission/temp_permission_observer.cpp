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

#include "temp_permission_observer.h"

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_log.h"
#include "app_manager_access_client.h"
#include "permission_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TempPermissionObserver"};
static const std::string TASK_NAME_TEMP_PERMISSION = "atm_permission_manager_temp_permission";
static constexpr int32_t WAIT_MILLISECONDS = 10 * 1000; // 10s
}
std::recursive_mutex TempPermissionObserver::mutex_;
TempPermissionObserver* TempPermissionObserver::implInstance_ = nullptr;

TempPermissionObserver& TempPermissionObserver::GetInstance()
{
    if (implInstance_ == nullptr) {
        std::lock_guard<std::recursive_mutex> lock_l(mutex_);
        if (implInstance_ == nullptr) {
            implInstance_ = new TempPermissionObserver();
        }
    }
    return *implInstance_;
}

void PermissionAppStateObserver::OnProcessDied(const ProcessData &processData)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OnProcessDied die accessTokenId %{public}d", processData.accessTokenId);

    uint32_t tokenId = processData.accessTokenId;
    TempPermissionObserver::GetInstance().RevokeAllTempPermission(tokenId);
}

void PermissionAppStateObserver::OnForegroundApplicationChanged(const AppStateData &appStateData)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OnChange(accessTokenId=%{public}d, state=%{public}d)",
        appStateData.accessTokenId, appStateData.state);
    uint32_t tokenId = appStateData.accessTokenId;
    if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND)) {
        std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(tokenId);
        if (!TempPermissionObserver::GetInstance().CancleTaskOfPermissionRevoking(taskName)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "CancleTaskOfPermissionRevoking failed!!!");
        }
    } else if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND)) {
        std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(tokenId);
        if (!TempPermissionObserver::GetInstance().DelayRevokePermission(tokenId, taskName)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "DelayRevokePermission failed!!!");
        }
    }
}

void PermissionAppManagerDeathCallback::NotifyAppManagerDeath()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "TempPermissionObserver AppManagerDeath called");

    TempPermissionObserver::GetInstance().OnAppMgrRemoteDiedHandle();
}

TempPermissionObserver::TempPermissionObserver()
{}

TempPermissionObserver::~TempPermissionObserver()
{
    std::lock_guard<std::mutex> lock(appStateMutex_);
    if (appStateCallback_ != nullptr) {
        AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(appStateCallback_);
        appStateCallback_= nullptr;
    }
}

void TempPermissionObserver::RegisterApplicationCallback()
{
    std::lock_guard<std::mutex> lock(appStateMutex_);
    if (appStateCallback_ == nullptr) {
        appStateCallback_ = new(std::nothrow) PermissionAppStateObserver();
        if (appStateCallback_ == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "register appStateCallback failed.");
            return;
        }
        AppManagerAccessClient::GetInstance().RegisterApplicationStateObserver(appStateCallback_);
    }
}

void TempPermissionObserver::RegisterAppManagerDeathCallback()
{
    std::lock_guard<std::mutex> lock(appManagerDeathMutex_);
    if (appManagerDeathCallback_ == nullptr) {
        appManagerDeathCallback_ = std::make_shared<PermissionAppManagerDeathCallback>();
        AppManagerAccessClient::GetInstance().RegisterDeathCallbak(appManagerDeathCallback_);
    }
}

void TempPermissionObserver::AddPermToPermMap(AccessTokenID tokenID, const std::string& permissionName)
{
    std::unique_lock<std::mutex> lck(processPermMutex_);

    if (processPermMap_.find(tokenID) == processPermMap_.end()) {
        std::vector<std::string> permList { permissionName };
        processPermMap_[tokenID] = permList;
        return;
    }

    std::vector<std::string> permList = processPermMap_[tokenID];
    auto iter = std::find_if(permList.begin(), permList.end(), [permissionName](const std::string& perm) {
        return permissionName == perm;
    });
    if (iter == permList.end()) {
        processPermMap_[tokenID].emplace_back(permissionName);
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "permission:%{public}s has existed in permList", permissionName.c_str());
}

void TempPermissionObserver::DeletePermFromPermMap(AccessTokenID tokenID, const std::string& permissionName)
{
    std::unique_lock<std::mutex> lck(processPermMutex_);
    auto it = processPermMap_.find(tokenID);
    if (it == processPermMap_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId:%{public}d not exist in permList", tokenID);
        return;
    }

    auto iter = std::find_if(it->second.begin(), it->second.end(), [permissionName](const std::string& perm) {
        return permissionName == perm;
    });
    if (iter != it->second.end()) {
        it->second.erase(iter);
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "permission:%{public}s has been earsed from permList", permissionName.c_str());
    if (it->second.empty()) {
        processPermMap_.erase(it->first);
    }
    if (processPermMap_.empty()) {
        std::lock_guard<std::mutex> lock(appStateMutex_);
        if (appStateCallback_ != nullptr) {
            AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(appStateCallback_);
            appStateCallback_= nullptr;
        }
    }
}

void TempPermissionObserver::RevokeAllTempPermission(AccessTokenID tokenID)
{
    std::vector<std::string> permList {};
    {
        std::unique_lock<std::mutex> lck(processPermMutex_);
        auto it = processPermMap_.find(tokenID);
        if (it == processPermMap_.end()) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID:%{public}d doesn't request permissions!", tokenID);
            return;
        }
        permList = it->second;
        processPermMap_.erase(tokenID);
    }
    if (processPermMap_.empty()) {
        std::lock_guard<std::mutex> lock(appStateMutex_);
        if (appStateCallback_ != nullptr) {
            AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(appStateCallback_);
            appStateCallback_= nullptr;
        }
    }
    for (const auto& permission : permList) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission:%{public}s", permission.c_str());
        if (PermissionManager::GetInstance().RevokePermission(
            tokenID, permission, PERMISSION_ALLOW_THIS_TIME) != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID:%{public}d revoke permission:%{public}s failed!",
                tokenID, permission.c_str());
        }
    }
}

void TempPermissionObserver::OnAppMgrRemoteDiedHandle()
{
    {
        std::unique_lock<std::mutex> lck(processPermMutex_);
        for (auto it = processPermMap_.begin(); it != processPermMap_.end(); ++it) {
            for (const auto& permission : it->second) {
                if (PermissionManager::GetInstance().RevokePermission(
                    it->first, permission, PERMISSION_ALLOW_THIS_TIME) != RET_SUCCESS) {
                    ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID:%{public}d revoke permission:%{public}s failed!",
                        it->first, permission.c_str());
                }
            }
        }
        processPermMap_.clear();
        ACCESSTOKEN_LOG_INFO(LABEL, "processPermMap_ clear!");
    }
    {
        std::lock_guard<std::mutex> lock(appStateMutex_);
        if (appStateCallback_ != nullptr) {
            AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(appStateCallback_);
            appStateCallback_= nullptr;
        }
    }
}

void TempPermissionObserver::InitEventHandler(const std::shared_ptr<AccessEventHandler>& eventHandler)
{
    eventHandler_ = eventHandler;
}

bool TempPermissionObserver::DelayRevokePermission(AccessToken::AccessTokenID tokenId, const std::string& taskName)
{
    if (eventHandler_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "fail to get EventHandler");
        return false;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "add permission task name:%{public}s", taskName.c_str());

    std::function<void()> delayed = ([tokenId]() {
        TempPermissionObserver::GetInstance().RevokeAllTempPermission(tokenId);
        ACCESSTOKEN_LOG_INFO(LABEL, "delay revoke permission");
    });

    ACCESSTOKEN_LOG_INFO(LABEL, "revoke permission after %{public}d ms", WAIT_MILLISECONDS);
    eventHandler_->ProxyPostTask(delayed, taskName, WAIT_MILLISECONDS);
    return true;
}

bool TempPermissionObserver::CancleTaskOfPermissionRevoking(const std::string& taskName)
{
    if (eventHandler_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "fail to get EventHandler");
        return false;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "revoke permission task name:%{public}s", taskName.c_str());
    eventHandler_->ProxyRemoveTask(taskName);
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
