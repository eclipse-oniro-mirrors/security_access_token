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
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "app_manager_access_client.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TempPermissionObserver"};
static const std::string TASK_NAME_TEMP_PERMISSION = "atm_permission_manager_temp_permission";
#ifdef EVENTHANDLER_ENABLE
static constexpr int32_t WAIT_MILLISECONDS = 10 * 1000; // 10s
#endif
std::recursive_mutex g_instanceMutex;
}

TempPermissionObserver& TempPermissionObserver::GetInstance()
{
    static TempPermissionObserver* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new TempPermissionObserver();
        }
    }
    return *instance;
}

void PermissionAppStateObserver::OnProcessDied(const ProcessData &processData)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OnProcessDied die accessTokenId %{public}d", processData.accessTokenId);

    uint32_t tokenID = processData.accessTokenId;
    // cancle task when process die
    std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(tokenID);
    TempPermissionObserver::GetInstance().CancleTaskOfPermissionRevoking(taskName);
    TempPermissionObserver::GetInstance().RevokeAllTempPermission(tokenID);
}

void PermissionAppStateObserver::OnForegroundApplicationChanged(const AppStateData &appStateData)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "OnChange(accessTokenId=%{public}d, state=%{public}d)",
        appStateData.accessTokenId, appStateData.state);
    uint32_t tokenID = appStateData.accessTokenId;
    if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND)) {
        std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(tokenID);
        if (!TempPermissionObserver::GetInstance().CancleTaskOfPermissionRevoking(taskName)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "CancleTaskOfPermissionRevoking failed!!!");
        }
    } else if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND)) {
        std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(tokenID);
        if (!TempPermissionObserver::GetInstance().DelayRevokePermission(tokenID, taskName)) {
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
    std::lock_guard<std::mutex> lock(tempPermissionMutex_);
    if (appStateCallback_ != nullptr) {
        AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(appStateCallback_);
        appStateCallback_= nullptr;
    }
}

void TempPermissionObserver::RegisterCallback()
{
    if (appStateCallback_ == nullptr) {
        appStateCallback_ = new (std::nothrow) PermissionAppStateObserver();
        if (appStateCallback_ == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "register appStateCallback failed.");
            return;
        }
        AppManagerAccessClient::GetInstance().RegisterApplicationStateObserver(appStateCallback_);
    }
    if (appManagerDeathCallback_ == nullptr) {
        appManagerDeathCallback_ = std::make_shared<PermissionAppManagerDeathCallback>();
        AppManagerAccessClient::GetInstance().RegisterDeathCallbak(appManagerDeathCallback_);
    }
}

void TempPermissionObserver::AddTempPermTokenToList(AccessTokenID tokenID, const std::string& permissionName)
{
    std::unique_lock<std::mutex> lck(tempPermissionMutex_);
    RegisterCallback();
    auto iter = std::find_if(tempPermTokenList_.begin(), tempPermTokenList_.end(), [tokenID](const AccessTokenID& id) {
        return tokenID == id;
    });
    if (iter != tempPermTokenList_.end()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "tokenID:%{public}d has existed in tokenList", tokenID);
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID:%{public}d added in tokenList", tokenID);
    tempPermTokenList_.emplace_back(tokenID);
}

void TempPermissionObserver::DeleteTempPermFromList(AccessTokenID tokenID, const std::string& permissionName)
{
    std::unique_lock<std::mutex> lck(tempPermissionMutex_);
    auto iter = std::find_if(tempPermTokenList_.begin(), tempPermTokenList_.end(), [tokenID](const AccessTokenID& id) {
        return tokenID == id;
    });
    if (iter == tempPermTokenList_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID:%{public}d not exist in tokenList", tokenID);
        return;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "permission:%{public}s has been erased from permList", permissionName.c_str());
    tempPermTokenList_.erase(iter);
    if (tempPermTokenList_.empty()) {
        if (appStateCallback_ != nullptr) {
            AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(appStateCallback_);
            appStateCallback_= nullptr;
        }
    }
}

bool TempPermissionObserver::GetPermissionStateFull(AccessTokenID tokenID,
    std::vector<PermissionStateFull>& permissionStateFullList)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "token %{public}u is invalid.", tokenID);
        return false;
    }
    if (infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "it is a remote hap token %{public}u!", tokenID);
        return false;
    }
    std::shared_ptr<PermissionPolicySet> permPolicySet = infoPtr->GetHapInfoPermissionPolicySet();
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return false;
    }

    permPolicySet->GetPermissionStateFulls(permissionStateFullList);
    return true;
}

void TempPermissionObserver::RevokeAllTempPermission(AccessTokenID tokenID)
{
    std::unique_lock<std::mutex> lck(tempPermissionMutex_);
    auto iter = std::find_if(tempPermTokenList_.begin(), tempPermTokenList_.end(), [tokenID](const AccessTokenID& id) {
        return tokenID == id;
    });
    if (iter == tempPermTokenList_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID:%{public}d not exist in permList", tokenID);
        return;
    }
    tempPermTokenList_.erase(iter);
    if (tempPermTokenList_.empty()) {
        if (appStateCallback_ != nullptr) {
            AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(appStateCallback_);
            appStateCallback_= nullptr;
        }
    }

    std::vector<PermissionStateFull> tmpList;
    if (!GetPermissionStateFull(tokenID, tmpList)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID:%{public}d get permission state full fail!", tokenID);
        return;
    }
    for (const auto& permissionState : tmpList) {
        if (permissionState.grantFlags[0] == PERMISSION_ALLOW_THIS_TIME) {
            if (PermissionManager::GetInstance().RevokePermission(
                tokenID, permissionState.permissionName, PERMISSION_ALLOW_THIS_TIME) != RET_SUCCESS) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID:%{public}d revoke permission:%{public}s failed!",
                    tokenID, permissionState.permissionName.c_str());
                return;
            }
        }
    }
}

void TempPermissionObserver::OnAppMgrRemoteDiedHandle()
{
    std::unique_lock<std::mutex> lck(tempPermissionMutex_);
    for (auto iter = tempPermTokenList_.begin(); iter != tempPermTokenList_.end(); ++iter) {
        std::vector<PermissionStateFull> tmpList;
        GetPermissionStateFull(*iter, tmpList);
        for (const auto& permissionState : tmpList) {
            if (permissionState.grantFlags[0] == PERMISSION_ALLOW_THIS_TIME) {
                PermissionManager::GetInstance().RevokePermission(
                    *iter, permissionState.permissionName, PERMISSION_ALLOW_THIS_TIME);
            }
        }
        std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(*iter);
        TempPermissionObserver::GetInstance().CancleTaskOfPermissionRevoking(taskName);
    }
    tempPermTokenList_.clear();
    ACCESSTOKEN_LOG_INFO(LABEL, "tempPermTokenList_ clear!");
    appStateCallback_= nullptr;
}

#ifdef EVENTHANDLER_ENABLE
void TempPermissionObserver::InitEventHandler(const std::shared_ptr<AccessEventHandler>& eventHandler)
{
    eventHandler_ = eventHandler;
}
#endif

bool TempPermissionObserver::DelayRevokePermission(AccessToken::AccessTokenID tokenID, const std::string& taskName)
{
#ifdef EVENTHANDLER_ENABLE
    if (eventHandler_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "fail to get EventHandler");
        return false;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "add permission task name:%{public}s", taskName.c_str());

    std::function<void()> delayed = ([tokenID]() {
        TempPermissionObserver::GetInstance().RevokeAllTempPermission(tokenID);
        ACCESSTOKEN_LOG_INFO(LABEL, "token: %{public}d, delay revoke permission end", tokenID);
    });

    eventHandler_->ProxyPostTask(delayed, taskName, WAIT_MILLISECONDS);
    return true;
#else
    return false;
#endif
}

bool TempPermissionObserver::CancleTaskOfPermissionRevoking(const std::string& taskName)
{
#ifdef EVENTHANDLER_ENABLE
    if (eventHandler_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "fail to get EventHandler");
        return false;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "revoke permission task name:%{public}s", taskName.c_str());
    eventHandler_->ProxyRemoveTask(taskName);
    return true;
#else
    return false;
#endif
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
