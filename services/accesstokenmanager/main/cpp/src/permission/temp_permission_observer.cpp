/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "config_policy_loader.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "libraryloader.h"
#include "app_manager_access_client.h"
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
#include "background_task_manager_access_client.h"
#endif
#include "form_manager_access_client.h"
#include "hisysevent.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TempPermissionObserver"};
static const std::string TASK_NAME_TEMP_PERMISSION = "atm_permission_manager_temp_permission";
static const std::string FORM_INVISIBLE_NAME = "#0";
static const std::string FORM_VISIBLE_NAME = "#1";
static constexpr int32_t ROOT_UID = 0;
static constexpr int32_t FOREGROUND_FLAG = 0;
static constexpr int32_t FORMS_FLAG = 1;
static constexpr int32_t CONTINUOUS_TASK_FLAG = 2;
#ifdef EVENTHANDLER_ENABLE
static constexpr int32_t DEFAULT_CANCLE_MILLISECONDS = 10 * 1000; // 10s
#endif
std::recursive_mutex g_instanceMutex;
static const std::vector<std::string> g_tempPermission = {
    "ohos.permission.READ_PASTEBOARD",
    "ohos.permission.APPROXIMATELY_LOCATION",
    "ohos.permission.LOCATION",
    "ohos.permission.LOCATION_IN_BACKGROUND"
};
}

TempPermissionObserver& TempPermissionObserver::GetInstance()
{
    static TempPermissionObserver* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            TempPermissionObserver* tmp = new TempPermissionObserver();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

void PermissionAppStateObserver::OnAppStateChanged(const AppStateData &appStateData)
{
    uint32_t tokenID = appStateData.accessTokenId;
    std::vector<bool> list;
    if (!TempPermissionObserver::GetInstance().GetAppStateListByTokenID(tokenID, list)) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "TokenID:%{public}d not use temp permission", tokenID);
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "OnChange(accessTokenId=%{public}d, state=%{public}d)", tokenID, appStateData.state);
    if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND)) {
        TempPermissionObserver::GetInstance().ModifyAppState(tokenID, FOREGROUND_FLAG, true);
        std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(tokenID);
        TempPermissionObserver::GetInstance().CancleTaskOfPermissionRevoking(taskName);
    } else if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND)) {
        TempPermissionObserver::GetInstance().ModifyAppState(tokenID, FOREGROUND_FLAG, false);
        if (list[FORMS_FLAG]) {
            ACCESSTOKEN_LOG_WARN(LABEL, "%{public}d:tokenID has form, don't delayRevokePermission!", tokenID);
            return;
        }
        if (list[CONTINUOUS_TASK_FLAG]) {
            ACCESSTOKEN_LOG_WARN(LABEL, "%{public}d:tokenID has continuoustask, don't delayRevokePermission!", tokenID);
            return;
        }
        std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(tokenID);
        TempPermissionObserver::GetInstance().DelayRevokePermission(tokenID, taskName);
    }
}

void PermissionAppStateObserver::OnAppStopped(const AppStateData &appStateData)
{
    if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED)) {
        uint32_t tokenID = appStateData.accessTokenId;
        ACCESSTOKEN_LOG_INFO(LABEL, "TokenID:%{public}d died.", tokenID);
        // cancle task when process die
        std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(tokenID);
        TempPermissionObserver::GetInstance().CancleTaskOfPermissionRevoking(taskName);
        TempPermissionObserver::GetInstance().RevokeAllTempPermission(tokenID);
    }
}

void PermissionAppStateObserver::OnAppCacheStateChanged(const AppStateData &appStateData)
{
    uint32_t tokenID = appStateData.accessTokenId;
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenID is %{public}d, state is %{public}d.", tokenID, appStateData.state);

    /*
        warm start application shut down application do not means kill process,
        actually this operation means application turn background with OnAppCacheStateChanged callback,
        so temporary authorization should be cancle as OnAppStopped when receive this callback
     */
    std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(tokenID);
    TempPermissionObserver::GetInstance().CancleTaskOfPermissionRevoking(taskName);
    TempPermissionObserver::GetInstance().RevokeAllTempPermission(tokenID);
}

int32_t PermissionFormStateObserver::NotifyWhetherFormsVisible(const FormVisibilityType visibleType,
    const std::string &bundleName, std::vector<FormInstance> &formInstances)
{
    for (size_t i = 0; i < formInstances.size(); i++) {
        AccessTokenID tokenID;
        if (!TempPermissionObserver::GetInstance().GetTokenIDByBundle(formInstances[i].bundleName_, tokenID)) {
            continue;
        }
        std::vector<bool> list;
        if (!TempPermissionObserver::GetInstance().GetAppStateListByTokenID(tokenID, list)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID:%{public}d not use temp permission", tokenID);
            continue;
        }

        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s, tokenID: %{public}d, formVisiblity:%{public}d",
            formInstances[i].bundleName_.c_str(), tokenID, formInstances[i].formVisiblity_);

        if (formInstances[i].formVisiblity_ == FormVisibilityType::VISIBLE) {
            TempPermissionObserver::GetInstance().ModifyAppState(tokenID, FORMS_FLAG, true);
            std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(tokenID);
            TempPermissionObserver::GetInstance().CancleTaskOfPermissionRevoking(taskName);
        } else if (formInstances[i].formVisiblity_ == FormVisibilityType::INVISIBLE) {
            TempPermissionObserver::GetInstance().ModifyAppState(tokenID, FORMS_FLAG, false);
            if (list[FOREGROUND_FLAG]) {
                ACCESSTOKEN_LOG_WARN(LABEL, "%{public}d:tokenID in foreground don't delayRevokePermission!", tokenID);
                continue;
            }
            if (list[CONTINUOUS_TASK_FLAG]) {
                ACCESSTOKEN_LOG_WARN(LABEL, "%{public}d:tokenID has task, don't delayRevokePermission!", tokenID);
                continue;
            }
            std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(tokenID);
            TempPermissionObserver::GetInstance().DelayRevokePermission(tokenID, taskName);
        }
    }
    return RET_SUCCESS;
}
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
void PermissionBackgroundTaskObserver::OnContinuousTaskStart(
    const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo)
{
    AccessTokenID tokenID = static_cast<AccessTokenID>(continuousTaskCallbackInfo->GetFullTokenId());
    uint32_t typeId = continuousTaskCallbackInfo->GetTypeId();
    if (static_cast<BackgroundMode>(typeId) != BackgroundMode::LOCATION) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "TypeId:%{public}d can not use temp permission", typeId);
        return;
    }
    std::vector<bool> list;
    if (!TempPermissionObserver::GetInstance().GetAppStateListByTokenID(tokenID, list)) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "TokenID:%{public}d not use temp permission", tokenID);
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}d", tokenID);
    TempPermissionObserver::GetInstance().AddContinuousTask(tokenID);
    TempPermissionObserver::GetInstance().ModifyAppState(tokenID, CONTINUOUS_TASK_FLAG, true);
    std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(tokenID);
    TempPermissionObserver::GetInstance().CancleTaskOfPermissionRevoking(taskName);
}

void PermissionBackgroundTaskObserver::OnContinuousTaskStop(
    const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo)
{
    AccessTokenID tokenID = static_cast<AccessTokenID>(continuousTaskCallbackInfo->GetFullTokenId());
    uint32_t typeId = continuousTaskCallbackInfo->GetTypeId();
    if (static_cast<BackgroundMode>(typeId) != BackgroundMode::LOCATION) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "TypeId:%{public}d can not use temp permission", typeId);
        return;
    }
    std::vector<bool> list;
    if (!TempPermissionObserver::GetInstance().GetAppStateListByTokenID(tokenID, list)) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "TokenID:%{public}d not use temp permission", tokenID);
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}d", tokenID);
    TempPermissionObserver::GetInstance().DelContinuousTask(tokenID);
    if (TempPermissionObserver::GetInstance().FindContinuousTask(tokenID)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "Has continuous task don't delayRevokePermission!");
        return;
    }
    TempPermissionObserver::GetInstance().ModifyAppState(tokenID, CONTINUOUS_TASK_FLAG, false);
    if (list[FOREGROUND_FLAG] || list[FORMS_FLAG]) {
        ACCESSTOKEN_LOG_WARN(LABEL, "Has form or inForeground don't delayRevokePermission!");
        return;
    }
    std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(tokenID);
    TempPermissionObserver::GetInstance().DelayRevokePermission(tokenID, taskName);
}
#endif
void PermissionAppManagerDeathCallback::NotifyAppManagerDeath()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "TempPermissionObserver AppManagerDeath called");

    TempPermissionObserver::GetInstance().OnAppMgrRemoteDiedHandle();
}

TempPermissionObserver::TempPermissionObserver() : cancleTimes_(DEFAULT_CANCLE_MILLISECONDS)
{}

TempPermissionObserver::~TempPermissionObserver()
{
    UnRegisterCallback();
}

void TempPermissionObserver::RegisterCallback()
{
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
    {
        std::lock_guard<std::mutex> lock(backgroundTaskCallbackMutex_);
        if (backgroundTaskCallback_ == nullptr) {
            backgroundTaskCallback_ = new (std::nothrow) PermissionBackgroundTaskObserver();
            if (backgroundTaskCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Register backgroundTaskCallback failed.");
                return;
            }
            int ret = BackgourndTaskManagerAccessClient::GetInstance().SubscribeBackgroundTask(backgroundTaskCallback_);
            ACCESSTOKEN_LOG_INFO(LABEL, "Register backgroundTaskCallback %{public}d.", ret);
        }
    }
#endif
    {
        std::lock_guard<std::mutex> lock(formStateCallbackMutex_);
        if (formVisibleCallback_ == nullptr) {
            formVisibleCallback_ = new (std::nothrow) PermissionFormStateObserver();
            if (formVisibleCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Register formStateCallback failed.");
                return;
            }
            int ret = FormManagerAccessClient::GetInstance().RegisterAddObserver(
                FORM_VISIBLE_NAME, formVisibleCallback_->AsObject());
            if (ret != ERR_OK) {
                ACCESSTOKEN_LOG_INFO(LABEL, "Register observer %{public}d.", ret);
            }
        }
        if (formInvisibleCallback_ == nullptr) {
            formInvisibleCallback_ = new (std::nothrow) PermissionFormStateObserver();
            if (formInvisibleCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Register formStateCallback failed.");
                formVisibleCallback_ = nullptr;
                return;
            }
            int ret = FormManagerAccessClient::GetInstance().RegisterAddObserver(
                FORM_INVISIBLE_NAME, formInvisibleCallback_->AsObject());
            if (ret != ERR_OK) {
                ACCESSTOKEN_LOG_INFO(LABEL, "Register observer %{public}d.", ret);
            }
        }
    }
    RegisterAppStatusListener();
}

void TempPermissionObserver::RegisterAppStatusListener()
{
    {
        std::lock_guard<std::mutex> lock(appStateCallbackMutex_);
        if (appStateCallback_ == nullptr) {
            appStateCallback_ = new (std::nothrow) PermissionAppStateObserver();
            if (appStateCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Register appStateCallback failed.");
                return;
            }
            int ret = AppManagerAccessClient::GetInstance().RegisterApplicationStateObserver(appStateCallback_);
            if (ret != ERR_OK) {
                ACCESSTOKEN_LOG_INFO(LABEL, "Register appStateCallback %{public}d.", ret);
            }
        }
    }
    // app manager death callback register
    {
        std::lock_guard<std::mutex> lock(appManagerDeathMutex_);
        if (appManagerDeathCallback_ == nullptr) {
            appManagerDeathCallback_ = std::make_shared<PermissionAppManagerDeathCallback>();
            if (appManagerDeathCallback_ == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Register appManagerDeathCallback failed.");
                return;
            }
            AppManagerAccessClient::GetInstance().RegisterDeathCallback(appManagerDeathCallback_);
        }
    }
}

void TempPermissionObserver::UnRegisterCallback()
{
    {
        std::lock_guard<std::mutex> lock(appStateCallbackMutex_);
        if (appStateCallback_ != nullptr) {
            int32_t ret = AppManagerAccessClient::GetInstance().UnregisterApplicationStateObserver(appStateCallback_);
            if (ret != ERR_OK) {
                ACCESSTOKEN_LOG_INFO(LABEL, "Unregister appStateCallback %{public}d.", ret);
            }
            appStateCallback_= nullptr;
        }
    }
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
    {
        std::lock_guard<std::mutex> lock(backgroundTaskCallbackMutex_);
        if (backgroundTaskCallback_ != nullptr) {
            int32_t ret = BackgourndTaskManagerAccessClient::GetInstance().UnsubscribeBackgroundTask(
                backgroundTaskCallback_);
            if (ret != ERR_NONE) {
                ACCESSTOKEN_LOG_INFO(LABEL, "Unregister appStateCallback %{public}d.", ret);
            }
            backgroundTaskCallback_= nullptr;
        }
    }
#endif
    {
        std::lock_guard<std::mutex> lock(formStateCallbackMutex_);
        if (formVisibleCallback_ != nullptr) {
            int32_t ret = FormManagerAccessClient::GetInstance().RegisterRemoveObserver(
                FORM_VISIBLE_NAME,
                formVisibleCallback_);
            if (ret != ERR_OK) {
                ACCESSTOKEN_LOG_INFO(LABEL, "Unregister appStateCallback %{public}d.", ret);
            }
            formVisibleCallback_ = nullptr;
        }
        if (formInvisibleCallback_ != nullptr) {
            int32_t ret = FormManagerAccessClient::GetInstance().RegisterRemoveObserver(
                FORM_INVISIBLE_NAME, formInvisibleCallback_);
            if (ret != ERR_OK) {
                ACCESSTOKEN_LOG_INFO(LABEL, "Unregister appStateCallback %{public}d.", ret);
            }
            formInvisibleCallback_ = nullptr;
        }
    }
}

bool TempPermissionObserver::GetAppStateListByTokenID(AccessTokenID tokenID, std::vector<bool>& list)
{
    std::unique_lock<std::mutex> lck(tempPermissionMutex_);
    auto iter = tempPermTokenMap_.find(tokenID);
    if (iter == tempPermTokenMap_.end()) {
        return false;
    }
    list = iter->second;
    return true;
}

void TempPermissionObserver::ModifyAppState(AccessTokenID tokenID, int32_t index, bool flag)
{
    std::unique_lock<std::mutex> lck(tempPermissionMutex_);
    auto iter = tempPermTokenMap_.find(tokenID);
    if (iter == tempPermTokenMap_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID:%{public}d not exist in map", tokenID);
        return;
    }
    iter->second[index] = flag;
}

bool TempPermissionObserver::GetTokenIDByBundle(const std::string &bundleName, AccessTokenID& tokenID)
{
    std::unique_lock<std::mutex> lck(formTokenMutex_);
    auto iter = formTokenMap_.find(bundleName);
    if (iter == formTokenMap_.end()) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "BundleName:%{public}s not exist in map", bundleName.c_str());
        return false;
    }
    tokenID = iter->second;
    return true;
}

void TempPermissionObserver::AddContinuousTask(AccessTokenID tokenID)
{
    std::unique_lock<std::mutex> lck(continuousTaskMutex_);
    auto iter = continuousTaskMap_.find(tokenID);
    if (iter == continuousTaskMap_.end()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "TokenID:%{public}d not exist in map", tokenID);
        continuousTaskMap_[tokenID] = 1;
        return;
    }
    continuousTaskMap_[tokenID]++;
}

void TempPermissionObserver::DelContinuousTask(AccessTokenID tokenID)
{
    std::unique_lock<std::mutex> lck(continuousTaskMutex_);
    auto iter = continuousTaskMap_.find(tokenID);
    if (iter == continuousTaskMap_.end()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "TokenID:%{public}d not exist in map", tokenID);
        return;
    }
    continuousTaskMap_[tokenID]--;
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenID:%{public}d has %{public}d tasks in map",
        tokenID, continuousTaskMap_[tokenID]);
    if (continuousTaskMap_[tokenID] == 0) {
        continuousTaskMap_.erase(tokenID);
    }
}

bool TempPermissionObserver::FindContinuousTask(AccessTokenID tokenID)
{
    std::unique_lock<std::mutex> lck(continuousTaskMutex_);
    auto iter = continuousTaskMap_.find(tokenID);
    if (iter == continuousTaskMap_.end()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "TokenID:%{public}d not exist in map", tokenID);
        return false;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenID:%{public}d has %{public}d tasks in map",
        tokenID, continuousTaskMap_[tokenID]);
    return true;
}

bool TempPermissionObserver::IsAllowGrantTempPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    HapTokenInfo tokenInfo;
    if (AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, tokenInfo) != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid tokenId(%{public}d)", tokenID);
        return false;
    }
    auto iterator = std::find(g_tempPermission.begin(), g_tempPermission.end(), permissionName);
    if (iterator == g_tempPermission.end()) {
        ACCESSTOKEN_LOG_WARN(LABEL, "Permission is not available to temp grant: %{public}s!", permissionName.c_str());
        return false;
    }
    return CheckPermissionState(tokenID, permissionName, tokenInfo.bundleName);
}

bool TempPermissionObserver::CheckPermissionState(AccessTokenID tokenID,
    const std::string& permissionName, const std::string& bundleName)
{
    bool isForeground = false;
    std::vector<AppStateData> foreGroundAppList;
    AppManagerAccessClient::GetInstance().GetForegroundApplications(foreGroundAppList);
    if (std::any_of(foreGroundAppList.begin(), foreGroundAppList.end(),
        [tokenID](const auto& foreGroundApp) { return foreGroundApp.accessTokenId == tokenID; })) {
        isForeground = true;
    }
    bool isContinuousTaskExist = false;
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
    std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>> continuousTaskList;
    BackgourndTaskManagerAccessClient::GetInstance().GetContinuousTaskApps(continuousTaskList);
    for (auto iter = continuousTaskList.begin(); iter != continuousTaskList.end(); iter++) {
        if (static_cast<AccessTokenID>((*iter)->tokenId_) == tokenID) {
            if (std::any_of((*iter)->typeIds_.begin(), (*iter)->typeIds_.end(),
                [](const auto& typeId) { return static_cast<BackgroundMode>(typeId) == BackgroundMode::LOCATION; })) {
                TempPermissionObserver::GetInstance().AddContinuousTask(tokenID);
                isContinuousTaskExist = true;
            }
        }
    }
#endif
    bool isFormVisible = FormManagerAccessClient::GetInstance().HasFormVisible(tokenID);
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenID:%{public}d, isForeground:%{public}d, isFormVisible:%{public}d,"
        "isContinuousTaskExist:%{public}d",
        tokenID, isForeground, isFormVisible, isContinuousTaskExist);
    bool userEnable = true;
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    int callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid == ROOT_UID) {
        userEnable = false;
    }
#endif
    if (!userEnable || isForeground || isFormVisible || isContinuousTaskExist) {
        std::vector<bool> list;
        list.emplace_back(isForeground);
        list.emplace_back(isFormVisible);
        list.emplace_back(isContinuousTaskExist);
        AddTempPermTokenToList(tokenID, bundleName, permissionName, list);
        return true;
    }
    return false;
}

void TempPermissionObserver::AddTempPermTokenToList(AccessTokenID tokenID,
    const std::string& bundleName, const std::string& permissionName, const std::vector<bool>& list)
{
    RegisterCallback();
    {
        std::unique_lock<std::mutex> lck(tempPermissionMutex_);
        tempPermTokenMap_[tokenID] = list;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenID:%{public}d, permissionName:%{public}s", tokenID, permissionName.c_str());
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "GRANT_TEMP_PERMISSION",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "TOKENID", tokenID, "PERMISSION_NAME", permissionName);
    {
        std::unique_lock<std::mutex> lck(formTokenMutex_);
        formTokenMap_[bundleName] = tokenID;
    }
}

bool TempPermissionObserver::GetPermissionState(AccessTokenID tokenID,
    std::vector<PermissionStatus>& permissionStateList)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Token %{public}u is invalid.", tokenID);
        return false;
    }
    if (infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "It is a remote hap token %{public}u!", tokenID);
        return false;
    }
    if (infoPtr->GetPermissionStateList(permissionStateList) != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetPermissionStateList failed, token %{public}u!", tokenID);
        return false;
    }
    return true;
}

void TempPermissionObserver::RevokeAllTempPermission(AccessTokenID tokenID)
{
    std::vector<bool> list;
    if (!GetAppStateListByTokenID(tokenID, list)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID:%{public}d not exist in permList", tokenID);
        return;
    }
    std::unique_lock<std::mutex> lck(tempPermissionMutex_);
    tempPermTokenMap_.erase(tokenID);
    if (tempPermTokenMap_.empty()) {
        UnRegisterCallback();
    }

    std::vector<PermissionStatus> tmpList;
    if (!GetPermissionState(tokenID, tmpList)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID:%{public}d get permission state full fail!", tokenID);
        return;
    }
    for (const auto& permissionState : tmpList) {
        if (permissionState.grantFlag & PERMISSION_ALLOW_THIS_TIME) {
            if (PermissionManager::GetInstance().RevokePermission(
                tokenID, permissionState.permissionName, PERMISSION_ALLOW_THIS_TIME) != RET_SUCCESS) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID:%{public}d revoke permission:%{public}s failed!",
                    tokenID, permissionState.permissionName.c_str());
                return;
            }
        }
    }
}

void TempPermissionObserver::RevokeTempPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    std::vector<PermissionStatus> tmpList;
    if (!GetPermissionState(tokenID, tmpList)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID:%{public}d get permission state full fail!", tokenID);
        return;
    }
    for (const auto& permissionState : tmpList) {
        if ((permissionState.grantFlag & PERMISSION_ALLOW_THIS_TIME) &&
            permissionState.permissionName == permissionName) {
            if (PermissionManager::GetInstance().RevokePermission(
                tokenID, permissionState.permissionName, PERMISSION_ALLOW_THIS_TIME) != RET_SUCCESS) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID:%{public}d revoke permission:%{public}s failed!",
                    tokenID, permissionState.permissionName.c_str());
                return;
            }
        }
    }
}

void TempPermissionObserver::OnAppMgrRemoteDiedHandle()
{
    std::unique_lock<std::mutex> lck(tempPermissionMutex_);
    for (auto iter = tempPermTokenMap_.begin(); iter != tempPermTokenMap_.end(); ++iter) {
        std::vector<PermissionStatus> tmpList;
        GetPermissionState(iter->first, tmpList);
        for (const auto& permissionState : tmpList) {
            if (!(permissionState.grantFlag & PERMISSION_ALLOW_THIS_TIME)) {
                continue;
            }
            int32_t ret = PermissionManager::GetInstance().RevokePermission(
                iter->first, permissionState.permissionName, PERMISSION_ALLOW_THIS_TIME);
            if (ret != RET_SUCCESS) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "revoke permission failed, TokenId=%{public}d, permission \
                name is %{public}s", iter->first, permissionState.permissionName.c_str());
            }
        }
        std::string taskName = TASK_NAME_TEMP_PERMISSION + std::to_string(iter->first);
        TempPermissionObserver::GetInstance().CancleTaskOfPermissionRevoking(taskName);
    }
    tempPermTokenMap_.clear();
    ACCESSTOKEN_LOG_INFO(LABEL, "TempPermTokenMap_ clear!");
    appStateCallback_= nullptr;
}

#ifdef EVENTHANDLER_ENABLE
void TempPermissionObserver::InitEventHandler()
{
    auto eventRunner = AppExecFwk::EventRunner::Create(true, AppExecFwk::ThreadMode::FFRT);
    if (!eventRunner) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to create a recvRunner.");
        return;
    }
    eventHandler_ = std::make_shared<AccessEventHandler>(eventRunner);
}

std::shared_ptr<AccessEventHandler> TempPermissionObserver::GetEventHandler()
{
    std::lock_guard<std::mutex> lock(eventHandlerLock_);
    if (eventHandler_ == nullptr) {
        InitEventHandler();
    }
    return eventHandler_;
}
#endif

bool TempPermissionObserver::DelayRevokePermission(AccessToken::AccessTokenID tokenID, const std::string& taskName)
{
#ifdef EVENTHANDLER_ENABLE
    auto eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to get EventHandler");
        return false;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "Add permission task name:%{public}s", taskName.c_str());

    std::function<void()> delayed = ([tokenID]() {
        TempPermissionObserver::GetInstance().RevokeAllTempPermission(tokenID);
        ACCESSTOKEN_LOG_INFO(LABEL, "Token: %{public}d, delay revoke permission end", tokenID);
    });
    eventHandler->ProxyPostTask(delayed, taskName, cancleTimes_);
    return true;
#else
    ACCESSTOKEN_LOG_WARN(LABEL, "Eventhandler is not existed");
    return false;
#endif
}

bool TempPermissionObserver::CancleTaskOfPermissionRevoking(const std::string& taskName)
{
#ifdef EVENTHANDLER_ENABLE
    auto eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to get EventHandler");
        return false;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "Revoke permission task name:%{public}s", taskName.c_str());
    eventHandler->ProxyRemoveTask(taskName);
    return true;
#else
    ACCESSTOKEN_LOG_WARN(LABEL, "Eventhandler is not existed");
    return false;
#endif
}

void TempPermissionObserver::GetConfigValue()
{
    LibraryLoader loader(CONFIG_POLICY_LIBPATH);
    ConfigPolicyLoaderInterface* policy = loader.GetObject<ConfigPolicyLoaderInterface>();
    if (policy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Dlopen libaccesstoken_config_policy failed.");
        return;
    }
    AccessTokenConfigValue value;
    if (policy->GetConfigValue(ServiceType::ACCESSTOKEN_SERVICE, value)) {
        cancleTimes_ = value.atConfig.cancleTime == 0 ? DEFAULT_CANCLE_MILLISECONDS : value.atConfig.cancleTime;
    } else {
        cancleTimes_ = DEFAULT_CANCLE_MILLISECONDS;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "CancleTimes_ is %{public}d.", cancleTimes_);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
