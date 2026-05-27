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
#include "accesstoken_info_manager.h"
#include "accesstoken_common_log.h"
#include "libraryloader.h"
#include "app_manager_access_client.h"
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
#include "background_task_manager_access_client.h"
#include "continuous_task_callback_info.h"
#endif
#include "form_manager_access_client.h"
#include "hisysevent.h"
#include "hisysevent_adapter.h"
#include "ipc_skeleton.h"
#include "json_parse_loader.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::string TASK_NAME_TEMP_PERMISSION = "atm_permission_manager_temp_permission";
static const std::string FORM_INVISIBLE_NAME = "#0";
static const std::string FORM_VISIBLE_NAME = "#1";
static const std::string TEMP_PERMISSION_TASK_DELIMITER = "#";
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
static constexpr int32_t ROOT_UID = 0;
#endif
static constexpr int32_t FOREGROUND_FLAG = 0;
static constexpr int32_t FORMS_FLAG = 1;
static constexpr int32_t DEFAULT_CANCLE_MILLISECONDS = 10 * 1000; // 10s
std::recursive_mutex g_instanceMutex;
static const std::vector<std::string> g_tempPermission = {
    "ohos.permission.READ_PASTEBOARD",
    "ohos.permission.APPROXIMATELY_LOCATION",
    "ohos.permission.LOCATION",
    "ohos.permission.LOCATION_IN_BACKGROUND",
    "ohos.permission.CAMERA",
    "ohos.permission.MICROPHONE",
    "ohos.permission.CUSTOM_SCREEN_CAPTURE"
};

const std::map<std::string, TempPermissionType> g_permissionTypeMap = {
    {"ohos.permission.READ_PASTEBOARD", TempPermissionType::PASTEBOARD_TYPE},
    {"ohos.permission.APPROXIMATELY_LOCATION", TempPermissionType::LOCATION_TYPE},
    {"ohos.permission.LOCATION", TempPermissionType::LOCATION_TYPE},
    {"ohos.permission.LOCATION_IN_BACKGROUND", TempPermissionType::LOCATION_TYPE},
    {"ohos.permission.CAMERA", TempPermissionType::CAMERA_TYPE},
    {"ohos.permission.MICROPHONE", TempPermissionType::MICROPHONE_TYPE},
    {"ohos.permission.CUSTOM_SCREEN_CAPTURE", TempPermissionType::SCREEN_CAPTURE_TYPE},
};

std::string GetTempPermissionTaskName(AccessTokenID tokenID, const std::string& permissionName)
{
    return TASK_NAME_TEMP_PERMISSION + std::to_string(tokenID) + TEMP_PERMISSION_TASK_DELIMITER + permissionName;
}

#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
bool ContainsTypeId(const std::vector<uint32_t>& typeIds, BackgroundMode type)
{
    return std::find(typeIds.begin(), typeIds.end(), static_cast<uint32_t>(type)) != typeIds.end();
}

bool HasAudioTaskType(const std::vector<uint32_t>& typeIds)
{
    return ContainsTypeId(typeIds, BackgroundMode::AUDIO_RECORDING) ||
        ContainsTypeId(typeIds, BackgroundMode::VOIP);
}

bool IsMatchedTaskType(TempPermissionType permissionType, const std::vector<uint32_t>& typeIds)
{
    if (permissionType == TempPermissionType::LOCATION_TYPE) {
        return ContainsTypeId(typeIds, BackgroundMode::LOCATION);
    }
    if (permissionType == TempPermissionType::MICROPHONE_TYPE) {
        return HasAudioTaskType(typeIds);
    }
    return false;
}
#endif
}

TempPermissionObserver& TempPermissionObserver::GetInstance()
{
    static TempPermissionObserver* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            TempPermissionObserver* tmp = new (std::nothrow) TempPermissionObserver();
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
        LOGD(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d not use temp permission", tokenID);
        return;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "OnChange(accessTokenId=%{public}d, state=%{public}d)", tokenID, appStateData.state);
    if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND)) {
        TempPermissionObserver::GetInstance().ModifyAppState(tokenID, FOREGROUND_FLAG, true);
        TempPermissionObserver::GetInstance().CancelDelayedTasks(tokenID);
    } else if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND)) {
        TempPermissionObserver::GetInstance().ModifyAppState(tokenID, FOREGROUND_FLAG, false);
        TempPermissionObserver::GetInstance().HandleBackgroundState(tokenID, list);
    }
}

void PermissionAppStateObserver::OnAppStopped(const AppStateData &appStateData)
{
    if (appStateData.state == static_cast<int32_t>(ApplicationState::APP_STATE_TERMINATED)) {
        uint32_t tokenID = appStateData.accessTokenId;
        LOGI(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d died.", tokenID);
        TempPermissionObserver::GetInstance().CancelDelayedTasks(tokenID);
        TempPermissionObserver::GetInstance().RevokeAllTempPermission(tokenID);
    }
}

void PermissionAppStateObserver::OnAppCacheStateChanged(const AppStateData &appStateData)
{
    uint32_t tokenID = appStateData.accessTokenId;
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID is %{public}d, state is %{public}d.", tokenID, appStateData.state);

    /*
        warm start application shut down application do not means kill process,
        actually this operation means application turn background with OnAppCacheStateChanged callback,
        so temporary authorization should be cancle as OnAppStopped when receive this callback
     */
    TempPermissionObserver::GetInstance().CancelDelayedTasks(tokenID);
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
            LOGE(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d not use temp permission", tokenID);
            continue;
        }

        LOGI(ATM_DOMAIN, ATM_TAG, "%{public}s, tokenID: %{public}d, formVisiblity:%{public}d",
            formInstances[i].bundleName_.c_str(), tokenID, formInstances[i].formVisiblity_);

        if (formInstances[i].formVisiblity_ == FormVisibilityType::VISIBLE) {
            TempPermissionObserver::GetInstance().ModifyAppState(tokenID, FORMS_FLAG, true);
            TempPermissionObserver::GetInstance().CancelDelayedTasks(tokenID, TempPermissionType::LOCATION_TYPE);
        } else if (formInstances[i].formVisiblity_ == FormVisibilityType::INVISIBLE) {
            TempPermissionObserver::GetInstance().ModifyAppState(tokenID, FORMS_FLAG, false);
            TempPermissionObserver::GetInstance().HandleFormInvisibleState(tokenID, list);
        }
    }
    return RET_SUCCESS;
}
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
void PermissionBackgroundTaskObserver::OnContinuousTaskStart(
    const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo)
{
    TempPermissionObserver::GetInstance().OnContinuousTaskStart(continuousTaskCallbackInfo);
}

void PermissionBackgroundTaskObserver::OnContinuousTaskUpdate(
    const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo)
{
    TempPermissionObserver::GetInstance().OnContinuousTaskUpdate(continuousTaskCallbackInfo);
}

void PermissionBackgroundTaskObserver::OnContinuousTaskStop(
    const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo)
{
    TempPermissionObserver::GetInstance().OnContinuousTaskStop(continuousTaskCallbackInfo);
}
#endif
void PermissionAppManagerDeathCallback::NotifyAppManagerDeath()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TempPermissionObserver AppManagerDeath called");

    TempPermissionObserver::GetInstance().OnAppMgrRemoteDiedHandle();
}

TempPermissionObserver::TempPermissionObserver() : cancelTimes_(DEFAULT_CANCLE_MILLISECONDS)
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
                LOGE(ATM_DOMAIN, ATM_TAG, "Register backgroundTaskCallback failed.");
                return;
            }
            int ret = BackgroundTaskManagerAccessClient::GetInstance().SubscribeBackgroundTask(backgroundTaskCallback_);
            LOGI(ATM_DOMAIN, ATM_TAG, "Register backgroundTaskCallback %{public}d.", ret);
        }
    }
#endif
    {
        std::lock_guard<std::mutex> lock(formStateCallbackMutex_);
        if (formVisibleCallback_ == nullptr) {
            formVisibleCallback_ = new (std::nothrow) PermissionFormStateObserver();
            if (formVisibleCallback_ == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Register formStateCallback failed.");
                return;
            }
            int ret = FormManagerAccessClient::GetInstance().RegisterAddObserver(
                FORM_VISIBLE_NAME, formVisibleCallback_->AsObject());
            if (ret != ERR_OK) {
                LOGI(ATM_DOMAIN, ATM_TAG, "Register observer %{public}d.", ret);
            }
        }
        if (formInvisibleCallback_ == nullptr) {
            formInvisibleCallback_ = new (std::nothrow) PermissionFormStateObserver();
            if (formInvisibleCallback_ == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Register formStateCallback failed.");
                formVisibleCallback_ = nullptr;
                return;
            }
            int ret = FormManagerAccessClient::GetInstance().RegisterAddObserver(
                FORM_INVISIBLE_NAME, formInvisibleCallback_->AsObject());
            if (ret != ERR_OK) {
                LOGI(ATM_DOMAIN, ATM_TAG, "Register observer %{public}d.", ret);
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
                LOGE(ATM_DOMAIN, ATM_TAG, "Register appStateCallback failed.");
                return;
            }
            int ret = AppManagerAccessClient::GetInstance().RegisterApplicationStateObserver(appStateCallback_);
            if (ret != ERR_OK) {
                LOGI(ATM_DOMAIN, ATM_TAG, "Register appStateCallback %{public}d.", ret);
            }
        }
    }
    // app manager death callback register
    {
        std::lock_guard<std::mutex> lock(appManagerDeathMutex_);
        if (appManagerDeathCallback_ == nullptr) {
            appManagerDeathCallback_ = std::make_shared<PermissionAppManagerDeathCallback>();
            if (appManagerDeathCallback_ == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Register appManagerDeathCallback failed.");
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
                LOGI(ATM_DOMAIN, ATM_TAG, "Unregister appStateCallback %{public}d.", ret);
            }
            appStateCallback_= nullptr;
        }
    }
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
    {
        std::lock_guard<std::mutex> lock(backgroundTaskCallbackMutex_);
        if (backgroundTaskCallback_ != nullptr) {
            int32_t ret = BackgroundTaskManagerAccessClient::GetInstance().UnsubscribeBackgroundTask(
                backgroundTaskCallback_);
            if (ret != ERR_NONE) {
                LOGI(ATM_DOMAIN, ATM_TAG, "Unregister appStateCallback %{public}d.", ret);
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
                LOGI(ATM_DOMAIN, ATM_TAG, "Unregister appStateCallback %{public}d.", ret);
            }
            formVisibleCallback_ = nullptr;
        }
        if (formInvisibleCallback_ != nullptr) {
            int32_t ret = FormManagerAccessClient::GetInstance().RegisterRemoveObserver(
                FORM_INVISIBLE_NAME, formInvisibleCallback_);
            if (ret != ERR_OK) {
                LOGI(ATM_DOMAIN, ATM_TAG, "Unregister appStateCallback %{public}d.", ret);
            }
            formInvisibleCallback_ = nullptr;
        }
    }
}

#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
void TempPermissionObserver::OnContinuousTaskStart(
    const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo)
{
    if (continuousTaskCallbackInfo == nullptr) {
        return;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(continuousTaskCallbackInfo->GetFullTokenId());
    std::vector<bool> list;
    if (!GetAppStateListByTokenID(tokenID, list)) {
        LOGD(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d not use temp permission", tokenID);
        return;
    }
    if (!AssociateContinuousTaskIfNeeded(tokenID, continuousTaskCallbackInfo->GetContinuousTaskId(),
        continuousTaskCallbackInfo->GetTypeIds())) {
        return;
    }
    if (ContainsTypeId(continuousTaskCallbackInfo->GetTypeIds(), BackgroundMode::LOCATION)) {
        CancelDelayedTasks(tokenID, TempPermissionType::LOCATION_TYPE);
    }
    if (ContainsTypeId(continuousTaskCallbackInfo->GetTypeIds(), BackgroundMode::AUDIO_RECORDING) ||
        ContainsTypeId(continuousTaskCallbackInfo->GetTypeIds(), BackgroundMode::VOIP)) {
        CancelDelayedTasks(tokenID, TempPermissionType::MICROPHONE_TYPE);
    }
}

void TempPermissionObserver::OnContinuousTaskUpdate(
    const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo)
{
    if (continuousTaskCallbackInfo == nullptr) {
        return;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(continuousTaskCallbackInfo->GetFullTokenId());
    std::vector<bool> list;
    if (!GetAppStateListByTokenID(tokenID, list)) {
        LOGD(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d not use temp permission", tokenID);
        return;
    }

    int32_t taskId = continuousTaskCallbackInfo->GetContinuousTaskId();
    std::vector<uint32_t> oldTypeIds;
    bool isAssociated = GetContinuousTaskTypeIds(tokenID, taskId, oldTypeIds);
    if (isAssociated) {
        UpsertContinuousTask(tokenID, taskId, continuousTaskCallbackInfo->GetTypeIds());
    } else if (!AssociateContinuousTaskIfNeeded(tokenID, taskId, continuousTaskCallbackInfo->GetTypeIds())) {
        return;
    }

    const auto& newTypeIds = continuousTaskCallbackInfo->GetTypeIds();
    bool hadLocation = ContainsTypeId(oldTypeIds, BackgroundMode::LOCATION);
    bool hasLocation = ContainsTypeId(newTypeIds, BackgroundMode::LOCATION);
    bool hadAudio = HasAudioTaskType(oldTypeIds);
    bool hasAudio = HasAudioTaskType(newTypeIds);
    if (hasLocation) {
        CancelDelayedTasks(tokenID, TempPermissionType::LOCATION_TYPE);
    } else if (hadLocation) {
        HandleContinuousTaskStop(tokenID, TempPermissionType::LOCATION_TYPE, list);
    }
    if (hasAudio) {
        CancelDelayedTasks(tokenID, TempPermissionType::MICROPHONE_TYPE);
    } else if (hadAudio) {
        HandleContinuousTaskStop(tokenID, TempPermissionType::MICROPHONE_TYPE, list);
    }
}

void TempPermissionObserver::OnContinuousTaskStop(
    const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo)
{
    if (continuousTaskCallbackInfo == nullptr) {
        return;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(continuousTaskCallbackInfo->GetFullTokenId());
    std::vector<bool> list;
    if (!GetAppStateListByTokenID(tokenID, list)) {
        LOGD(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d not use temp permission", tokenID);
        return;
    }

    std::vector<uint32_t> oldTypeIds;
    bool isAssociated = GetContinuousTaskTypeIds(
        tokenID, continuousTaskCallbackInfo->GetContinuousTaskId(), oldTypeIds);
    RemoveContinuousTask(tokenID, continuousTaskCallbackInfo->GetContinuousTaskId());
    if (!isAssociated) {
        return;
    }

    if (ContainsTypeId(oldTypeIds, BackgroundMode::LOCATION)) {
        HandleContinuousTaskStop(tokenID, TempPermissionType::LOCATION_TYPE, list);
    }
    if (HasAudioTaskType(oldTypeIds)) {
        HandleContinuousTaskStop(tokenID, TempPermissionType::MICROPHONE_TYPE, list);
    }
}
#endif

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
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d not exist in map", tokenID);
        return;
    }
    iter->second[index] = flag;
}

bool TempPermissionObserver::GetTokenIDByBundle(const std::string &bundleName, AccessTokenID& tokenID)
{
    std::unique_lock<std::mutex> lck(formTokenMutex_);
    auto iter = formTokenMap_.find(bundleName);
    if (iter == formTokenMap_.end()) {
        LOGD(ATM_DOMAIN, ATM_TAG, "BundleName:%{public}s not exist in map", bundleName.c_str());
        return false;
    }
    tokenID = iter->second;
    return true;
}

TempPermissionType TempPermissionObserver::GetPermissionType(const std::string& permissionName) const
{
    auto iter = g_permissionTypeMap.find(permissionName);
    if (iter == g_permissionTypeMap.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Temp permission type is invalid, permissionName:%{public}s",
            permissionName.c_str());
        return TempPermissionType::INVALID_TYPE;
    }
    return iter->second;
}

bool TempPermissionObserver::HasLocationTask(AccessTokenID tokenID)
{
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
    return FindContinuousTask(tokenID, TempPermissionType::LOCATION_TYPE);
#else
    return false;
#endif
}

bool TempPermissionObserver::HasAudioRecordingOrVoipTask(AccessTokenID tokenID)
{
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
    return FindContinuousTask(tokenID, TempPermissionType::MICROPHONE_TYPE);
#else
    return false;
#endif
}

bool TempPermissionObserver::ReportTempPermissionDeny(AccessTokenID tokenID, const std::string& permissionName,
    const std::string& bundleName) const
{
    ReportUpdatePermStatusErrorEvent({.errorCode = UpdatePermStatusErrorCode::GRANT_TEMP_PERMISSION_FAILED,
        .tokenId = tokenID, .permissionName = permissionName, .bundleName = bundleName});
    return false;
}

bool TempPermissionObserver::IsPrivilegedCalling() const
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    return IPCSkeleton::GetCallingUid() == ROOT_UID;
#else
    return false;
#endif
}

bool TempPermissionObserver::CheckTempPermissionByType(AccessTokenID tokenID, const std::string& permissionName,
    const std::string& bundleName, const PermissionCheckContext& context)
{
    switch (GetPermissionType(permissionName)) {
        case TempPermissionType::CAMERA_TYPE:
            return CheckCameraPermission(tokenID, bundleName, permissionName, context.isForeground);
        case TempPermissionType::MICROPHONE_TYPE:
            return CheckMicrophonePermission(
                tokenID, bundleName, permissionName, context.isForeground, context.hasAudioTask);
        case TempPermissionType::SCREEN_CAPTURE_TYPE:
            return true;
        case TempPermissionType::PASTEBOARD_TYPE:
            return CheckPasteboardPermission(
                tokenID, bundleName, permissionName, context.isForeground, context.isFormVisible);
        case TempPermissionType::LOCATION_TYPE:
            return CheckLocationPermission(tokenID, bundleName, permissionName, context.isForeground,
                context.isFormVisible, context.hasLocationTask);
        case TempPermissionType::INVALID_TYPE:
        default:
            LOGE(ATM_DOMAIN, ATM_TAG, "Temp permission type is invalid, permissionName:%{public}s",
                permissionName.c_str());
            return false;
    }
}

#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
void TempPermissionObserver::UpsertContinuousTask(AccessTokenID tokenID,
    int32_t continuousTaskId, const std::vector<uint32_t>& typeIds)
{
    std::unique_lock<std::mutex> lck(continuousTaskMutex_);
    continuousTaskIdMap_[tokenID][continuousTaskId] = typeIds;
}

void TempPermissionObserver::RemoveContinuousTask(AccessTokenID tokenID, int32_t continuousTaskId)
{
    std::unique_lock<std::mutex> lck(continuousTaskMutex_);
    auto tokenIter = continuousTaskIdMap_.find(tokenID);
    if (tokenIter == continuousTaskIdMap_.end()) {
        return;
    }
    tokenIter->second.erase(continuousTaskId);
    if (tokenIter->second.empty()) {
        continuousTaskIdMap_.erase(tokenIter);
    }
}

bool TempPermissionObserver::FindContinuousTask(AccessTokenID tokenID, TempPermissionType type)
{
    std::unique_lock<std::mutex> lck(continuousTaskMutex_);
    auto tokenIter = continuousTaskIdMap_.find(tokenID);
    if (tokenIter == continuousTaskIdMap_.end()) {
        return false;
    }
    for (const auto& item : tokenIter->second) {
        if (IsMatchedTaskType(type, item.second)) {
            return true;
        }
    }
    return false;
}

void TempPermissionObserver::CollectContinuousTaskState(AccessTokenID tokenID, bool& hasLocationTask,
    bool& hasAudioTask, std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>>& continuousTaskList)
{
    (void)BackgroundTaskManagerAccessClient::GetInstance().GetContinuousTaskApps(continuousTaskList);
    for (const auto& info : continuousTaskList) {
        if (info == nullptr || static_cast<AccessTokenID>(info->GetFullTokenId()) != tokenID) {
            continue;
        }
        if (ContainsTypeId(info->GetTypeIds(), BackgroundMode::LOCATION)) {
            hasLocationTask = true;
        }
        if (HasAudioTaskType(info->GetTypeIds())) {
            hasAudioTask = true;
        }
    }
}

void TempPermissionObserver::AssociateGrantedPermissionTasks(AccessTokenID tokenID,
    TempPermissionType permissionType,
    const std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>>& continuousTaskList)
{
    for (const auto& info : continuousTaskList) {
        if (info == nullptr || static_cast<AccessTokenID>(info->GetFullTokenId()) != tokenID) {
            continue;
        }
        if (permissionType == TempPermissionType::LOCATION_TYPE &&
            ContainsTypeId(info->GetTypeIds(), BackgroundMode::LOCATION)) {
            AssociateContinuousTaskIfNeeded(tokenID, info->GetContinuousTaskId(), info->GetTypeIds());
            continue;
        }
        if (permissionType == TempPermissionType::MICROPHONE_TYPE && HasAudioTaskType(info->GetTypeIds())) {
            AssociateContinuousTaskIfNeeded(tokenID, info->GetContinuousTaskId(), info->GetTypeIds());
        }
    }
}

bool TempPermissionObserver::GetContinuousTaskTypeIds(AccessTokenID tokenID, int32_t continuousTaskId,
    std::vector<uint32_t>& typeIds)
{
    std::unique_lock<std::mutex> lck(continuousTaskMutex_);
    auto tokenIter = continuousTaskIdMap_.find(tokenID);
    if (tokenIter == continuousTaskIdMap_.end()) {
        return false;
    }
    auto taskIter = tokenIter->second.find(continuousTaskId);
    if (taskIter == tokenIter->second.end()) {
        return false;
    }
    typeIds = taskIter->second;
    return true;
}

bool TempPermissionObserver::AssociateContinuousTaskIfNeeded(
    AccessTokenID tokenID, int32_t continuousTaskId, const std::vector<uint32_t>& typeIds)
{
    bool shouldAssociate = false;
    if (ContainsTypeId(typeIds, BackgroundMode::LOCATION) &&
        HasTempPermissionType(tokenID, TempPermissionType::LOCATION_TYPE)) {
        shouldAssociate = true;
    }
    if (HasAudioTaskType(typeIds) &&
        HasTempPermissionType(tokenID, TempPermissionType::MICROPHONE_TYPE)) {
        shouldAssociate = true;
    }
    if (!shouldAssociate) {
        return false;
    }
    UpsertContinuousTask(tokenID, continuousTaskId, typeIds);
    return true;
}

void TempPermissionObserver::HandleContinuousTaskStop(AccessTokenID tokenID, TempPermissionType type,
    const std::vector<bool>& list)
{
    if (type == TempPermissionType::LOCATION_TYPE) {
        if (FindContinuousTask(tokenID, type)) {
            return;
        }
        if (list[FOREGROUND_FLAG] || list[FORMS_FLAG]) {
            return;
        }
    } else if (type == TempPermissionType::MICROPHONE_TYPE) {
        if (FindContinuousTask(tokenID, type) || list[FOREGROUND_FLAG]) {
            return;
        }
    } else {
        return;
    }
    DelayRevokePermissionsByType(tokenID, type);
}
#endif

bool TempPermissionObserver::IsAllowGrantTempPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    HapTokenInfo tokenInfo;
    int32_t ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, tokenInfo);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to get hap info of %{public}u, err %{public}d.", tokenID, ret);
        return false;
    }
    auto iterator = std::find(g_tempPermission.begin(), g_tempPermission.end(), permissionName);
    if (iterator == g_tempPermission.end()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Perm(%{public}s) of %{public}u is not available to temp grant!",
            permissionName.c_str(), tokenID);
        return false;
    }
    return CheckPermissionState(tokenID, permissionName, tokenInfo.bundleName);
}

bool TempPermissionObserver::CheckLocationPermission(AccessTokenID tokenID, const std::string& bundleName,
    const std::string& permissionName, bool isForeground, bool isFormVisible, bool hasLocationTask)
{
    if (isForeground || isFormVisible || hasLocationTask) {
        return true;
    }
    return ReportTempPermissionDeny(tokenID, permissionName, bundleName);
}

bool TempPermissionObserver::CheckPasteboardPermission(AccessTokenID tokenID, const std::string& bundleName,
    const std::string& permissionName, bool isForeground, bool isFormVisible)
{
    if (isForeground || isFormVisible) {
        return true;
    }
    return ReportTempPermissionDeny(tokenID, permissionName, bundleName);
}

bool TempPermissionObserver::CheckCameraPermission(AccessTokenID tokenID, const std::string& bundleName,
    const std::string& permissionName, bool isForeground)
{
    if (isForeground) {
        return true;
    }
    return ReportTempPermissionDeny(tokenID, permissionName, bundleName);
}

bool TempPermissionObserver::CheckMicrophonePermission(AccessTokenID tokenID, const std::string& bundleName,
    const std::string& permissionName, bool isForeground, bool hasAudioTask)
{
    if (isForeground || hasAudioTask) {
        return true;
    }
    return ReportTempPermissionDeny(tokenID, permissionName, bundleName);
}

bool TempPermissionObserver::CheckPermissionState(AccessTokenID tokenID,
    const std::string& permissionName, const std::string& bundleName)
{
    PermissionCheckContext context;
    std::vector<AppStateData> foreGroundAppList;
    (void)AppManagerAccessClient::GetInstance().GetForegroundApplications(foreGroundAppList);
    if (std::any_of(foreGroundAppList.begin(), foreGroundAppList.end(),
        [tokenID](const auto& foreGroundApp) { return foreGroundApp.accessTokenId == tokenID; })) {
        context.isForeground = true;
    }
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
    std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>> continuousTaskList;
    CollectContinuousTaskState(tokenID, context.hasLocationTask, context.hasAudioTask, continuousTaskList);
#endif
    context.isFormVisible = FormManagerAccessClient::GetInstance().HasFormVisible(tokenID);
    bool isContinuousTaskExist = context.hasLocationTask || context.hasAudioTask;
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d, isForeground:%{public}d, isFormVisible:%{public}d,"
        "isContinuousTaskExist:%{public}d, permissionName:%{public}s",
        tokenID, context.isForeground, context.isFormVisible, isContinuousTaskExist, permissionName.c_str());
    std::vector<bool> list = {context.isForeground, context.isFormVisible};
    if (IsPrivilegedCalling()) {
        AddTempPermTokenToList(tokenID, bundleName, permissionName, list);
        return true;
    }
    if (!CheckTempPermissionByType(tokenID, permissionName, bundleName, context)) {
        return false;
    }
    AddTempPermTokenToList(tokenID, bundleName, permissionName, list);
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
    AssociateGrantedPermissionTasks(tokenID, GetPermissionType(permissionName), continuousTaskList);
#endif
    return true;
}

void TempPermissionObserver::AddTempPermTokenToList(AccessTokenID tokenID,
    const std::string& bundleName, const std::string& permissionName, const std::vector<bool>& list)
{
    RegisterCallback();
    {
        std::unique_lock<std::mutex> lck(tempPermissionMutex_);
        tempPermTokenMap_[tokenID] = list;
        tempPermPermissionMap_[tokenID].insert(permissionName);
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d, permissionName:%{public}s", tokenID, permissionName.c_str());
    ReportGrantTempPermissionEvent(tokenID, permissionName);
    {
        std::unique_lock<std::mutex> lck(formTokenMutex_);
        formTokenMap_[bundleName] = tokenID;
    }
}

bool TempPermissionObserver::GetTempPermissionNames(AccessTokenID tokenID, std::set<std::string>& permissionNames)
{
    std::unique_lock<std::mutex> lck(tempPermissionMutex_);
    auto iter = tempPermPermissionMap_.find(tokenID);
    if (iter == tempPermPermissionMap_.end()) {
        return false;
    }
    permissionNames = iter->second;
    return true;
}

bool TempPermissionObserver::HasTempPermissionType(AccessTokenID tokenID, TempPermissionType type)
{
    std::set<std::string> permissionNames;
    if (!GetTempPermissionNames(tokenID, permissionNames)) {
        return false;
    }
    for (const auto& permissionName : permissionNames) {
        if (GetPermissionType(permissionName) == type) {
            return true;
        }
    }
    return false;
}

bool TempPermissionObserver::GetPermissionState(AccessTokenID tokenID,
    std::vector<PermissionStatus>& permissionStateList)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", tokenID);
        return false;
    }
    if (infoPtr->IsRemote()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "It is a remote hap token %{public}u!", tokenID);
        return false;
    }
    if (infoPtr->GetPermissionStateList(permissionStateList) != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetPermissionStateList failed, token %{public}u!", tokenID);
        return false;
    }
    return true;
}

void TempPermissionObserver::RevokeAllTempPermission(AccessTokenID tokenID)
{
    std::vector<bool> list;
    if (!GetAppStateListByTokenID(tokenID, list)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d not exist in permList", tokenID);
        return;
    }
    bool needUnregister = false;
    {
        std::lock_guard<std::mutex> lock(tempPermissionMutex_);
        tempPermTokenMap_.erase(tokenID);
        tempPermPermissionMap_.erase(tokenID);
        needUnregister = tempPermTokenMap_.empty();
    }
    if (needUnregister) {
        UnRegisterCallback();
    }

    std::vector<PermissionStatus> tmpList;
    if (!GetPermissionState(tokenID, tmpList)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d get permission state full fail!", tokenID);
        return;
    }
    for (const auto& permissionState : tmpList) {
        if (permissionState.grantFlag & PERMISSION_ALLOW_THIS_TIME) {
            if (PermissionManager::GetInstance().UpdatePermission(
                tokenID, permissionState.permissionName, false, PERMISSION_ALLOW_THIS_TIME, false) != RET_SUCCESS) {
                LOGE(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d revoke permission:%{public}s failed!",
                    tokenID, permissionState.permissionName.c_str());
                return;
            }
            (void)CancelTaskOfPermissionRevoking(GetTempPermissionTaskName(tokenID, permissionState.permissionName));
        }
    }
    {
        std::lock_guard<std::mutex> lock(continuousTaskMutex_);
        continuousTaskIdMap_.erase(tokenID);
    }
}

bool TempPermissionObserver::RemoveTempPermissionRecord(
    AccessTokenID tokenID, const std::string& permissionName, bool& clearTaskState, bool& needUnregister)
{
    std::lock_guard<std::mutex> lock(tempPermissionMutex_);
    auto iter = tempPermPermissionMap_.find(tokenID);
    if (iter == tempPermPermissionMap_.end()) {
        return false;
    }
    iter->second.erase(permissionName);
    if (!iter->second.empty()) {
        return true;
    }
    tempPermPermissionMap_.erase(iter);
    tempPermTokenMap_.erase(tokenID);
    clearTaskState = true;
    needUnregister = tempPermPermissionMap_.empty();
    return true;
}

void TempPermissionObserver::RevokeTempPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    std::vector<PermissionStatus> tmpList;
    if (!GetPermissionState(tokenID, tmpList)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d get permission state full fail!", tokenID);
        return;
    }
    for (const auto& permissionState : tmpList) {
        if (permissionState.permissionName != permissionName) {
            continue;
        }
        if (!(permissionState.grantFlag & PERMISSION_ALLOW_THIS_TIME)) {
            return;
        }
        if (PermissionManager::GetInstance().UpdatePermission(
            tokenID, permissionState.permissionName, false, PERMISSION_ALLOW_THIS_TIME, false) != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TokenID:%{public}d revoke permission:%{public}s failed!",
                tokenID, permissionState.permissionName.c_str());
            return;
        }
        bool clearTaskState = false;
        bool needUnregister = false;
        (void)RemoveTempPermissionRecord(tokenID, permissionName, clearTaskState, needUnregister);
        if (clearTaskState) {
            std::lock_guard<std::mutex> lock(continuousTaskMutex_);
            continuousTaskIdMap_.erase(tokenID);
        }
        (void)CancelTaskOfPermissionRevoking(GetTempPermissionTaskName(tokenID, permissionName));
        if (needUnregister) {
            UnRegisterCallback();
        }
        return;
    }
}

void TempPermissionObserver::OnAppMgrRemoteDiedHandle()
{
    std::vector<AccessTokenID> tokenIds;
    {
        std::lock_guard<std::mutex> lock(tempPermissionMutex_);
        tokenIds.reserve(tempPermTokenMap_.size());
        for (const auto& item : tempPermTokenMap_) {
            tokenIds.emplace_back(item.first);
        }
    }

    for (const auto& tokenId : tokenIds) {
        std::vector<PermissionStatus> tmpList;
        GetPermissionState(tokenId, tmpList);
        for (const auto& permissionState : tmpList) {
            if (!(permissionState.grantFlag & PERMISSION_ALLOW_THIS_TIME)) {
                continue;
            }
            int32_t ret = PermissionManager::GetInstance().RevokePermission(
                tokenId, permissionState.permissionName, PERMISSION_ALLOW_THIS_TIME);
            if (ret != RET_SUCCESS) {
                LOGE(ATM_DOMAIN, ATM_TAG, "revoke permission failed, TokenId=%{public}d, permission \
                name is %{public}s", tokenId, permissionState.permissionName.c_str());
            }
        }
        TempPermissionObserver::GetInstance().CancelDelayedTasks(tokenId);
    }
    {
        std::lock_guard<std::mutex> lock(tempPermissionMutex_);
        tempPermTokenMap_.clear();
        tempPermPermissionMap_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(continuousTaskMutex_);
        continuousTaskIdMap_.clear();
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "TempPermTokenMap_ clear!");
    appStateCallback_= nullptr;
}

#ifdef EVENTHANDLER_ENABLE
void TempPermissionObserver::InitEventHandler()
{
    auto eventRunner = AppExecFwk::EventRunner::Create(true, AppExecFwk::ThreadMode::FFRT);
    if (!eventRunner) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create a recvRunner.");
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

void TempPermissionObserver::CancelDelayedTasks(AccessTokenID tokenID)
{
    std::set<std::string> permissionNames;
    if (!GetTempPermissionNames(tokenID, permissionNames)) {
        return;
    }
    for (const auto& permissionName : permissionNames) {
        (void)CancelTaskOfPermissionRevoking(GetTempPermissionTaskName(tokenID, permissionName));
    }
}

void TempPermissionObserver::CancelDelayedTasks(AccessTokenID tokenID, TempPermissionType type)
{
    std::set<std::string> permissionNames;
    if (!GetTempPermissionNames(tokenID, permissionNames)) {
        return;
    }
    for (const auto& permissionName : permissionNames) {
        if (GetPermissionType(permissionName) != type) {
            continue;
        }
        (void)CancelTaskOfPermissionRevoking(GetTempPermissionTaskName(tokenID, permissionName));
    }
}

void TempPermissionObserver::DelayRevokePermissionsByType(AccessTokenID tokenID, TempPermissionType type)
{
    std::set<std::string> permissionNames;
    if (!GetTempPermissionNames(tokenID, permissionNames)) {
        return;
    }
    for (const auto& permissionName : permissionNames) {
        if (GetPermissionType(permissionName) != type) {
            continue;
        }
        (void)DelayRevokePermission(tokenID, permissionName, GetTempPermissionTaskName(tokenID, permissionName));
    }
}

void TempPermissionObserver::HandleBackgroundState(AccessTokenID tokenID, const std::vector<bool>& list)
{
    DelayRevokePermissionsByType(tokenID, TempPermissionType::CAMERA_TYPE);
    if (!HasAudioRecordingOrVoipTask(tokenID)) {
        DelayRevokePermissionsByType(tokenID, TempPermissionType::MICROPHONE_TYPE);
    }
    if (!list[FORMS_FLAG]) {
        DelayRevokePermissionsByType(tokenID, TempPermissionType::PASTEBOARD_TYPE);
    }
    if (!list[FORMS_FLAG] && !HasLocationTask(tokenID)) {
        DelayRevokePermissionsByType(tokenID, TempPermissionType::LOCATION_TYPE);
    }
}

void TempPermissionObserver::HandleFormInvisibleState(AccessTokenID tokenID, const std::vector<bool>& list)
{
    if (list[FOREGROUND_FLAG]) {
        LOGW(ATM_DOMAIN, ATM_TAG, "%{public}d:tokenID in foreground don't delay revoke location permission!",
            tokenID);
        return;
    }
    DelayRevokePermissionsByType(tokenID, TempPermissionType::PASTEBOARD_TYPE);
    if (HasLocationTask(tokenID)) {
        LOGW(ATM_DOMAIN, ATM_TAG, "%{public}d:tokenID has location task, don't delay revoke location permission!",
            tokenID);
    } else {
        DelayRevokePermissionsByType(tokenID, TempPermissionType::LOCATION_TYPE);
    }
}

bool TempPermissionObserver::DelayRevokePermission(AccessToken::AccessTokenID tokenID,
    const std::string& permissionName, const std::string& taskName)
{
#ifdef EVENTHANDLER_ENABLE
    auto eventHandler = GetEventHandler();
    if (eventHandler == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fail to get EventHandler");
        return false;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Add permission task name:%{public}s", taskName.c_str());

    std::function<void()> delayed = ([tokenID, permissionName]() {
        TempPermissionObserver::GetInstance().RevokeTempPermission(tokenID, permissionName);
        LOGI(ATM_DOMAIN, ATM_TAG, "Token: %{public}d, delay revoke permission:%{public}s end",
            tokenID, permissionName.c_str());
    });
    eventHandler->ProxyPostTask(delayed, taskName, cancelTimes_);
    return true;
#else
    LOGW(ATM_DOMAIN, ATM_TAG, "Eventhandler is not existed");
    return false;
#endif
}

bool TempPermissionObserver::CancelTaskOfPermissionRevoking(const std::string& taskName)
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
    LOGW(ATM_DOMAIN, ATM_TAG, "Eventhandler is not existed");
    return false;
#endif
}

void TempPermissionObserver::SetCancelTime(int32_t cancelTime)
{
    if (cancelTime != 0) {
        cancelTimes_ = cancelTime;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "CancelTimes_ is %{public}d.", cancelTimes_);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
