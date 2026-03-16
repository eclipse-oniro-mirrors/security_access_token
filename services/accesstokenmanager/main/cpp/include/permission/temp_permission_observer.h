/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#ifndef TEMP_PERMISSION_OBSERVER_H
#define TEMP_PERMISSION_OBSERVER_H

#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "access_token.h"
#ifdef EVENTHANDLER_ENABLE
#include "access_event_handler.h"
#endif
#include "app_manager_death_callback.h"
#include "app_status_change_callback.h"
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
#include "continuous_task_change_callback.h"
#endif
#include "form_status_change_callback.h"
#include "permission_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum class TempPermissionType {
    INVALID_TYPE = -1,
    LOCATION_TYPE = 0,
    PASTEBOARD_TYPE,
    CAMERA_TYPE,
    MICROPHONE_TYPE,
    SCREEN_CAPTURE_TYPE,
};

class PermissionAppStateObserver : public ApplicationStateObserverStub {
public:
    PermissionAppStateObserver() = default;
    ~PermissionAppStateObserver() = default;

    void OnAppStopped(const AppStateData &appStateData) override;
    void OnAppStateChanged(const AppStateData &appStateData) override;
    void OnAppCacheStateChanged(const AppStateData &appStateData) override;

    DISALLOW_COPY_AND_MOVE(PermissionAppStateObserver);
};

class PermissionFormStateObserver : public FormStateObserverStub {
public:
    PermissionFormStateObserver() = default;
    ~PermissionFormStateObserver() = default;

    int32_t NotifyWhetherFormsVisible(const FormVisibilityType visibleType,
        const std::string &bundleName, std::vector<FormInstance> &formInstances) override;
    DISALLOW_COPY_AND_MOVE(PermissionFormStateObserver);
};
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
class PermissionBackgroundTaskObserver : public BackgroundTaskSubscriberStub {
public:
    PermissionBackgroundTaskObserver() = default;
    ~PermissionBackgroundTaskObserver() = default;

    void OnContinuousTaskStart(const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo) override;
    void OnContinuousTaskUpdate(const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo) override;
    void OnContinuousTaskStop(const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo) override;

    DISALLOW_COPY_AND_MOVE(PermissionBackgroundTaskObserver);
};
#endif
class PermissionAppManagerDeathCallback : public AppManagerDeathCallback {
public:
    PermissionAppManagerDeathCallback() = default;
    ~PermissionAppManagerDeathCallback() = default;

    void NotifyAppManagerDeath() override;
    DISALLOW_COPY_AND_MOVE(PermissionAppManagerDeathCallback);
};

class TempPermissionObserver {
public:
    static TempPermissionObserver& GetInstance();
    TempPermissionObserver();
    virtual ~TempPermissionObserver();

    void OnAppMgrRemoteDiedHandle();

    bool IsAllowGrantTempPermission(AccessTokenID tokenID, const std::string& permissionName);
    bool CheckPermissionState(AccessTokenID tokenID, const std::string& permissionName, const std::string& bundleName);
    void AddTempPermTokenToList(AccessTokenID tokenID,
        const std::string& bundleName, const std::string& permissionName, const std::vector<bool>& list);
    void RevokeAllTempPermission(AccessTokenID tokenID);
    void RevokeTempPermission(AccessTokenID tokenID, const std::string& permissionName);
    bool GetPermissionState(AccessTokenID tokenID, std::vector<PermissionStatus>& permissionStateList);
    bool GetAppStateListByTokenID(AccessTokenID tokenID, std::vector<bool>& list);
    void ModifyAppState(AccessTokenID tokenID, int32_t index, bool flag);
    bool GetTokenIDByBundle(const std::string &bundleName, AccessTokenID& tokenID);
    TempPermissionType GetPermissionType(const std::string& permissionName) const;
    bool HasLocationTask(AccessTokenID tokenID);
    bool HasAudioRecordingOrVoipTask(AccessTokenID tokenID);
    void UpsertContinuousTask(AccessTokenID tokenID, int32_t continuousTaskId, const std::vector<uint32_t>& typeIds);
    void RemoveContinuousTask(AccessTokenID tokenID, int32_t continuousTaskId);
    bool FindContinuousTask(AccessTokenID tokenID, TempPermissionType type);
    bool CheckLocationPermission(AccessTokenID tokenID, const std::string& bundleName,
        const std::string& permissionName, bool isForeground, bool isFormVisible, bool hasLocationTask);
    bool CheckPasteboardPermission(AccessTokenID tokenID, const std::string& bundleName,
        const std::string& permissionName, bool isForeground, bool isFormVisible);
    bool CheckCameraPermission(AccessTokenID tokenID, const std::string& bundleName,
        const std::string& permissionName, bool isForeground);
    bool CheckMicrophonePermission(AccessTokenID tokenID, const std::string& bundleName,
        const std::string& permissionName, bool isForeground, bool hasAudioTask);
    void HandleBackgroundState(AccessTokenID tokenID, const std::vector<bool>& list);
    void HandleFormInvisibleState(AccessTokenID tokenID, const std::vector<bool>& list);
    void HandleContinuousTaskStop(AccessTokenID tokenID, TempPermissionType type, const std::vector<bool>& list);
    void CancelDelayedTasks(AccessTokenID tokenID);
    void CancelDelayedTasks(AccessTokenID tokenID, TempPermissionType type);
#ifdef EVENTHANDLER_ENABLE
    void InitEventHandler();
#endif
    void SetCancelTime(int32_t cancelTime);
    bool DelayRevokePermission(AccessToken::AccessTokenID tokenId,
        const std::string& permissionName, const std::string& taskName);
    bool CancelTaskOfPermissionRevoking(const std::string& taskName);
    void RegisterCallback();
    void RegisterAppStatusListener();
    void UnRegisterCallback();
    int32_t NotifyWhetherFormsVisible(const FormVisibilityType visibleType,
        const std::string &bundleName, std::vector<FormInstance> &formInstances);
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
    void OnContinuousTaskStart(const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo);
    void OnContinuousTaskUpdate(const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo);
    void OnContinuousTaskStop(const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo);
#endif

private:
    struct PermissionCheckContext {
        bool isForeground = false;
        bool isFormVisible = false;
        bool hasLocationTask = false;
        bool hasAudioTask = false;
    };

    bool ReportTempPermissionDeny(AccessTokenID tokenID, const std::string& permissionName,
        const std::string& bundleName) const;
    bool IsPrivilegedCalling() const;
    bool CheckTempPermissionByType(AccessTokenID tokenID, const std::string& permissionName,
        const std::string& bundleName, const PermissionCheckContext& context);
    bool GetTempPermissionNames(AccessTokenID tokenID, std::set<std::string>& permissionNames);
    bool HasTempPermissionType(AccessTokenID tokenID, TempPermissionType type);
    bool GetContinuousTaskTypeIds(AccessTokenID tokenID, int32_t continuousTaskId, std::vector<uint32_t>& typeIds);
    bool AssociateContinuousTaskIfNeeded(
        AccessTokenID tokenID, int32_t continuousTaskId, const std::vector<uint32_t>& typeIds);
    bool RemoveTempPermissionRecord(
        AccessTokenID tokenID, const std::string& permissionName, bool& clearTaskState, bool& needUnregister);
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
    void CollectContinuousTaskState(AccessTokenID tokenID, bool& hasLocationTask, bool& hasAudioTask,
        std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>>& continuousTaskList);
    void AssociateGrantedPermissionTasks(AccessTokenID tokenID, TempPermissionType permissionType,
        const std::vector<std::shared_ptr<ContinuousTaskCallbackInfo>>& continuousTaskList);
#endif
    void DelayRevokePermissionsByType(AccessTokenID tokenID, TempPermissionType type);

#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AccessEventHandler> GetEventHandler();
    std::shared_ptr<AccessEventHandler> eventHandler_;
    std::mutex eventHandlerLock_;
#endif
    int32_t cancelTimes_;
    std::mutex tempPermissionMutex_;
    std::map<AccessTokenID, std::vector<bool>> tempPermTokenMap_;
    std::map<AccessTokenID, std::set<std::string>> tempPermPermissionMap_;

    std::mutex continuousTaskMutex_;
    std::map<AccessTokenID, std::map<int32_t, std::vector<uint32_t>>> continuousTaskIdMap_;

    // appState
    std::mutex appStateCallbackMutex_;
    sptr<PermissionAppStateObserver> appStateCallback_ = nullptr;
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
    // backgroundTask
    std::mutex backgroundTaskCallbackMutex_;
    sptr<PermissionBackgroundTaskObserver> backgroundTaskCallback_ = nullptr;
#endif
    // formState
    std::mutex formStateCallbackMutex_;
    sptr<PermissionFormStateObserver> formVisibleCallback_ = nullptr;
    sptr<PermissionFormStateObserver> formInvisibleCallback_ = nullptr;

    std::mutex formTokenMutex_;
    std::map<std::string, AccessTokenID> formTokenMap_;

    // app manager death
    std::mutex appManagerDeathMutex_;
    std::shared_ptr<PermissionAppManagerDeathCallback> appManagerDeathCallback_ = nullptr;
    DISALLOW_COPY_AND_MOVE(TempPermissionObserver);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // TEMP_PERMISSION_OBSERVER_H
