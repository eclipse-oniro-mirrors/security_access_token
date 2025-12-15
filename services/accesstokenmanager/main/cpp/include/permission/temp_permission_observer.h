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

#ifndef TEMP_PERMISSION_OBSERVER_H
#define TEMP_PERMISSION_OBSERVER_H

#include <mutex>
#include <vector>
#include <string>

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
    void AddContinuousTask(AccessTokenID tokenID);
    void DelContinuousTask(AccessTokenID tokenID);
    bool FindContinuousTask(AccessTokenID tokenID);
#ifdef EVENTHANDLER_ENABLE
    void InitEventHandler();
    void SetCancelTime(int32_t cancelTime);
#endif
    bool DelayRevokePermission(AccessToken::AccessTokenID tokenId, const std::string& taskName);
    bool CancelTaskOfPermissionRevoking(const std::string& taskName);
    void RegisterCallback();
    void RegisterAppStatusListener();
    void UnRegisterCallback();
    int32_t NotifyWhetherFormsVisible(const FormVisibilityType visibleType,
        const std::string &bundleName, std::vector<FormInstance> &formInstances);
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
    void OnContinuousTaskStart(const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo);
    void OnContinuousTaskStop(const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo);
#endif

private:
#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AccessEventHandler> GetEventHandler();
    std::shared_ptr<AccessEventHandler> eventHandler_;
    std::mutex eventHandlerLock_;
#endif
    int32_t cancelTimes_;
    std::mutex tempPermissionMutex_;
    std::map<AccessTokenID, std::vector<bool>> tempPermTokenMap_;

    std::mutex continuousTaskMutex_;
    std::map<AccessTokenID, int32_t> continuousTaskMap_;

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
