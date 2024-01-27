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
#include "app_manager_death_recipient.h"
#include "app_status_change_callback.h"
#include "permission_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionAppStateObserver : public ApplicationStateObserverStub {
public:
    PermissionAppStateObserver() = default;
    ~PermissionAppStateObserver() = default;

    void OnForegroundApplicationChanged(const AppStateData &appStateData) override;
    void OnProcessDied(const ProcessData &processData) override;
    DISALLOW_COPY_AND_MOVE(PermissionAppStateObserver);

private:
    std::mutex taskMutex_;
    std::vector<std::string> taskName_;
};

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

    void AddTempPermTokenToList(AccessTokenID tokenID, const std::string& permissionName);
    void DeleteTempPermFromList(AccessTokenID tokenID, const std::string& permissionName);
    void RevokeAllTempPermission(AccessTokenID tokenID);
    bool GetPermissionStateFull(AccessTokenID tokenID, std::vector<PermissionStateFull>& permissionStateFullList);
    
#ifdef EVENTHANDLER_ENABLE
    void InitEventHandler(const std::shared_ptr<AccessEventHandler>& eventHandler);
#endif
    bool DelayRevokePermission(AccessToken::AccessTokenID tokenId, const std::string& taskName);
    bool CancleTaskOfPermissionRevoking(const std::string& taskName);
    void RegisterCallback();

private:
#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AccessEventHandler> eventHandler_;
#endif

    std::mutex tempPermissionMutex_;
    std::vector<AccessTokenID> tempPermTokenList_;

    // appState
    sptr<PermissionAppStateObserver> appStateCallback_ = nullptr;

    // app manager death
    std::shared_ptr<PermissionAppManagerDeathCallback> appManagerDeathCallback_ = nullptr;
    DISALLOW_COPY_AND_MOVE(TempPermissionObserver);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // TEMP_PERMISSION_OBSERVER_H
