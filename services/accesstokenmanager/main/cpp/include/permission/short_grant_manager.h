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


#ifndef SHORT_GRANT_MANAGER_H
#define SHORT_GRANT_MANAGER_H

#include <memory>
#include <mutex>
#include <unordered_map>
#include <string>

#include "access_event_handler.h"
#include "app_status_change_callback.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

using AccessTokenID = uint32_t;

typedef struct {
    AccessTokenID tokenID;
    std::string permissionName;
    uint32_t firstGrantTimes;
    uint32_t revokeTimes;
} PermTimerData;

class ShortPermAppStateObserver : public ApplicationStateObserverStub {
public:
    ShortPermAppStateObserver() = default;
    ~ShortPermAppStateObserver() = default;

    void OnAppStopped(const AppStateData &appStateData) override;

    DISALLOW_COPY_AND_MOVE(ShortPermAppStateObserver);
};

class ShortGrantManager {
public:
    static ShortGrantManager& GetInstance();

    void InitEventHandler(const std::shared_ptr<AccessEventHandler>& eventHandler);

    int RefreshPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t onceTime);

    bool IsShortGrantPermission(const std::string& permissionName);

    void ClearShortPermissionByTokenID(AccessTokenID tokenID);

private:
    ShortGrantManager();
    ~ShortGrantManager() = default;
    uint32_t GetCurrentTime();
    void ScheduleRevokeTask(AccessTokenID tokenID, const std::string& permission,
        const std::string& taskName, uint32_t cancelTimes);
    void ClearShortPermissionData(AccessTokenID tokenID, const std::string& permission);
    bool CancelTaskOfPermissionRevoking(const std::string& taskName);
    uint32_t maxTime_;
    std::vector<PermTimerData> shortGrantData_;
    std::mutex shortGrantDataMutex_;
    std::shared_ptr<AccessEventHandler> eventHandler_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // SHORT_GRANT_MANAGER_H
