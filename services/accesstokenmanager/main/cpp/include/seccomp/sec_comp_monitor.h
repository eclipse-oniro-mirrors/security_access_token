/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef PERMISSION_SEC_COMP_MONITOR_H
#define PERMISSION_SEC_COMP_MONITOR_H

#include <mutex>
#include <set>
#include <vector>
#include "app_manager_death_callback.h"
#include "app_status_change_callback.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class SecCompUsageObserver : public ApplicationStateObserverStub {
public:
    SecCompUsageObserver() = default;
    ~SecCompUsageObserver() = default;

    void OnProcessDied(const ProcessData &processData) override;
    void OnProcessStateChanged(const ProcessData &processData) override;
    void OnAppCacheStateChanged(const AppStateData &appStateData) override;
    DISALLOW_COPY_AND_MOVE(SecCompUsageObserver);
};

class SecCompAppManagerDeathCallback : public AppManagerDeathCallback {
public:
    SecCompAppManagerDeathCallback() = default;
    ~SecCompAppManagerDeathCallback() = default;

    void NotifyAppManagerDeath() override;
    DISALLOW_COPY_AND_MOVE(SecCompAppManagerDeathCallback);
};

class SecCompMonitor final {
public:
    static SecCompMonitor& GetInstance();
    ~SecCompMonitor();

    void RemoveProcessFromForegroundList(int32_t pid);
    bool IsToastShownNeeded(int32_t pid);
    void OnAppMgrRemoteDiedHandle();

private:
    SecCompMonitor();
    void InitAppObserver();
    DISALLOW_COPY_AND_MOVE(SecCompMonitor);
    sptr<SecCompUsageObserver> observer_ = nullptr;
    std::shared_ptr<SecCompAppManagerDeathCallback> appManagerDeathCallback_ = nullptr;
    std::mutex appfgLock_;
    std::set<int32_t> appsInForeground_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_SEC_COMP_MONITOR_H
