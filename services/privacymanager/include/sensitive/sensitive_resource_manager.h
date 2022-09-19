/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef RESOURCE_MANAGER_H
#define RESOURCE_MANAGER_H

#include <map>
#include <mutex>
#include <string>
#include "app_mgr_proxy.h"
#include "application_status_change_callback.h"
#include "safe_map.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum AppStatus {
    APP_CREATE = 0,
    APP_DIE,
    APP_FOREGROUND,
    APP_BACKGROUND,
};
enum ResourceType {
    INVALID = -1,
    CAMERA = 0,
    MICROPHONE = 1,
};

using DialogCallback = std::function<void(int32_t id, const std::string& event, const std::string& param)>;
class SensitiveResourceManager final {
public:
    static SensitiveResourceManager& GetInstance();
    SensitiveResourceManager();
    virtual ~SensitiveResourceManager();
    void Init();

    bool GetAppStatus(const std::string& pkgName, int32_t& status);
    bool GetGlobalSwitch(const ResourceType type);
    void SetGlobalSwitch(const ResourceType type, bool switchStatus);

    // register and unregister app status change callback
    bool RegisterAppStatusChangeCallback(uint32_t tokenId, OnAppStatusChangeCallback callback);
    bool UnRegisterAppStatusChangeCallback(uint32_t tokenId, OnAppStatusChangeCallback callback);

private:
    bool InitProxy();
    OHOS::sptr<OHOS::AppExecFwk::IAppMgr> GetAppManagerProxy();
    
private:
    std::mutex appStatusMutex_;
    std::vector<OHOS::sptr<ApplicationStatusChangeCallback>> appStateCallbacks_;
    SafeMap<ResourceType, bool> switchStatusMap_;
    std::mutex mutex_;
    sptr<AppExecFwk::IAppMgr> appMgrProxy_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // RESOURCE_MANAGER_H
