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
#include "camera_global_switch_change_callback.h"
#include "mic_global_switch_change_callback.h"
#include "safe_map.h"
#include "sensitive_death_recipient.h"
#include "privacy_error.h"
#include "accesstoken_kit.h"
#include "window_manager_privacy_client.h"
#include "window_manager_privacy_agent.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef void (*OnCameraFloatWindowChangeCallback)(AccessTokenID tokenId, bool isShowing);
enum AppStatus {
    APP_INVALID = 0,
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

    bool GetAppStatus(const std::string& pkgName, int32_t& status);
    bool GetGlobalSwitch(const ResourceType type);
    bool IsFlowWindowShow(AccessTokenID tokenId);
    void SetFlowWindowStatus(AccessTokenID tokenId, bool isShow);
    void OnRemoteDiedHandle();

    int32_t ShowDialog(const ResourceType& type);

    // register and unregister app status change callback
    int32_t RegisterAppStatusChangeCallback(uint32_t tokenId, OnAppStatusChangeCallback callback);
    int32_t UnRegisterAppStatusChangeCallback(uint32_t tokenId, OnAppStatusChangeCallback callback);

    // mic global switch
    int32_t RegisterMicGlobalSwitchChangeCallback(OnMicGlobalSwitchChangeCallback callback);
    int32_t UnRegisterMicGlobalSwitchChangeCallback(OnMicGlobalSwitchChangeCallback callback);

    // camera global switch
    int32_t RegisterCameraGlobalSwitchChangeCallback(OnCameraGlobalSwitchChangeCallback callback);
    int32_t UnRegisterCameraGlobalSwitchChangeCallback(OnCameraGlobalSwitchChangeCallback callback);

    // camera float window
    int32_t RegisterCameraFloatWindowChangeCallback(OnCameraFloatWindowChangeCallback callback);
    int32_t UnRegisterCameraFloatWindowChangeCallback(OnCameraFloatWindowChangeCallback callback);
private:
    bool InitProxy();
    OHOS::sptr<OHOS::AppExecFwk::IAppMgr> GetAppManagerProxy();
    sptr<SensitiveDeathRecipient> sensitiveDeathObserver_ = nullptr;

private:
    std::mutex appStatusMutex_;
    std::vector<OHOS::sptr<ApplicationStatusChangeCallback>> appStateCallbacks_;
    std::mutex flowWindowMutex_;
    bool flowWindowStatus_ = false;
    AccessTokenID flowWindowId_ = INVALID_TOKENID;
    std::mutex micGlobalSwitchMutex_;
    std::vector<std::shared_ptr<MicGlobalSwitchChangeCallback>> micGlobalSwitchCallbacks_;
    std::mutex CameraGlobalSwitchMutex_;
    std::vector<std::shared_ptr<CameraGlobalSwitchChangeCallback>> CameraGlobalSwitchCallbacks_;
    sptr<WindowManagerPrivacyAgent> floatAgent_;
    std::mutex mutex_;
    sptr<AppExecFwk::IAppMgr> appMgrProxy_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // RESOURCE_MANAGER_H
