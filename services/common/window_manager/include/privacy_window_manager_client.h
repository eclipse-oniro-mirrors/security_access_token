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

#ifndef PRIVACY_WINDOW_MANAGER_CLIENT_H
#define PRIVACY_WINDOW_MANAGER_CLIENT_H

#include <mutex>
#include <string>

#include "nocopyable.h"
#include "privacy_window_manager_death_recipient.h"
#include "privacy_window_manager_interface.h"
#include "privacy_window_manager_interface_lite.h"
#include "privacy_scene_session_manager_lite_proxy.h"
#include "privacy_scene_session_manager_proxy.h"
#include "privacy_session_manager_proxy.h"
#include "privacy_mock_session_manager_proxy.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyWindowManagerClient final {
public:
    static PrivacyWindowManagerClient& GetInstance();

    virtual ~PrivacyWindowManagerClient();
    int32_t RegisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent);
    int32_t UnregisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent);
    void AddDeathCallback(void (*callback)());
    void OnRemoteDiedHandle();

private:
    PrivacyWindowManagerClient();
    DISALLOW_COPY_AND_MOVE(PrivacyWindowManagerClient);
    sptr<IWindowManager> GetProxy();
    sptr<IWindowManagerLite> GetLiteProxy();
    int32_t RegisterWindowManagerAgentLite(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent);
    int32_t UnregisterWindowManagerAgentLite(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent);

    void InitSceneSessionManagerProxy();
    void InitSessionManagerServiceProxy();
    void InitSceneSessionManagerLiteProxy();
    sptr<ISceneSessionManager> GetSSMProxy();
    sptr<ISceneSessionManagerLite> GetSSMLiteProxy();
    void InitWMSProxy();
    sptr<IWindowManager> GetWMSProxy();

    sptr<PrivacyWindowManagerDeathRecipient> serviceDeathObserver_ = nullptr;
    std::mutex proxyMutex_;

    std::mutex deathMutex_;
    void (*deathCallback_)();
    sptr<IMockSessionManagerInterface> mockSessionManagerServiceProxy_ = nullptr;
    sptr<ISessionManagerService> sessionManagerServiceProxy_ = nullptr;
    sptr<ISceneSessionManager> sceneSessionManagerProxy_ = nullptr;
    sptr<ISceneSessionManagerLite> sceneSessionManagerLiteProxy_ = nullptr;
    sptr<IWindowManager> wmsProxy_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_WINDOW_MANAGER_CLIENT_H

