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

#ifndef OHOS_WINDOW_MANAGER_PRIVACY_PROXY_H
#define OHOS_WINDOW_MANAGER_PRIVACY_PROXY_H

#include <iremote_proxy.h>

#include "privacy_window_service_ipc_interface_code.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum class WindowManagerAgentType : uint32_t {
    WINDOW_MANAGER_AGENT_TYPE_FOCUS,
    WINDOW_MANAGER_AGENT_TYPE_SYSTEM_BAR,
    WINDOW_MANAGER_AGENT_TYPE_WINDOW_UPDATE,
    WINDOW_MANAGER_AGENT_TYPE_WINDOW_VISIBILITY,
    WINDOW_MANAGER_AGENT_TYPE_WINDOW_DRAWING_STATE,
    WINDOW_MANAGER_AGENT_TYPE_CAMERA_FLOAT,
    WINDOW_MANAGER_AGENT_TYPE_WATER_MARK_FLAG,
    WINDOW_MANAGER_AGENT_TYPE_GESTURE_NAVIGATION_ENABLED,
};

class IWindowManagerAgent : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.IWindowManagerAgent");

    virtual void UpdateCameraFloatWindowStatus(uint32_t accessTokenId, bool isShowing) = 0;
};

class IWindowManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.IWindowManager");

    enum class WindowManagerMessage : uint32_t {
        TRANS_ID_REGISTER_WINDOW_MANAGER_AGENT = 7,
        TRANS_ID_UNREGISTER_WINDOW_MANAGER_AGENT = 8,
    };

    virtual bool RegisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) = 0;
    virtual bool UnregisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) = 0;
};

class WindowManagerPrivacyProxy : public IRemoteProxy<IWindowManager> {
public:
    explicit WindowManagerPrivacyProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IWindowManager>(impl) {};

    ~WindowManagerPrivacyProxy() {};
    bool RegisterWindowManagerAgent(WindowManagerAgentType type,
            const sptr<IWindowManagerAgent>& windowManagerAgent) override;
    bool UnregisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) override;

private:
    static inline BrokerDelegator<WindowManagerPrivacyProxy> delegator_;
};
}
}
}
#endif // OHOS_WINDOW_MANAGER_PRIVACY_PROXY_H
