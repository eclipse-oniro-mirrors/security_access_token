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

namespace OHOS {
namespace Security {
namespace AccessToken {
enum class WindowManagerAgentType : uint32_t {
    WINDOW_MANAGER_AGENT_TYPE_FOCUS,
    WINDOW_MANAGER_AGENT_TYPE_SYSTEM_BAR,
    WINDOW_MANAGER_AGENT_TYPE_WINDOW_UPDATE,
    WINDOW_MANAGER_AGENT_TYPE_WINDOW_VISIBILITY,
    WINDOW_MANAGER_AGENT_TYPE_CAMERA_FLOAT,
};

class IWindowManagerAgent : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.IWindowManagerAgent");
    enum class WindowManagerAgentMsg : uint32_t {
        TRANS_ID_UPDATE_FOCUS  = 1,
        TRANS_ID_UPDATE_SYSTEM_BAR_PROPS,
        TRANS_ID_UPDATE_WINDOW_STATUS,
        TRANS_ID_UPDATE_WINDOW_VISIBILITY,
        TRANS_ID_UPDATE_CAMERA_FLOAT,
    };

    virtual void UpdateCameraFloatWindowStatus(uint32_t accessTokenId, bool isShowing) = 0;
};

class IWindowManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.IWindowManager");

    enum class WindowManagerMessage : uint32_t {
        TRANS_ID_CREATE_WINDOW,
        TRANS_ID_ADD_WINDOW,
        TRANS_ID_REMOVE_WINDOW,
        TRANS_ID_DESTROY_WINDOW,
        TRANS_ID_REQUEST_FOCUS,
        TRANS_ID_REGISTER_FOCUS_CHANGED_LISTENER,
        TRANS_ID_UNREGISTER_FOCUS_CHANGED_LISTENER,
        TRANS_ID_REGISTER_WINDOW_MANAGER_AGENT,
        TRANS_ID_UNREGISTER_WINDOW_MANAGER_AGENT,
        TRANS_ID_GET_AVOID_AREA,
        TRANS_ID_GET_TOP_WINDOW_ID,
        TRANS_ID_PROCESS_POINT_DOWN,
        TRANS_ID_PROCESS_POINT_UP,
        TRANS_ID_MINIMIZE_ALL_APP_WINDOWS,
        TRANS_ID_TOGGLE_SHOWN_STATE_FOR_ALL_APP_WINDOWS,
        TRANS_ID_SET_BACKGROUND_BLUR,
        TRANS_ID_SET_ALPHA,
        TRANS_ID_UPDATE_LAYOUT_MODE,
        TRANS_ID_UPDATE_PROPERTY,
        TRANS_ID_GET_ACCESSIBILITY_WINDOW_INFO_ID,
        TRANS_ID_GET_VISIBILITY_WINDOW_INFO_ID,
        TRANS_ID_ANIMATION_SET_CONTROLLER,
        TRANS_ID_GET_SYSTEM_CONFIG,
        TRANS_ID_NOTIFY_WINDOW_TRANSITION,
        TRANS_ID_GET_FULLSCREEN_AND_SPLIT_HOT_ZONE,
        TRANS_ID_GET_ANIMATION_CALLBACK,
        TRANS_ID_UPDATE_AVOIDAREA_LISTENER,
        TRANS_ID_UPDATE_RS_TREE,
        TRANS_ID_BIND_DIALOG_TARGET,
        TRANS_ID_NOTIFY_READY_MOVE_OR_DRAG,
        TRANS_ID_SET_ANCHOR_AND_SCALE,
        TRANS_ID_SET_ANCHOR_OFFSET,
        TRANS_ID_OFF_WINDOW_ZOOM,
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
