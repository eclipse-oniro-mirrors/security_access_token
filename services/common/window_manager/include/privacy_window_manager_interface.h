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
#ifndef PRIVACY_WINDOW_MANAGER_NTERFACE_H
#define PRIVACY_WINDOW_MANAGER_NTERFACE_H

#include <iremote_broker.h>

namespace OHOS {
namespace Security {
namespace AccessToken {

enum class WindowManagerAgentType : uint32_t {
    WINDOW_MANAGER_AGENT_TYPE_CAMERA_FLOAT = 5,
    WINDOW_MANAGER_AGENT_TYPE_CAMERA_WINDOW = 9,
};

enum class PrivacyWindowServiceInterfaceCode {
    TRANS_ID_UPDATE_CAMERA_FLOAT = 6,
    TRANS_ID_UPDATE_CAMERA_WINDOW_STATUS = 10,
};

class IWindowManagerAgent : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.IWindowManagerAgent");

    virtual void UpdateCameraFloatWindowStatus(uint32_t accessTokenId, bool isShowing) = 0;
    virtual void UpdateCameraWindowStatus(uint32_t accessTokenId, bool isShowing) = 0;
};

class IWindowManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.IWindowManager");
    enum class WindowManagerMessage : uint32_t {
        TRANS_ID_REGISTER_WINDOW_MANAGER_AGENT = 7,
        TRANS_ID_UNREGISTER_WINDOW_MANAGER_AGENT = 8,
    };

    virtual int32_t RegisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) = 0;
    virtual int32_t UnregisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) = 0;
};
}
}
}
#endif // PRIVACY_WINDOW_MANAGER_NTERFACE_H
