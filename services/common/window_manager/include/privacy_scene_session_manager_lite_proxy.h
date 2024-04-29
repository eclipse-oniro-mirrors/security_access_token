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

#ifndef PRIVACY_SCENE_SESSION_MANAGER_LITE_PROXY_H
#define PRIVACY_SCENE_SESSION_MANAGER_LITE_PROXY_H

#include <iremote_proxy.h>
#include "privacy_window_manager_interface.h"
#include "privacy_window_manager_interface_lite.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class ISceneSessionManagerLite : public IWindowManagerLite {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.ISceneSessionManagerLite");

    enum class SceneSessionManagerLiteMessage : uint32_t {
        TRANS_ID_REGISTER_WINDOW_MANAGER_AGENT = 22,
        TRANS_ID_UNREGISTER_WINDOW_MANAGER_AGENT = 23,
    };

    virtual int32_t RegisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) = 0;
    virtual int32_t UnregisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) = 0;
};

class PrivacySceneSessionManagerLiteProxy : public IRemoteProxy<ISceneSessionManagerLite> {
public:
    explicit PrivacySceneSessionManagerLiteProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<ISceneSessionManagerLite>(impl) {}
    virtual ~PrivacySceneSessionManagerLiteProxy() = default;

    int32_t RegisterWindowManagerAgent(WindowManagerAgentType type,
            const sptr<IWindowManagerAgent>& windowManagerAgent) override;
    int32_t UnregisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) override;
private:
    static inline BrokerDelegator<PrivacySceneSessionManagerLiteProxy> delegator_;
};
}
}
}
#endif // PRIVACY_SCENE_SESSION_MANAGER_LITE_PROXY_H
