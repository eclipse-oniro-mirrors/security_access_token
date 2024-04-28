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

#ifndef PRIVACY_OHOS_WINDOW_MANAGER_PROXY_H
#define PRIVACY_OHOS_WINDOW_MANAGER_PROXY_H

#include <iremote_proxy.h>
#include "privacy_window_manager_interface.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyWindowManagerProxy : public IRemoteProxy<IWindowManager> {
public:
    explicit PrivacyWindowManagerProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<IWindowManager>(impl) {}

    ~PrivacyWindowManagerProxy() {}
    int32_t RegisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) override;
    int32_t UnregisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent) override;

private:
    static inline BrokerDelegator<PrivacyWindowManagerProxy> delegator_;
};
}
}
}
#endif // PRIVACY_OHOS_WINDOW_MANAGER_PROXY_H
