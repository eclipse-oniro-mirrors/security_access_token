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

#ifndef WINDOW_MANAGER_PRIVACY_CLIENT_H
#define WINDOW_MANAGER_PRIVACY_CLIENT_H

#include <mutex>
#include <string>

#include "window_manager_privacy_death_recipient.h"
#include "window_manager_privacy_proxy.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class WindowManagerPrivacyClient final {
public:
    static WindowManagerPrivacyClient& GetInstance();

    virtual ~WindowManagerPrivacyClient();
    bool RegisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent);
    bool UnregisterWindowManagerAgent(WindowManagerAgentType type,
        const sptr<IWindowManagerAgent>& windowManagerAgent);
    void OnRemoteDiedHandle();

private:
    WindowManagerPrivacyClient();
    DISALLOW_COPY_AND_MOVE(WindowManagerPrivacyClient);

    void InitProxy();
    sptr<IWindowManager> GetProxy();

    sptr<WindowManagerPrivacyDeathRecipient> serviceDeathObserver_ = nullptr;
    std::mutex proxyMutex_;
    sptr<IWindowManager> proxy_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // WINDOW_MANAGER_PRIVACY_CLIENT_H

