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

#ifndef PRIVACY_WINDOW_MANAGER_AGENT_H
#define PRIVACY_WINDOW_MANAGER_AGENT_H

#include "iremote_stub.h"
#include "nocopyable.h"
#include "privacy_window_manager_interface.h"
#include "window_manager_loader.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PrivacyWindowManagerAgent : public IRemoteStub<IWindowManagerAgent> {
public:
    PrivacyWindowManagerAgent(WindowChangeCallback callback);
    ~PrivacyWindowManagerAgent() = default;

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;
    void UpdateCameraFloatWindowStatus(uint32_t accessTokenId, bool isShowing) override;
    void UpdateCameraWindowStatus(uint32_t accessTokenId, bool isShowing) override;
private:
    WindowChangeCallback callback_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PRIVACY_WINDOW_MANAGER_AGENT_H

