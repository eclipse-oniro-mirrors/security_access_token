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

#ifndef WINDOW_MANAGER_PRIVACY_AGENT_H
#define WINDOW_MANAGER_PRIVACY_AGENT_H

#include "accesstoken_kit.h"
#include "iremote_stub.h"
#include "nocopyable.h"
#include "window_manager_privacy_proxy.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

typedef void (*OnCameraFloatWindowChangeCallback)(AccessTokenID tokenId, bool isShowing);
class WindowManagerPrivacyAgent : public IRemoteStub<IWindowManagerAgent> {
public:
    WindowManagerPrivacyAgent() = default;
    ~WindowManagerPrivacyAgent() = default;

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;
    void UpdateCameraFloatWindowStatus(uint32_t accessTokenId, bool isShowing) override;
    void SetCallBack(OnCameraFloatWindowChangeCallback callback);

private:
    OnCameraFloatWindowChangeCallback callback_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // WINDOW_MANAGER_PRIVACY_AGENT_H
