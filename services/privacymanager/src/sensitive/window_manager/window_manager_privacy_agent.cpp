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

#include "window_manager_privacy_agent.h"
#include "accesstoken_log.h"
#include "permission_record_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "WindowManagerPrivacyAgent"
};
}

int WindowManagerPrivacyAgent::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, code: %{public}u", __func__, code);
    if (data.ReadInterfaceToken() != IWindowManagerAgent::GetDescriptor()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, read desciptor error", __func__);
        return -1;
    }
    IWindowManagerAgent::WindowManagerAgentMsg msgId = static_cast<IWindowManagerAgent::WindowManagerAgentMsg>(code);
    switch (msgId) {
        case IWindowManagerAgent::WindowManagerAgentMsg::TRANS_ID_UPDATE_CAMERA_FLOAT: {
            uint32_t accessTokenId = data.ReadUint32();
            bool isShowing = data.ReadBool();
            UpdateCameraFloatWindowStatus(accessTokenId, isShowing);
            break;
        }
        default:
            break;
    }
    return 0;
}

void WindowManagerPrivacyAgent::UpdateCameraFloatWindowStatus(uint32_t accessTokenId, bool isShowing)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OnChange(tokenId=%{public}d, isShow=%{public}d)", accessTokenId, isShowing);
    PermissionRecordManager::GetInstance().NotifyCameraFloatWindowChange(accessTokenId, isShowing);
}
} // namespace AccessToken
}
} // namespace OHOS

