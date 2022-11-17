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

#include "window_manager_privacy_proxy.h"
#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
    constexpr HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_PRIVACY, "WindowManagerPrivacyProxy"};
}

bool WindowManagerPrivacyProxy::RegisterWindowManagerAgent(WindowManagerAgentType type,
    const sptr<IWindowManagerAgent>& windowManagerAgent)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInterfaceToken failed");
        return false;
    }

    if (!data.WriteUint32(static_cast<uint32_t>(type))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write type failed");
        return false;
    }

    if (!data.WriteRemoteObject(windowManagerAgent->AsObject())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write IWindowManagerAgent failed");
        return false;
    }
    if (Remote()->SendRequest(
        static_cast<uint32_t>(IWindowManager::WindowManagerMessage::TRANS_ID_REGISTER_WINDOW_MANAGER_AGENT),
        data, reply, option) != ERR_NONE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest failed");
        return false;
    }
    return reply.ReadBool();
}

bool WindowManagerPrivacyProxy::UnregisterWindowManagerAgent(WindowManagerAgentType type,
    const sptr<IWindowManagerAgent>& windowManagerAgent)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInterfaceToken failed");
        return false;
    }

    if (!data.WriteUint32(static_cast<uint32_t>(type))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write type failed");
        return false;
    }

    if (!data.WriteRemoteObject(windowManagerAgent->AsObject())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write IWindowManagerAgent failed");
        return false;
    }

    if (Remote()->SendRequest(
        static_cast<uint32_t>(IWindowManager::WindowManagerMessage::TRANS_ID_UNREGISTER_WINDOW_MANAGER_AGENT),
        data, reply, option) != ERR_NONE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest failed");
        return false;
    }

    return reply.ReadBool();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
