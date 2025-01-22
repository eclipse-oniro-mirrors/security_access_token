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

#include "privacy_window_manager_proxy.h"
#include "accesstoken_common_log.h"
#include "privacy_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

int32_t PrivacyWindowManagerProxy::RegisterWindowManagerAgent(WindowManagerAgentType type,
    const sptr<IWindowManagerAgent>& windowManagerAgent)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE(PRI_DOMAIN, PRI_TAG, "WriteInterfaceToken failed");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteUint32(static_cast<uint32_t>(type))) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Write type failed");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteRemoteObject(windowManagerAgent->AsObject())) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Write IWindowManagerAgent failed");
        return ERR_WRITE_PARCEL_FAILED;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Remote service is null.");
        return ERR_REMOTE_CONNECTION;
    }
    int32_t error = remote->SendRequest(
        static_cast<uint32_t>(IWindowManager::WindowManagerMessage::TRANS_ID_REGISTER_WINDOW_MANAGER_AGENT),
        data, reply, option);
    if (error != ERR_NONE) {
        LOGE(PRI_DOMAIN, PRI_TAG, "SendRequest failed");
        return error;
    }
    return reply.ReadInt32();
}

int32_t PrivacyWindowManagerProxy::UnregisterWindowManagerAgent(WindowManagerAgentType type,
    const sptr<IWindowManagerAgent>& windowManagerAgent)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE(PRI_DOMAIN, PRI_TAG, "WriteInterfaceToken failed");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteUint32(static_cast<uint32_t>(type))) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Write type failed");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteRemoteObject(windowManagerAgent->AsObject())) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Write IWindowManagerAgent failed");
        return ERR_WRITE_PARCEL_FAILED;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Remote service is null.");
        return ERR_REMOTE_CONNECTION;
    }
    int32_t error = remote->SendRequest(
        static_cast<uint32_t>(IWindowManager::WindowManagerMessage::TRANS_ID_UNREGISTER_WINDOW_MANAGER_AGENT),
        data, reply, option);
    if (error != ERR_NONE) {
        LOGE(PRI_DOMAIN, PRI_TAG, "SendRequest failed");
        return error;
    }

    return reply.ReadInt32();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
