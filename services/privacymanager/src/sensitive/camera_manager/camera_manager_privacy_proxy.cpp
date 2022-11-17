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

#include "camera_manager_privacy_proxy.h"
#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_PRIVACY, "CameraManagerPrivacyProxy"};
static constexpr int32_t ERROR = -1;
}

int32_t CameraManagerPrivacyProxy::SetMuteCallback(const sptr<ICameraMuteServiceCallback>& callback)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback is null");
        return ERROR;
    }

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInterfaceToken failed");
        return ERROR;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteRemoteObject failed");
        return ERROR;
    }

    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(CAMERA_SERVICE_SET_MUTE_CALLBACK), data, reply, option);
    if (error != ERR_NONE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest failed, error: %{public}d", error);
    }
    return error;
}

int32_t CameraManagerPrivacyProxy::MuteCamera(bool muteMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write descriptor");
        return ERROR;
    }
    if (!data.WriteBool(muteMode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write bool");
        return ERROR;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(CAMERA_SERVICE_MUTE_CAMERA), data, reply, option);
    if (error != ERR_NONE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest failed, error: %{public}d", error);
        return ERROR;
    }
    error = reply.ReadInt32();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "MuteCamera Read muteMode is %{public}d", error);
    return error;
}

int32_t CameraManagerPrivacyProxy::IsCameraMuted(bool &muteMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write descriptor");
        return ERROR;
    }
    if (!data.WriteBool(muteMode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write bool");
        return ERROR;
    }
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(CAMERA_SERVICE_IS_CAMERA_MUTED), data, reply, option);
    if (error != ERR_NONE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest failed, error: %{public}d", error);
        return ERROR;
    }
    muteMode = reply.ReadBool();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "IsCameraMuted Read muteMode is %{public}d", muteMode);
    return error;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
