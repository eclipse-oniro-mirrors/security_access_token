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

int32_t CameraManagerPrivacyProxy::MuteCameraPersist(PolicyType policyType, bool muteMode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write descriptor");
        return ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(policyType))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write bool");
        return ERROR;
    }
    if (!data.WriteBool(muteMode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write bool");
        return ERROR;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Remote service is null.");
        return ERROR;
    }
    int32_t error = remote->SendRequest(
        static_cast<uint32_t>(CAMERA_SERVICE_MUTE_CAMERA_PERSIST), data, reply, option);
    if (error != ERR_NONE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest failed, error: %{public}d", error);
    }
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
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Remote service is null.");
        return ERROR;
    }
    int32_t error = remote->SendRequest(static_cast<uint32_t>(CAMERA_SERVICE_IS_CAMERA_MUTED), data, reply, option);
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
