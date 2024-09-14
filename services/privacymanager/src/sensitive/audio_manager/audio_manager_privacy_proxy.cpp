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

#include "audio_manager_privacy_proxy.h"

#include "accesstoken_log.h"
#include "audio_policy_ipc_interface_code.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_PRIVACY, "AudioManagerPrivacyProxy"};
static constexpr int32_t ERROR = -1;
}

bool AudioManagerPrivacyProxy::GetPersistentMicMuteState()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInterfaceToken failed");
        return false;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Remote service is null.");
        return false;
    }
    int32_t error = remote->SendRequest(static_cast<uint32_t>(
        AudioStandard::AudioPolicyInterfaceCode::GET_MICROPHONE_MUTE_PERSISTENT), data, reply, option);
    if (error != ERR_NONE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetPersistentMicMuteState failed, error: %{public}d", error);
        return false;
    }
    bool isMute = reply.ReadBool();
    ACCESSTOKEN_LOG_INFO(LABEL, "Mic mute state: %{public}d", isMute);
    return isMute;
}

int32_t AudioManagerPrivacyProxy::SetMicrophoneMutePersistent(const bool isMute, const PolicyType type)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInterfaceToken failed");
        return ERROR;
    }
    data.WriteBool(isMute);
    data.WriteInt32(static_cast<int32_t>(type));
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Remote service is null.");
        return ERROR;
    }
    int32_t error = remote->SendRequest(static_cast<uint32_t>(
        AudioStandard::AudioPolicyInterfaceCode::SET_MICROPHONE_MUTE_PERSISTENT), data, reply, option);
    if (error != ERR_NONE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Set microphoneMute failed, error: %d", error);
        return error;
    }
    int32_t ret = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "Set mute result: %{public}d", ret);
    return ret;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
