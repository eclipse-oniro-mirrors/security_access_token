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

#include "audio_manager_adapter.h"
#include "access_token_error.h"
#include "accesstoken_log.h"
#include "audio_policy_ipc_interface_code.h"
#include <iremote_proxy.h>
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "AudioManagerAdapter"
};

const std::u16string AUDIO_MGR_DESCRIPTOR = u"IAudioPolicy";
}

AudioManagerAdapter& AudioManagerAdapter::GetInstance()
{
    static AudioManagerAdapter *instance = new (std::nothrow) AudioManagerAdapter();
    return *instance;
}

AudioManagerAdapter::AudioManagerAdapter()
{}

AudioManagerAdapter::~AudioManagerAdapter()
{}

int32_t AudioManagerAdapter::SetMicrophoneMutePersistent(const bool isMute, const PolicyType type)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to GetProxy.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(AUDIO_MGR_DESCRIPTOR)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteBool(isMute)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write isMute.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteInt32(static_cast<int32_t>(type))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write type.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    int32_t error = proxy->SendRequest(
        static_cast<uint32_t>(AudioStandard::AudioPolicyInterfaceCode::SET_MICROPHONE_MUTE_PERSISTENT),
        data, reply, option);
    if (error != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

bool AudioManagerAdapter::GetPersistentMicMuteState()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to GetProxy.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(AUDIO_MGR_DESCRIPTOR)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    int32_t error = proxy->SendRequest(
        static_cast<uint32_t>(AudioStandard::AudioPolicyInterfaceCode::GET_MICROPHONE_MUTE_PERSISTENT),
        data, reply, option);
    if (error != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest error: %{public}d", error);
        return error;
    }
    return reply.ReadBool();
}

void AudioManagerAdapter::InitProxy()
{
    if (proxy_ != nullptr) {
        return;
    }
    sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemManager == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to get system ability registry.");
        return;
    }
    sptr<IRemoteObject> remoteObj = systemManager->CheckSystemAbility(AUDIO_POLICY_SERVICE_ID);
    if (remoteObj == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to connect ability manager service.");
        return;
    }

    deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) AudioManagerDeathRecipient());
    if (deathRecipient_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to create AudioManagerDeathRecipient!");
        return;
    }
    if ((remoteObj->IsProxyObject()) && (!remoteObj->AddDeathRecipient(deathRecipient_))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Add death recipient to AbilityManagerService failed.");
        return;
    }
    proxy_ = remoteObj;
}

sptr<IRemoteObject> AudioManagerAdapter::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr) {
        InitProxy();
    }
    return proxy_;
}

void AudioManagerAdapter::ReleaseProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if ((proxy_ != nullptr) && (proxy_ == remote.promote())) {
        proxy_->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
        deathRecipient_ = nullptr;
    }
}

void AudioManagerAdapter::AudioManagerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    ACCESSTOKEN_LOG_ERROR(LABEL, "AudioManagerDeathRecipient handle remote died.");
    AudioManagerAdapter::GetInstance().ReleaseProxy(remote);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
