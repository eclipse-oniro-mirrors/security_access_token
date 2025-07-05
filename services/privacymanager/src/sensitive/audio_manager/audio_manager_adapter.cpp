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
#include "accesstoken_common_log.h"
#ifdef AUDIO_FRAMEWORK_ENABLE
#include "audio_policy_ipc_interface_code.h"
#endif
#include <iremote_proxy.h>
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

AudioManagerAdapter& AudioManagerAdapter::GetInstance()
{
    static AudioManagerAdapter *instance = new (std::nothrow) AudioManagerAdapter();
    return *instance;
}

AudioManagerAdapter::AudioManagerAdapter()
{}

AudioManagerAdapter::~AudioManagerAdapter()
{}

bool AudioManagerAdapter::GetPersistentMicMuteState()
{
#ifndef AUDIO_FRAMEWORK_ENABLE
    LOGI(PRI_DOMAIN, PRI_TAG, "audio framework is not support.");
    return false;
#else
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to GetProxy.");
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    std::u16string AUDIO_MGR_DESCRIPTOR = u"OHOS.AudioStandard.IAudioPolicy";
    if (!data.WriteInterfaceToken(AUDIO_MGR_DESCRIPTOR)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to write WriteInterfaceToken.");
        return false;
    }
    int32_t error = proxy->SendRequest(
        static_cast<uint32_t>(AudioStandard::AudioPolicyInterfaceCode::GET_MICROPHONE_MUTE_PERSISTENT),
        data, reply, option);
    if (error != NO_ERROR) {
        LOGE(PRI_DOMAIN, PRI_TAG, "SendRequest error: %{public}d", error);
        return false;
    }
    int32_t errorCode = reply.ReadInt32();
    if (errorCode != NO_ERROR) {
        LOGE(PRI_DOMAIN, PRI_TAG, "GET_MICROPHONE_MUTE_PERSISTENT error: %{public}d", errorCode);
        return false;
    }
    return reply.ReadInt32() == 1 ? true : false;
#endif
}

#ifdef AUDIO_FRAMEWORK_ENABLE
void AudioManagerAdapter::InitProxy()
{
    if (proxy_ != nullptr && (!proxy_->IsObjectDead())) {
        return;
    }
    sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemManager == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Fail to get system ability registry.");
        return;
    }
    sptr<IRemoteObject> remoteObj = systemManager->CheckSystemAbility(AUDIO_POLICY_SERVICE_ID);
    if (remoteObj == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Fail to connect ability manager service.");
        return;
    }

    deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) AudioManagerDeathRecipient());
    if (deathRecipient_ == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to create AudioManagerDeathRecipient!");
        return;
    }
    if ((remoteObj->IsProxyObject()) && (!remoteObj->AddDeathRecipient(deathRecipient_))) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Add death recipient to AbilityManagerService failed.");
        return;
    }
    proxy_ = remoteObj;
}

sptr<IRemoteObject> AudioManagerAdapter::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr || proxy_->IsObjectDead()) {
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
    LOGE(PRI_DOMAIN, PRI_TAG, "AudioManagerDeathRecipient handle remote died.");
    AudioManagerAdapter::GetInstance().ReleaseProxy(remote);
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
