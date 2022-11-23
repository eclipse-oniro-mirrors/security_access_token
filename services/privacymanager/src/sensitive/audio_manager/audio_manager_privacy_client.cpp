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
#include "audio_manager_privacy_client.h"
#include <unistd.h>

#include "accesstoken_log.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "AudioManagerPrivacyClient"
};
} // namespace

AudioManagerPrivacyClient& AudioManagerPrivacyClient::GetInstance()
{
    static AudioManagerPrivacyClient instance;
    return instance;
}

AudioManagerPrivacyClient::AudioManagerPrivacyClient()
{}

AudioManagerPrivacyClient::~AudioManagerPrivacyClient()
{}

int32_t AudioManagerPrivacyClient::SetMicStateChangeCallback(const sptr<AudioRoutingManagerListenerStub>& callback)
{
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "AudioPolicyManager: callback is nullptr");
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return -1;
    }
    int32_t clientId = static_cast<int32_t>(getpid());
    sptr<IRemoteObject> object = callback->AsObject();
    if (object == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "AudioPolicyManager: AsObject is nullptr.");
        return -1;
    }
    return proxy->SetMicStateChangeCallback(clientId, object);
}

int32_t AudioManagerPrivacyClient::SetMicrophoneMute(bool isMute)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return -1;
    }
    return proxy->SetMicrophoneMute(isMute);
}

bool AudioManagerPrivacyClient::IsMicrophoneMute()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return false;
    }
    return proxy->IsMicrophoneMute();
}

void AudioManagerPrivacyClient::InitProxy()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbilityManager is null");
        return;
    }
    auto audioManagerSa = sam->GetSystemAbility(AUDIO_POLICY_SERVICE_ID);
    if (audioManagerSa == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbility %{public}d is null",
            AUDIO_POLICY_SERVICE_ID);
        return;
    }

    serviceDeathObserver_ = new (std::nothrow) AudioMgrDeathRecipient();
    if (serviceDeathObserver_ != nullptr) {
        audioManagerSa->AddDeathRecipient(serviceDeathObserver_);
    }

    proxy_ = iface_cast<IAudioPolicy>(audioManagerSa);
    if (proxy_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "iface_cast get null");
    }
}

void AudioManagerPrivacyClient::OnRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    proxy_ = nullptr;
}

sptr<IAudioPolicy> AudioManagerPrivacyClient::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr) {
        InitProxy();
    }
    return proxy_;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

