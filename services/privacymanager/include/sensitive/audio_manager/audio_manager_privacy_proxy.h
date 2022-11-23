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

#ifndef OHOS_AUDIO_MANAGER_PRIVACY_PROXY_H
#define OHOS_AUDIO_MANAGER_PRIVACY_PROXY_H

#include <iremote_proxy.h>

namespace OHOS {
namespace Security {
namespace AccessToken {
enum AudioPolicyCommand {
    SET_MICROPHONE_MUTE = 13,
    IS_MICROPHONE_MUTE = 15,
    SET_MIC_STATE_CHANGE_CALLBACK = 56,
};

struct MicStateChangeEvent {
    bool mute;
};

class IStandardAudioRoutingManagerListener : public IRemoteBroker {
public:
    virtual ~IStandardAudioRoutingManagerListener() = default;
    virtual void OnMicStateUpdated(const MicStateChangeEvent &micStateChangeEvent) = 0;

    enum AudioRingerModeUpdateListenerMsg {
        ON_ERROR = 0,
        ON_MIC_STATE_UPDATED,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"IStandardAudioRoutingManagerListener");
};

class IAudioPolicy : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"IAudioPolicy");

    virtual bool IsMicrophoneMute() = 0;
    virtual int32_t SetMicrophoneMute(bool isMute) = 0;
    virtual int32_t SetMicStateChangeCallback(const int32_t clientId, const sptr<IRemoteObject> &object) = 0;
};

class AudioManagerPrivacyProxy : public IRemoteProxy<IAudioPolicy> {
public:
    explicit AudioManagerPrivacyProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IAudioPolicy>(impl) {};

    virtual ~AudioManagerPrivacyProxy() = default;

    bool IsMicrophoneMute() override;
    int32_t SetMicrophoneMute(bool isMute) override;
    int32_t SetMicStateChangeCallback(const int32_t clientId, const sptr<IRemoteObject> &object) override;
private:
    static inline BrokerDelegator<AudioManagerPrivacyProxy> delegator_;
};
}
}
}
#endif // OHOS_AUDIO_MANAGER_PRIVACY_PROXY_H
