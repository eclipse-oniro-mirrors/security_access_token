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

#ifndef AUDIO_MANAGER_PRIVACY_CLIENT_H
#define AUDIO_MANAGER_PRIVACY_CLIENT_H

#include <mutex>
#include <string>

#include "audio_global_switch_change_stub.h"
#include "audio_manager_privacy_death_recipient.h"
#include "audio_manager_privacy_proxy.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AudioManagerPrivacyClient final {
public:
    static AudioManagerPrivacyClient& GetInstance();
    virtual ~AudioManagerPrivacyClient();

    int32_t SetMicStateChangeCallback(const sptr<AudioRoutingManagerListenerStub>& callback);
    int32_t SetMicrophoneMute(bool isMute);
    bool IsMicrophoneMute();
    void OnRemoteDiedHandle();

private:
    AudioManagerPrivacyClient();
    DISALLOW_COPY_AND_MOVE(AudioManagerPrivacyClient);

    void InitProxy();
    sptr<IAudioPolicy> GetProxy();

    sptr<AudioMgrDeathRecipient> serviceDeathObserver_ = nullptr;
    std::mutex proxyMutex_;
    sptr<IAudioPolicy> proxy_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // AUDIO_MANAGER_PRIVACY_CLIENT_H

