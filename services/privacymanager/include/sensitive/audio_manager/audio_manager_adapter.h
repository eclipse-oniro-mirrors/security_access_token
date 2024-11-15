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

#ifndef ACCESSTOKEN_AUDIO_MANAGER_ADAPTER_H
#define ACCESSTOKEN_AUDIO_MANAGER_ADAPTER_H

#include <mutex>
#include <string>

#include <iremote_proxy.h>
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AudioManagerAdapter final {
private:
    AudioManagerAdapter();
    virtual ~AudioManagerAdapter();
    DISALLOW_COPY_AND_MOVE(AudioManagerAdapter);

public:
    static AudioManagerAdapter& GetInstance();

    bool GetPersistentMicMuteState();

#ifdef AUDIO_FRAMEWORK_ENABLE
private:
    void InitProxy();

    class AudioManagerDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        AudioManagerDeathRecipient() = default;
        ~AudioManagerDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
    private:
        DISALLOW_COPY_AND_MOVE(AudioManagerDeathRecipient);
    };

    sptr<IRemoteObject> GetProxy();
    void ReleaseProxy(const wptr<IRemoteObject>& remote);

    std::mutex proxyMutex_;
    sptr<IRemoteObject> proxy_ = nullptr;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
#endif
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_AUDIO_MANAGER_ADAPTER_H
