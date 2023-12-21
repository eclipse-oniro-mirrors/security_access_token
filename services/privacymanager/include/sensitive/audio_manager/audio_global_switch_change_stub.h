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

#ifndef MIC_GLOBAL_SWITCH_CHANGE_STUB_H
#define MIC_GLOBAL_SWITCH_CHANGE_STUB_H

#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct MicStateChangeEvent {
    bool mute;
};

class IAudioPolicyClient : public IRemoteBroker {
public:
    virtual void OnMicStateUpdated(const MicStateChangeEvent &micStateChangeEvent) = 0;

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"IAudioPolicyClient");
};

class AudioRoutingManagerListenerStub : public IRemoteStub<IAudioPolicyClient> {
public:
    AudioRoutingManagerListenerStub();
    virtual ~AudioRoutingManagerListenerStub();

    int OnRemoteRequest(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option) override;
    void OnMicStateUpdated(const MicStateChangeEvent &micStateChangeEvent) override;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // MIC_GLOBAL_SWITCH_CHANGE_STUB_H
