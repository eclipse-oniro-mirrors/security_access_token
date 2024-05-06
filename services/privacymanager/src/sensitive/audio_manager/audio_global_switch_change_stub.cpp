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

#include "audio_global_switch_change_stub.h"
#include "accesstoken_log.h"
#include "permission_record_manager.h"
#include "privacy_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    SECURITY_DOMAIN_ACCESSTOKEN, "AudioRoutingManagerListenerStub"};

static constexpr uint32_t UPDATE_CALLBACK_CLIENT = 0;
static constexpr int32_t ON_MIC_STATE_UPDATED = 6; // audio_policy_client.h | ON_MIC_STATE_UPDATED
}
AudioRoutingManagerListenerStub::AudioRoutingManagerListenerStub()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "AudioRoutingManagerListenerStub Instance create");
}

AudioRoutingManagerListenerStub::~AudioRoutingManagerListenerStub()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "AudioRoutingManagerListenerStub Instance destroy");
}

int AudioRoutingManagerListenerStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "AudioRoutingManagerListenerStub: ReadInterfaceToken failed");
        return ERROR_IPC_REQUEST_FAIL;
    }
    switch (code) {
        case UPDATE_CALLBACK_CLIENT: {
            MicStateChangeEvent micStateChangeEvent = {};

            int32_t clientCode = data.ReadInt32();
            if (clientCode != ON_MIC_STATE_UPDATED) {
                ACCESSTOKEN_LOG_INFO(LABEL, "ClientCode %{public}d is not ON_MIC_STATE_UPDATED-6, ignore", clientCode);
                return NO_ERROR;
            }

            micStateChangeEvent.mute = data.ReadBool();
            OnMicStateUpdated(micStateChangeEvent);
            return NO_ERROR;
        }
        default: {
            ACCESSTOKEN_LOG_INFO(LABEL, "default case, need check AudioListenerStub");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
    return NO_ERROR;
}

void AudioRoutingManagerListenerStub::OnMicStateUpdated(const MicStateChangeEvent &micStateChangeEvent)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OnMicMute(%{public}d)", micStateChangeEvent.mute);
    PermissionRecordManager::GetInstance().NotifyMicChange(micStateChangeEvent.mute);
}
}
} // namespace AccessToken
} // namespace OHOS
