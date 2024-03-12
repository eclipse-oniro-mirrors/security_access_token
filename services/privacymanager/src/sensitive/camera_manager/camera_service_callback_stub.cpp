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

#include "camera_service_callback_stub.h"
#include "accesstoken_log.h"
#include "permission_record_manager.h"
#include "privacy_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    SECURITY_DOMAIN_ACCESSTOKEN, "CameraServiceCallbackStub"};
}
CameraServiceCallbackStub::CameraServiceCallbackStub()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "CameraServiceCallbackStub Instance create");
}

CameraServiceCallbackStub::~CameraServiceCallbackStub()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "CameraServiceCallbackStub Instance destroy");
}

int CameraServiceCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "CameraServiceCallbackStub: ReadInterfaceToken failed");
        return ERROR_IPC_REQUEST_FAIL;
    }
    PrivacyCameraMuteServiceInterfaceCode msgId = static_cast<PrivacyCameraMuteServiceInterfaceCode>(code);
    switch (msgId) {
        case CAMERA_CALLBACK_MUTE_MODE: {
            bool mute = data.ReadBool();
            OnCameraMute(mute);
            return 0;
        }
        default: {
            ACCESSTOKEN_LOG_INFO(LABEL, "default case, need check AudioListenerStub");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

int32_t CameraServiceCallbackStub::OnCameraMute(bool muteMode)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OnCameraMute(%{public}d)", muteMode);
    PermissionRecordManager::GetInstance().NotifyCameraChange(muteMode);
    return 0;
}
}
} // namespace AccessToken
} // namespace OHOS
