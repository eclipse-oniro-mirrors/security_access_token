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

#ifndef PRIVACY_CAMERA_SERVICE_CALLBACK_STUB_H
#define PRIVACY_CAMERA_SERVICE_CALLBACK_STUB_H

#include "iremote_stub.h"
#include "nocopyable.h"
#include "camera_manager_privacy_proxy.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class CameraServiceCallbackStub : public IRemoteStub<ICameraMuteServiceCallback> {
public:
    CameraServiceCallbackStub();
    virtual ~CameraServiceCallbackStub();

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    int32_t OnCameraMute(bool muteMode) override;
};
}
} // namespace AccessToken
} // namespace OHOS
#endif // PRIVACY_CAMERA_SERVICE_CALLBACK_STUB_H
