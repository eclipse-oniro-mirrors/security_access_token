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

#ifndef OHOS_CAMERA_MANAGER_PRIVACY_PROXY_H
#define OHOS_CAMERA_MANAGER_PRIVACY_PROXY_H

#include <iremote_proxy.h>

namespace OHOS {
namespace Security {
namespace AccessToken {
enum CameraMuteServiceCallbackRequestCode {
    CAMERA_CALLBACK_MUTE_MODE = 0
};

enum CameraServiceRequestCode {
    CAMERA_SERVICE_CREATE_DEVICE = 0,
    CAMERA_SERVICE_SET_CALLBACK,
    CAMERA_SERVICE_SET_MUTE_CALLBACK,
    CAMERA_SERVICE_GET_CAMERAS,
    CAMERA_SERVICE_CREATE_CAPTURE_SESSION,
    CAMERA_SERVICE_CREATE_PHOTO_OUTPUT,
    CAMERA_SERVICE_CREATE_PREVIEW_OUTPUT,
    CAMERA_SERVICE_CREATE_DEFERRED_PREVIEW_OUTPUT,
    CAMERA_SERVICE_CREATE_VIDEO_OUTPUT,
    CAMERA_SERVICE_SET_LISTENER_OBJ,
    CAMERA_SERVICE_CREATE_METADATA_OUTPUT,
    CAMERA_SERVICE_MUTE_CAMERA,
    CAMERA_SERVICE_IS_CAMERA_MUTED,
};

class ICameraMuteServiceCallback : public IRemoteBroker {
public:
    virtual int32_t OnCameraMute(bool muteMode) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ICameraMuteServiceCallback");
};

class ICameraService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ICameraService");

    virtual int32_t SetMuteCallback(const sptr<ICameraMuteServiceCallback>& callback) = 0;
    virtual int32_t MuteCamera(bool muteMode) = 0;
    virtual int32_t IsCameraMuted(bool &muteMode) = 0;
};

class CameraManagerPrivacyProxy : public IRemoteProxy<ICameraService> {
public:
    explicit CameraManagerPrivacyProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<ICameraService>(impl) {};

    virtual ~CameraManagerPrivacyProxy() = default;

    int32_t SetMuteCallback(const sptr<ICameraMuteServiceCallback>& callback) override;
    int32_t MuteCamera(bool muteMode) override;
    int32_t IsCameraMuted(bool &muteMode) override;
private:
    static inline BrokerDelegator<CameraManagerPrivacyProxy> delegator_;
};
}
}
}
#endif // OHOS_CAMERA_MANAGER_PRIVACY_PROXY_H
