/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef PRIVACY_CAMERA_SERVICE_IPC_INTERFACE_CODE_H
#define PRIVACY_CAMERA_SERVICE_IPC_INTERFACE_CODE_H

namespace OHOS {
namespace Security {
namespace AccessToken {
enum PrivacyCameraMuteServiceInterfaceCode {
    CAMERA_CALLBACK_MUTE_MODE = 0
};

enum PrivacyCameraServiceInterfaceCode {
    CAMERA_SERVICE_SET_MUTE_CALLBACK = 2,
    CAMERA_SERVICE_MUTE_CAMERA = 11,
    CAMERA_SERVICE_IS_CAMERA_MUTED = 12,
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // PRIVACY_CAMERA_SERVICE_IPC_INTERFACE_CODE_H
