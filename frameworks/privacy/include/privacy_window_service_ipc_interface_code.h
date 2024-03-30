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

#ifndef PRIVACY_WINDOW_SERVICE_IPC_INTERFACE_CODE_H
#define PRIVACY_WINDOW_SERVICE_IPC_INTERFACE_CODE_H

namespace OHOS {
namespace Security {
namespace AccessToken {
enum class PrivacyWindowServiceInterfaceCode {
    TRANS_ID_UPDATE_FOCUS  = 1,
    TRANS_ID_UPDATE_SYSTEM_BAR_PROPS,
    TRANS_ID_UPDATE_WINDOW_STATUS,
    TRANS_ID_UPDATE_WINDOW_VISIBILITY,
    TRANS_ID_UPDATE_WINDOW_DRAWING_STATE,
    TRANS_ID_UPDATE_CAMERA_FLOAT,
    TRANS_ID_UPDATE_WATER_MARK_FLAG,
    TRANS_ID_UPDATE_GESTURE_NAVIGATION_ENABLED,
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // PRIVACY_WINDOW_SERVICE_IPC_INTERFACE_CODE_H
