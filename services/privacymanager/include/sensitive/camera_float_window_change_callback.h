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

#ifndef CAMERA_FLOAT_WINDOW_CALLBACK_H
#define CAMERA_FLOAT_WINDOW_CALLBACK_H

#include "accesstoken_kit.h"
#include "window_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef void (*OnCameraFloatWindowChangeCallback)(AccessTokenID tokenId, bool isShowing);
class CameraFloatWindowChangeCallback : public Rosen::ICameraFloatWindowChangedListener {
public:
    void OnCameraFloatWindowChange(AccessTokenID accessTokenId, bool isShowing) override;
    
    void SetCallback(OnCameraFloatWindowChangeCallback callback);
    OnCameraFloatWindowChangeCallback GetCallback() const;

private:
    OnCameraFloatWindowChangeCallback callback_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // CAMERA_FLOAT_WINDOW_CALLBACK_H
