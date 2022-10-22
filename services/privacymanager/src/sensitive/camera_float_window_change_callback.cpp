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

#include "camera_float_window_change_callback.h"
#include "accesstoken_log.h"
#include "sensitive_resource_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "CameraFloatWindowChangeCallback"
};
}

void CameraFloatWindowChangeCallback::OnCameraFloatWindowChange(AccessTokenID accessTokenId, bool isShowing)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OnChange(tokenId=%{public}d, isShow=%{public}d)", accessTokenId, isShowing);

    if (callback_ != nullptr) {
        callback_(accessTokenId, isShowing);
    }
}

void CameraFloatWindowChangeCallback::SetCallback(OnCameraFloatWindowChangeCallback callback)
{
    callback_ = callback;
}

OnCameraFloatWindowChangeCallback CameraFloatWindowChangeCallback::GetCallback() const
{
    return callback_;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
