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

#include "mic_global_switch_change_callback.h"
#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "GlobalSwitchChangeCallback"
};
}

void MicGlobalSwitchChangeCallback::OnMicStateUpdated(const AudioStandard::MicStateChangeEvent &micStateChangeEvent)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "OnChange(MicGlobalStatus=%{public}d)", micStateChangeEvent.mute);

    if (callback_ != nullptr) {
        callback_(!micStateChangeEvent.mute);
    }
}

void MicGlobalSwitchChangeCallback::SetCallback(OnMicGlobalSwitchChangeCallback callback)
{
    callback_ = callback;
}

OnMicGlobalSwitchChangeCallback MicGlobalSwitchChangeCallback::GetCallback() const
{
    return callback_;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
