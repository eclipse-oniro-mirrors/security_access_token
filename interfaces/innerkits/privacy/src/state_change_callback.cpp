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

#include "accesstoken_log.h"
#include "state_change_callback.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "StateChangeCallback"
};
StateChangeCallback::StateChangeCallback(
    const std::shared_ptr<StateCustomizedCbk> &customizedCallback)
    : customizedCallback_(customizedCallback)
{}

StateChangeCallback::~StateChangeCallback()
{}

void StateChangeCallback::StateChangeNotify(AccessTokenID tokenId, bool isShowing)
{
    if (customizedCallback_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "customizedCallback_ is nullptr");
        return;
    }

    customizedCallback_->StateChangeNotify(tokenId, isShowing);
}

void StateChangeCallback::Stop()
{}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
