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

#include "perm_active_status_change_callback.h"

#include "access_token.h"
#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "PermissionActiveStatusChangeCallback"
};
PermActiveStatusChangeCallback::PermActiveStatusChangeCallback(
    const std::shared_ptr<PermActiveStatusCustomizedCbk> &customizedCallback)
    : customizedCallback_(customizedCallback)
{}

PermActiveStatusChangeCallback::~PermActiveStatusChangeCallback()
{}

void PermActiveStatusChangeCallback::ActiveStatusChangeCallback(ActiveChangeResponse& result)
{
    if (customizedCallback_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "customizedCallback_ is nullptr");
        return;
    }

    customizedCallback_->ActiveStatusChangeCallback(result);
}

void PermActiveStatusChangeCallback::Stop()
{}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
