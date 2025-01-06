/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "proxy_death_recipient.h"
#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "ProxyDeathRecipient"};
}

ProxyDeathRecipient::ProxyDeathRecipient(ProxyDeathHandler* handler) : handler_(handler)
{
}

void ProxyDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Proxy died.");
    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object is nullptr");
        return;
    }
    if (handler_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Handler is nullptr");
        return;
    }
    handler_->HandleRemoteDied(object);
}
}  // namespace AccessToken
} // namespace Security
}  // namespace OHOS

