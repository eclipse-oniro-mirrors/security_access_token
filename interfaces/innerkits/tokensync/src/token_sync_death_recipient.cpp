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

#include "token_sync_death_recipient.h"

#include "token_sync_manager_client.h"
#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenSyncDeathRecipient"};
}

void TokenSyncDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& onject)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called");

    TokenSyncManagerClient::GetInstance().OnRemoteDiedHandle();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
