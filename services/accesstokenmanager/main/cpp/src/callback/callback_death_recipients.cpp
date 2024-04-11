/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "callback_death_recipients.h"

#include "access_token.h"
#include "callback_manager.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_modify_notifier.h"
#endif // TOKEN_SYNC_ENABLE

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "CallbackDeathRecipients"
};
}

void PermStateCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "enter");
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remote object is nullptr");
        return;
    }

    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "object is nullptr");
        return;
    }
    CallbackManager::GetInstance().RemoveCallback(object);
    ACCESSTOKEN_LOG_INFO(LABEL, "end");
}

#ifdef TOKEN_SYNC_ENABLE
void TokenSyncCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Call OnRemoteDied.");
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Remote object is nullptr.");
        return;
    }
    TokenModifyNotifier::GetInstance().UnRegisterTokenSyncCallback();
    ACCESSTOKEN_LOG_INFO(LABEL, "Call UnRegisterTokenSyncCallback end.");
}
#endif // TOKEN_SYNC_ENABLE
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
