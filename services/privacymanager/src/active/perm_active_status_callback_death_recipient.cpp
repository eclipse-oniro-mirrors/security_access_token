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

#include "perm_active_status_callback_death_recipient.h"

#include "access_token.h"
#include "active_status_callback_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

void PermActiveStatusCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Enter");
    if (remote == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remote object is nullptr");
        return;
    }

    sptr<IRemoteObject> object = remote.promote();
    if (object == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Object is nullptr");
        return;
    }
    ActiveStatusCallbackManager::GetInstance().RemoveCallback(object);
    LOGI(ATM_DOMAIN, ATM_TAG, "End");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
