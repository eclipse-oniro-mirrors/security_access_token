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

#include "token_sync_load_callback.h"

#include "accesstoken_log.h"
#include "i_token_sync_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenSyncLoadCallBack"};
}

TokenSyncLoadCallback::TokenSyncLoadCallback()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "enter");
}

void TokenSyncLoadCallback::OnLoadSystemAbilitySuccess(int32_t systemAbilityId,
    const sptr<IRemoteObject>& remoteObject)
{
    if (systemAbilityId != ITokenSyncManager::SA_ID_TOKENSYNC_MANAGER_SERVICE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "start aystemabilityId is not TokenSync!");
        return;
    }

    if (remoteObject == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remoteObject is null.");
        return;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "OnLoadSystemAbilitySuccess start systemAbilityId: %{public}d success!",
        systemAbilityId);

    TokenSyncManagerClient::GetInstance().FinishStartSASuccess(remoteObject);
}

void TokenSyncLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    if (systemAbilityId != ITokenSyncManager::SA_ID_TOKENSYNC_MANAGER_SERVICE) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "start aystemabilityId is not TokenSync!");
        return;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "OnLoadSystemAbilityFail systemAbilityId: %{public}d failed.", systemAbilityId);

    TokenSyncManagerClient::GetInstance().FinishStartSAFailed();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
