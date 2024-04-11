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

#include "accesstoken_callbacks.h"

#include "access_token.h"
#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenCallbacks"
};

PermissionStateChangeCallback::PermissionStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& customizedCallback)
    : customizedCallback_(customizedCallback)
{}

PermissionStateChangeCallback::~PermissionStateChangeCallback()
{}

void PermissionStateChangeCallback::PermStateChangeCallback(PermStateChangeInfo& result)
{
    if (customizedCallback_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "customizedCallback_ is nullptr");
        return;
    }

    customizedCallback_->PermStateChangeCallback(result);
}

void PermissionStateChangeCallback::Stop()
{}

#ifdef TOKEN_SYNC_ENABLE
TokenSyncCallback::TokenSyncCallback(const std::shared_ptr<TokenSyncKitInterface>& tokenSyncCallback)
    : tokenSyncCallback_(tokenSyncCallback)
{}

TokenSyncCallback::~TokenSyncCallback()
{}

int32_t TokenSyncCallback::GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID)
{
    if (tokenSyncCallback_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Get nullptr, name = tokenSyncCallback_.");
        return TOKEN_SYNC_PARAMS_INVALID;
    }
    return tokenSyncCallback_->GetRemoteHapTokenInfo(deviceID, tokenID);
}

int32_t TokenSyncCallback::DeleteRemoteHapTokenInfo(AccessTokenID tokenID)
{
    if (tokenSyncCallback_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Get nullptr, name = tokenSyncCallback_.");
        return TOKEN_SYNC_PARAMS_INVALID;
    }
    return tokenSyncCallback_->DeleteRemoteHapTokenInfo(tokenID);
}

int32_t TokenSyncCallback::UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo)
{
    if (tokenSyncCallback_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Get nullptr, name = tokenSyncCallback_.");
        return TOKEN_SYNC_PARAMS_INVALID;
    }
    return tokenSyncCallback_->UpdateRemoteHapTokenInfo(tokenInfo);
}
#endif // TOKEN_SYNC_ENABLE
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
