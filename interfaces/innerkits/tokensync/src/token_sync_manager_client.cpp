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

#include "token_sync_manager_client.h"

#include "accesstoken_log.h"
#include "hap_token_info_for_sync_parcel.h"
#include "native_token_info_for_sync_parcel.h"
#include "iservice_registry.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenSyncManagerClient"};
std::recursive_mutex g_instanceMutex;
} // namespace

TokenSyncManagerClient& TokenSyncManagerClient::GetInstance()
{
    static TokenSyncManagerClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new TokenSyncManagerClient();
        }
    }
    return *instance;
}

TokenSyncManagerClient::TokenSyncManagerClient()
{}

TokenSyncManagerClient::~TokenSyncManagerClient()
{
    ACCESSTOKEN_LOG_ERROR(LABEL, "~TokenSyncManagerClient");
}

int TokenSyncManagerClient::GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) const
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return TOKEN_SYNC_IPC_ERROR;
    }
    return proxy->GetRemoteHapTokenInfo(deviceID, tokenID);
}

int TokenSyncManagerClient::DeleteRemoteHapTokenInfo(AccessTokenID tokenID) const
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return TOKEN_SYNC_IPC_ERROR;
    }
    return proxy->DeleteRemoteHapTokenInfo(tokenID);
}

int TokenSyncManagerClient::UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) const
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return TOKEN_SYNC_IPC_ERROR;
    }
    return proxy->UpdateRemoteHapTokenInfo(tokenInfo);
}

sptr<ITokenSyncManager> TokenSyncManagerClient::GetProxy() const
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        ACCESSTOKEN_LOG_WARN(LABEL, "GetSystemAbilityManager is null");
        return nullptr;
    }

    auto tokensyncSa = sam->GetSystemAbility(ITokenSyncManager::SA_ID_TOKENSYNC_MANAGER_SERVICE);
    if (tokensyncSa == nullptr) {
        ACCESSTOKEN_LOG_WARN(LABEL, "GetSystemAbility %{public}d is null",
            ITokenSyncManager::SA_ID_TOKENSYNC_MANAGER_SERVICE);
        return nullptr;
    }

    auto proxy = iface_cast<ITokenSyncManager>(tokensyncSa);
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_WARN(LABEL, "iface_cast get null");
        return nullptr;
    }
    return proxy;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
