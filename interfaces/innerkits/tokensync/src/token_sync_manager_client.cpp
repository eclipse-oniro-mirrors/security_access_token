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

#include "accesstoken_common_log.h"
#include "hap_token_info_for_sync_parcel.h"
#include "iservice_registry.h"
#include "token_sync_manager_proxy.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
} // namespace

TokenSyncManagerClient& TokenSyncManagerClient::GetInstance()
{
    static TokenSyncManagerClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            TokenSyncManagerClient* tmp = new TokenSyncManagerClient();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

TokenSyncManagerClient::TokenSyncManagerClient()
{}

TokenSyncManagerClient::~TokenSyncManagerClient()
{
    LOGE(ATM_DOMAIN, ATM_TAG, "~TokenSyncManagerClient");
}

int TokenSyncManagerClient::GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) const
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Called");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return TOKEN_SYNC_IPC_ERROR;
    }
    return proxy->GetRemoteHapTokenInfo(deviceID, tokenID);
}

int TokenSyncManagerClient::DeleteRemoteHapTokenInfo(AccessTokenID tokenID) const
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Called");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return TOKEN_SYNC_IPC_ERROR;
    }
    return proxy->DeleteRemoteHapTokenInfo(tokenID);
}

int TokenSyncManagerClient::UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) const
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Called");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return TOKEN_SYNC_IPC_ERROR;
    }
    return proxy->UpdateRemoteHapTokenInfo(tokenInfo);
}

sptr<ITokenSyncManager> TokenSyncManagerClient::GetProxy() const
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "GetSystemAbilityManager is null");
        return nullptr;
    }

    auto tokensyncSa = sam->GetSystemAbility(ITokenSyncManager::SA_ID_TOKENSYNC_MANAGER_SERVICE);
    if (tokensyncSa == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "GetSystemAbility %{public}d is null",
            ITokenSyncManager::SA_ID_TOKENSYNC_MANAGER_SERVICE);
        return nullptr;
    }

    auto proxy = new TokenSyncManagerProxy(tokensyncSa);
    if (proxy == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Iface_cast get null");
        return nullptr;
    }
    return proxy;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
