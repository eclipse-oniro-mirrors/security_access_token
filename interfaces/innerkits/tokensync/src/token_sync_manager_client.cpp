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
#include "token_sync_death_recipient.h"
#include "token_sync_load_callback.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenSyncManagerClient"};
} // namespace

TokenSyncManagerClient& TokenSyncManagerClient::GetInstance()
{
    static TokenSyncManagerClient instance;
    return instance;
}

TokenSyncManagerClient::TokenSyncManagerClient()
{}

TokenSyncManagerClient::~TokenSyncManagerClient()
{}

int TokenSyncManagerClient::GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return TOKEN_SYNC_IPC_ERROR;
    }
    return proxy->GetRemoteHapTokenInfo(deviceID, tokenID);
}

int TokenSyncManagerClient::DeleteRemoteHapTokenInfo(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return TOKEN_SYNC_IPC_ERROR;
    }
    return proxy->DeleteRemoteHapTokenInfo(tokenID);
}

int TokenSyncManagerClient::UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "called");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return TOKEN_SYNC_IPC_ERROR;
    }
    return proxy->UpdateRemoteHapTokenInfo(tokenInfo);
}

void TokenSyncManagerClient::LoadTokenSync()
{
    {
        std::unique_lock<std::mutex> lock(tokenSyncMutex_);
        ready_ = false;
    }

    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbilityManager return null");
        return;
    }

    sptr<TokenSyncLoadCallback> ptrTokenSyncLoadCallback = new (std::nothrow) TokenSyncLoadCallback();
    if (ptrTokenSyncLoadCallback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new ptrTokenSyncLoadCallback fail.");
        return;
    }

    int32_t result = sam->LoadSystemAbility(ITokenSyncManager::SA_ID_TOKENSYNC_MANAGER_SERVICE,
        ptrTokenSyncLoadCallback);
    if (result != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "LoadSystemAbility %{public}d failed",
            ITokenSyncManager::SA_ID_TOKENSYNC_MANAGER_SERVICE);
        return;
    }

    {
        std::unique_lock<std::mutex> lock(tokenSyncMutex_);
        // wait_for release lock and block until time out(60s) or match the condition with notice
        auto waitStatus = tokenSyncCon_.wait_for(lock, std::chrono::milliseconds(TOKEN_SYNC_LOAD_SA_TIMEOUT_MS),
            [this]() { return ready_; });
        if (!waitStatus) {
            // time out or loadcallback fail
            ACCESSTOKEN_LOG_WARN(LABEL, "tokensync load sa timeout");
            return;
        }
    }

    if (GetRemoteObject() == nullptr) {
        ACCESSTOKEN_LOG_WARN(LABEL, "remote object is null");
        return;
    }
    sptr<TokenSyncDeathRecipient> ptrTokenSyncDeathRecipient = new (std::nothrow) TokenSyncDeathRecipient();
    if (ptrTokenSyncDeathRecipient == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new TokenSyncDeathRecipient fail.");
        return;
    }
    // add death recipient to reset token_sync
    GetRemoteObject()->AddDeathRecipient(ptrTokenSyncDeathRecipient);
}

void TokenSyncManagerClient::FinishStartSASuccess(const sptr<IRemoteObject>& remoteObject)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "get tokensync sa success.");

    SetRemoteObject(remoteObject);

    // get lock which wait_for release and send a notice so that wait_for can out of block
    {
        std::unique_lock<std::mutex> lock(tokenSyncMutex_);
        ready_ = true;
    }

    tokenSyncCon_.notify_one();
}

void TokenSyncManagerClient::FinishStartSAFailed()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "get tokensync sa failed.");

    SetRemoteObject(nullptr);

    // get lock which wait_for release and send a notice
    {
        std::unique_lock<std::mutex> lock(tokenSyncMutex_);
        ready_ = true;
    }

    tokenSyncCon_.notify_one();
}

void TokenSyncManagerClient::SetRemoteObject(const sptr<IRemoteObject>& remoteObject)
{
    std::unique_lock<std::mutex> lock(remoteMutex_);
    remoteObject_ = remoteObject;
}

sptr<IRemoteObject> TokenSyncManagerClient::GetRemoteObject()
{
    std::unique_lock<std::mutex> lock(remoteMutex_);
    return remoteObject_;
}

void TokenSyncManagerClient::OnRemoteDiedHandle()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Remote service died.");

    SetRemoteObject(nullptr);

    std::unique_lock<std::mutex> lock(tokenSyncMutex_);
    ready_ = false;
}

sptr<ITokenSyncManager> TokenSyncManagerClient::GetProxy()
{
    if (GetRemoteObject() == nullptr) {
        LoadTokenSync();
    }

    auto proxy = iface_cast<ITokenSyncManager>(GetRemoteObject());
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_WARN(LABEL, "iface_cast get null");
        return nullptr;
    }
    return proxy;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
