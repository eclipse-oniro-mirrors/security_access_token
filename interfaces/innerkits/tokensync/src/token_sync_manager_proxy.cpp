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

#include "token_sync_manager_proxy.h"

#include "accesstoken_common_log.h"
#include "parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

TokenSyncManagerProxy::TokenSyncManagerProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<ITokenSyncManager>(impl)
{}

TokenSyncManagerProxy::~TokenSyncManagerProxy()
{}

int TokenSyncManagerProxy::GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID)
{
    MessageParcel data;
    data.WriteInterfaceToken(ITokenSyncManager::GetDescriptor());
    if (!data.WriteString(deviceID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write deviceID");
        return TOKEN_SYNC_PARAMS_INVALID;
    }
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write tokenID");
        return TOKEN_SYNC_PARAMS_INVALID;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remote service null.");
        return TOKEN_SYNC_IPC_ERROR;
    }
    int32_t requestResult = remote->SendRequest(static_cast<uint32_t>(
        TokenSyncInterfaceCode::GET_REMOTE_HAP_TOKEN_INFO), data, reply, option);
    if (requestResult != NO_ERROR) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Send request fail, result: %{public}d", requestResult);
        return TOKEN_SYNC_IPC_ERROR;
    }

    int32_t result = reply.ReadInt32();
    LOGD(ATM_DOMAIN, ATM_TAG, "Get result from server data = %{public}d", result);
    return result;
}

int TokenSyncManagerProxy::DeleteRemoteHapTokenInfo(AccessTokenID tokenID)
{
    MessageParcel data;
    data.WriteInterfaceToken(ITokenSyncManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write tokenID");
        return TOKEN_SYNC_PARAMS_INVALID;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remote service null.");
        return TOKEN_SYNC_IPC_ERROR;
    }
    int32_t requestResult = remote->SendRequest(static_cast<uint32_t>(
        TokenSyncInterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO), data, reply, option);
    if (requestResult != NO_ERROR) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Send request fail, result: %{public}d", requestResult);
        return TOKEN_SYNC_IPC_ERROR;
    }

    int32_t result = reply.ReadInt32();
    LOGD(ATM_DOMAIN, ATM_TAG, "Get result from server data = %{public}d", result);
    return result;
}

int TokenSyncManagerProxy::UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo)
{
    MessageParcel data;
    data.WriteInterfaceToken(ITokenSyncManager::GetDescriptor());

    HapTokenInfoForSyncParcel tokenInfoParcel;
    tokenInfoParcel.hapTokenInfoForSyncParams = tokenInfo;

    if (!data.WriteParcelable(&tokenInfoParcel)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write tokenInfo");
        return TOKEN_SYNC_PARAMS_INVALID;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remote service null.");
        return TOKEN_SYNC_IPC_ERROR;
    }
    int32_t requestResult = remote->SendRequest(static_cast<uint32_t>(
        TokenSyncInterfaceCode::UPDATE_REMOTE_HAP_TOKEN_INFO), data, reply, option);
    if (requestResult != NO_ERROR) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Send request fail, result: %{public}d", requestResult);
        return TOKEN_SYNC_IPC_ERROR;
    }

    int32_t result = reply.ReadInt32();
    LOGD(ATM_DOMAIN, ATM_TAG, "Get result from server data = %{public}d", result);
    return result;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
