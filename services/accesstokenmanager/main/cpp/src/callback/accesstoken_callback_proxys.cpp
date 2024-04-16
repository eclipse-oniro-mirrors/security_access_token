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

#include "accesstoken_callback_proxys.h"

#include "access_token.h"
#include "accesstoken_log.h"
#ifdef TOKEN_SYNC_ENABLE
#include "hap_token_info_for_sync_parcel.h"
#endif // TOKEN_SYNC_ENABLE
#include "permission_state_change_info_parcel.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_sync_kit_interface.h"
#endif // TOKEN_SYNC_ENABLE

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenCallbackProxys"
};
}

PermissionStateChangeCallbackProxy::PermissionStateChangeCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IPermissionStateCallback>(impl) {
}

PermissionStateChangeCallbackProxy::~PermissionStateChangeCallbackProxy()
{}

void PermissionStateChangeCallbackProxy::PermStateChangeCallback(PermStateChangeInfo& result)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPermissionStateCallback::GetDescriptor());

    PermissionStateChangeInfoParcel resultParcel;
    resultParcel.changeInfo = result;
    if (!data.WriteParcelable(&resultParcel)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteParcelable(result)");
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remote service null.");
        return;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(AccesstokenStateChangeInterfaceCode::PERMISSION_STATE_CHANGE), data, reply, option);
    if (requestResult != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "send request fail, result: %{public}d", requestResult);
        return;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "SendRequest success");
}

#ifdef TOKEN_SYNC_ENABLE
TokenSyncCallbackProxy::TokenSyncCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<ITokenSyncCallback>(impl) {
}

TokenSyncCallbackProxy::~TokenSyncCallbackProxy()
{}

int32_t TokenSyncCallbackProxy::GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID)
{
    MessageParcel data;
    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());

    if (!data.WriteString(deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write deviceID.");
        return TOKEN_SYNC_PARAMS_INVALID;
    }
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID.");
        return TOKEN_SYNC_PARAMS_INVALID;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Remote service null.");
        return TOKEN_SYNC_IPC_ERROR;
    }
    int32_t requestResult = remote->SendRequest(static_cast<uint32_t>(
        TokenSyncCallbackInterfaceCode::GET_REMOTE_HAP_TOKEN_INFO), data, reply, option);
    if (requestResult != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Send request fail, result = %{public}d.", requestResult);
        return TOKEN_SYNC_IPC_ERROR;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "Get result from callback, data = %{public}d.", result);
    return result;
}

int32_t TokenSyncCallbackProxy::DeleteRemoteHapTokenInfo(AccessTokenID tokenID)
{
    MessageParcel data;
    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID.");
        return TOKEN_SYNC_PARAMS_INVALID;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Remote service null.");
        return TOKEN_SYNC_IPC_ERROR;
    }
    int32_t requestResult = remote->SendRequest(static_cast<uint32_t>(
        TokenSyncCallbackInterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO), data, reply, option);
    if (requestResult != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Send request fail, result: %{public}d", requestResult);
        return TOKEN_SYNC_IPC_ERROR;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "Get result from callback, data = %{public}d", result);
    return result;
}

int32_t TokenSyncCallbackProxy::UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo)
{
    MessageParcel data;
    data.WriteInterfaceToken(ITokenSyncCallback::GetDescriptor());

    HapTokenInfoForSyncParcel tokenInfoParcel;
    tokenInfoParcel.hapTokenInfoForSyncParams = tokenInfo;

    if (!data.WriteParcelable(&tokenInfoParcel)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenInfo.");
        return TOKEN_SYNC_PARAMS_INVALID;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Remote service null.");
        return TOKEN_SYNC_IPC_ERROR;
    }
    int32_t requestResult = remote->SendRequest(static_cast<uint32_t>(
        TokenSyncCallbackInterfaceCode::UPDATE_REMOTE_HAP_TOKEN_INFO), data, reply, option);
    if (requestResult != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Send request fail, result = %{public}d", requestResult);
        return TOKEN_SYNC_IPC_ERROR;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "Get result from callback, data = %{public}d", result);
    return result;
}
#endif // TOKEN_SYNC_ENABLE
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
