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

#include "accesstoken_callback_stubs.h"

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_log.h"
#include "permission_state_change_info_parcel.h"
#include "string_ex.h"

#ifdef TOKEN_SYNC_ENABLE
#include "hap_token_info_for_sync_parcel.h"
#include "ipc_skeleton.h"
#endif // TOKEN_SYNC_ENABLE

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenCallbackStubs"
};
#ifdef TOKEN_SYNC_ENABLE
static const int32_t ACCESSTOKEN_UID = 3020;
#endif // TOKEN_SYNC_ENABLE
}

int32_t PermissionStateChangeCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry, code: 0x%{public}x", code);
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IPermissionStateCallback::GetDescriptor()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return ERROR_IPC_REQUEST_FAIL;
    }

    int32_t msgCode =  static_cast<int32_t>(code);
    if (msgCode == static_cast<int32_t>(AccesstokenStateChangeInterfaceCode::PERMISSION_STATE_CHANGE)) {
        PermStateChangeInfo result;
        sptr<PermissionStateChangeInfoParcel> resultSptr = data.ReadParcelable<PermissionStateChangeInfoParcel>();
        if (resultSptr == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable fail");
            return ERR_READ_PARCEL_FAILED;
        }

        PermStateChangeCallback(resultSptr->changeInfo);
    } else {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return RET_SUCCESS;
}

#ifdef TOKEN_SYNC_ENABLE
int32_t TokenSyncCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Called.");
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != ITokenSyncCallback::GetDescriptor()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Get unexpect descriptor, descriptor = %{public}s",
            Str16ToStr8(descriptor).c_str());
        return ERROR_IPC_REQUEST_FAIL;
    }
    int32_t msgCode = static_cast<int32_t>(code);
    switch (msgCode) {
        case static_cast<int32_t>(TokenSyncCallbackInterfaceCode::GET_REMOTE_HAP_TOKEN_INFO):
            GetRemoteHapTokenInfoInner(data, reply);
            break;
        case static_cast<int32_t>(TokenSyncCallbackInterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO):
            DeleteRemoteHapTokenInfoInner(data, reply);
            break;
        case static_cast<int32_t>(TokenSyncCallbackInterfaceCode::UPDATE_REMOTE_HAP_TOKEN_INFO):
            UpdateRemoteHapTokenInfoInner(data, reply);
            break;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return RET_SUCCESS;
}

void TokenSyncCallbackStub::GetRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission denied, func = %{public}s", __func__);
        reply.WriteInt32(ERR_IDENTITY_CHECK_FAILED);
        return;
    }

    std::string deviceID = data.ReadString();
    AccessTokenID tokenID = data.ReadUint32();

    int result = this->GetRemoteHapTokenInfo(deviceID, tokenID);
    reply.WriteInt32(result);
}

void TokenSyncCallbackStub::DeleteRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission denied, func = %{public}s", __func__);
        reply.WriteInt32(ERR_IDENTITY_CHECK_FAILED);
        return;
    }

    AccessTokenID tokenID = data.ReadUint32();
    int result = this->DeleteRemoteHapTokenInfo(tokenID);
    reply.WriteInt32(result);
}

void TokenSyncCallbackStub::UpdateRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission denied, func = %{public}s", __func__);
        reply.WriteInt32(ERR_IDENTITY_CHECK_FAILED);
        return;
    }
    
    sptr<HapTokenInfoForSyncParcel> tokenInfoParcelPtr = data.ReadParcelable<HapTokenInfoForSyncParcel>();
    int result = RET_FAILED;
    if (tokenInfoParcelPtr != nullptr) {
        result = this->UpdateRemoteHapTokenInfo(tokenInfoParcelPtr->hapTokenInfoForSyncParams);
    }
    reply.WriteInt32(result);
}

bool TokenSyncCallbackStub::IsAccessTokenCalling() const
{
    int callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ACCESSTOKEN_UID;
}
#endif // TOKEN_SYNC_ENABLE
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
