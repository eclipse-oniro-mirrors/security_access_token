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

#include "token_sync_manager_stub.h"

#include "accesstoken_log.h"
#include "access_token_error.h"
#include "hap_token_info_for_sync_parcel.h"
#include "ipc_skeleton.h"
#include "native_token_info_for_sync_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenSyncManagerStub"};
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    static const int32_t ROOT_UID = 0;
#endif
}

int32_t TokenSyncManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, code: %{public}d", __func__, code);
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != ITokenSyncManager::GetDescriptor()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return ERROR_IPC_REQUEST_FAIL;
    }
    switch (code) {
        case static_cast<uint32_t>(TokenSyncInterfaceCode::GET_REMOTE_HAP_TOKEN_INFO):
            GetRemoteHapTokenInfoInner(data, reply);
            break;
        case static_cast<uint32_t>(TokenSyncInterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO):
            DeleteRemoteHapTokenInfoInner(data, reply);
            break;
        case static_cast<uint32_t>(TokenSyncInterfaceCode::UPDATE_REMOTE_HAP_TOKEN_INFO):
            UpdateRemoteHapTokenInfoInner(data, reply);
            break;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return NO_ERROR;
}

bool TokenSyncManagerStub::IsNativeProcessCalling() const
{
    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    uint32_t type = (reinterpret_cast<AccessTokenIDInner *>(&tokenCaller))->type;
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Calling type: %{public}d", type);
    return type == TOKEN_NATIVE;
}

bool TokenSyncManagerStub::IsRootCalling() const
{
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    int callingUid = IPCSkeleton::GetCallingUid();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Calling uid: %{public}d", callingUid);
    return callingUid == ROOT_UID;
#else
    return false;
#endif
}

void TokenSyncManagerStub::GetRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsRootCalling() && !IsNativeProcessCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(ERR_IDENTITY_CHECK_FAILED);
        return;
    }

    std::string deviceID = data.ReadString();
    AccessTokenID tokenID = data.ReadUint32();

    HapTokenInfoForSync tokenInfo;
    int result = this->GetRemoteHapTokenInfo(deviceID, tokenID);
    reply.WriteInt32(result);
}

void TokenSyncManagerStub::DeleteRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsRootCalling() && !IsNativeProcessCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(ERR_IDENTITY_CHECK_FAILED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    int result = this->DeleteRemoteHapTokenInfo(tokenID);
    reply.WriteInt32(result);
}

void TokenSyncManagerStub::UpdateRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsRootCalling() && !IsNativeProcessCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
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
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
