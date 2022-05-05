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
#include "hap_token_info_for_sync_parcel.h"
#include "ipc_skeleton.h"
#include "native_token_info_for_sync_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenSyncManagerStub"};
}

int32_t TokenSyncManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, code: %{public}d", __func__, code);
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != ITokenSyncManager::GetDescriptor()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return -1;
    }
    switch (code) {
        case static_cast<uint32_t>(ITokenSyncManager::InterfaceCode::GET_REMOTE_HAP_TOKEN_INFO):
            GetRemoteHapTokenInfoInner(data, reply);
            break;
        case static_cast<uint32_t>(ITokenSyncManager::InterfaceCode::DELETE_REMOTE_HAP_TOKEN_INFO):
            DeleteRemoteHapTokenInfoInner(data, reply);
            break;
        case static_cast<uint32_t>(ITokenSyncManager::InterfaceCode::UPDATE_REMOTE_HAP_TOKEN_INFO):
            UpdateRemoteHapTokenInfoInner(data, reply);
            break;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return NO_ERROR;
}

void TokenSyncManagerStub::GetRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    std::string deviceID = data.ReadString();
    AccessTokenID tokenID = data.ReadUint32();

    HapTokenInfoForSync tokenInfo;
    int result = this->GetRemoteHapTokenInfo(deviceID, tokenID);
    reply.WriteInt32(result);
}

void TokenSyncManagerStub::DeleteRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    std::string deviceID = data.ReadString();
    AccessTokenID tokenID = data.ReadUint32();
    int result = this->DeleteRemoteHapTokenInfo(tokenID);
    reply.WriteInt32(result);
}

void TokenSyncManagerStub::UpdateRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
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
