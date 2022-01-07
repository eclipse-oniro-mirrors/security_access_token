/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "accesstoken_manager_stub.h"

#include "accesstoken_log.h"

#include "ipc_skeleton.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenManagerStub"};
}

int32_t AccessTokenManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, code: %{public}d", __func__, code);
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IAccessTokenManager::GetDescriptor()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return -1;
    }
    auto itFunc = requestFuncMap_.find(code);
    if (itFunc != requestFuncMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            (this->*requestFunc)(data, reply);
        } else {
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
    return NO_ERROR;
}

void AccessTokenManagerStub::DeleteTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    int result = this->DeleteToken(tokenID);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::VerifyAccessTokenInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int result = this->VerifyAccessToken(tokenID, permissionName);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetDefPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    std::string permissionName = data.ReadString();
    PermissionDefParcel permissionDefParcel;
    int result = this->GetDefPermission(permissionName, permissionDefParcel);
    reply.WriteParcelable(&permissionDefParcel);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetDefPermissionsInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    std::vector<PermissionDefParcel> permList;

    int result = this->GetDefPermissions(tokenID, permList);
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permList size: %{public}d", __func__, (int) permList.size());
    reply.WriteInt32(permList.size());
    for (auto permDef : permList) {
        reply.WriteParcelable(&permDef);
    }
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetReqPermissionsInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    int isSystemGrant = data.ReadInt32();
    std::vector<PermissionStateFullParcel> permList;

    int result = this->GetReqPermissions(tokenID, permList, isSystemGrant);
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permList size: %{public}d", __func__, (int) permList.size());
    reply.WriteInt32(permList.size());
    for (auto permDef : permList) {
        reply.WriteParcelable(&permDef);
    }
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetPermissionFlagInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int result = this->GetPermissionFlag(tokenID, permissionName);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GrantPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int flag = data.ReadInt32();
    int result = this->GrantPermission(tokenID, permissionName, flag);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::RevokePermissionInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int flag = data.ReadInt32();
    int result = this->RevokePermission(tokenID, permissionName, flag);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::ClearUserGrantedPermissionStateInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    int result = this->ClearUserGrantedPermissionState(tokenID);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::AllocHapTokenInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenIDEx res = {0};
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }

    sptr<HapInfoParcel> hapInfoParcel = data.ReadParcelable<HapInfoParcel>();
    sptr<HapPolicyParcel> hapPolicyParcel = data.ReadParcelable<HapPolicyParcel>();

    res = this->AllocHapToken(*hapInfoParcel, *hapPolicyParcel);
    reply.WriteUint64(res.tokenIDEx);
}

void AccessTokenManagerStub::GetTokenTypeInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    int result = this->GetTokenType(tokenID);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::CheckNativeDCapInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    std::string dCap = data.ReadString();
    int result = this->CheckNativeDCap(tokenID, dCap);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetHapTokenIDInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    int userID = data.ReadInt32();
    std::string bundleName = data.ReadString();
    int instIndex = data.ReadInt32();
    AccessTokenID result = this->GetHapTokenID(userID, bundleName, instIndex);
    reply.WriteUint32(result);
}

void AccessTokenManagerStub::AllocLocalTokenIDInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    std::string remoteDeviceID = data.ReadString();
    AccessTokenID remoteTokenID = data.ReadUint32();
    AccessTokenID result = this->AllocLocalTokenID(remoteDeviceID, remoteTokenID);
    reply.WriteUint32(result);
}

void AccessTokenManagerStub::UpdateHapTokenInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    std::string appIDDesc = data.ReadString();
    sptr<HapPolicyParcel> policyParcel = data.ReadParcelable<HapPolicyParcel>();

    int32_t result = this->UpdateHapToken(tokenID, appIDDesc, *policyParcel);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    HapTokenInfoParcel hapTokenInfoParcel;
    AccessTokenID tokenID = data.ReadUint32();
    int result = this->GetHapTokenInfo(tokenID, hapTokenInfoParcel);
    reply.WriteParcelable(&hapTokenInfoParcel);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetNativeTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    NativeTokenInfoParcel nativeTokenInfoParcel;
    int result = this->GetNativeTokenInfo(tokenID, nativeTokenInfoParcel);
    reply.WriteParcelable(&nativeTokenInfoParcel);
    reply.WriteInt32(result);
}

bool AccessTokenManagerStub::IsAuthorizedCalling() const
{
    int callingUid = IPCSkeleton::GetCallingUid();
    ACCESSTOKEN_LOG_INFO(LABEL, "Calling uid: %{public}d", callingUid);
    return callingUid == SYSTEM_UID || callingUid == ROOT_UID;
}

AccessTokenManagerStub::AccessTokenManagerStub()
{
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::VERIFY_ACCESSTOKEN)] =
        &AccessTokenManagerStub::VerifyAccessTokenInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GET_DEF_PERMISSION)] =
        &AccessTokenManagerStub::GetDefPermissionInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GET_DEF_PERMISSIONS)] =
        &AccessTokenManagerStub::GetDefPermissionsInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GET_REQ_PERMISSIONS)] =
        &AccessTokenManagerStub::GetReqPermissionsInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GET_PERMISSION_FLAG)] =
        &AccessTokenManagerStub::GetPermissionFlagInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GRANT_PERMISSION)] =
        &AccessTokenManagerStub::GrantPermissionInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::REVOKE_PERMISSION)] =
        &AccessTokenManagerStub::RevokePermissionInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::CLEAR_USER_GRANT_PERMISSION)] =
        &AccessTokenManagerStub::ClearUserGrantedPermissionStateInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::ALLOC_TOKEN_HAP)] =
        &AccessTokenManagerStub::AllocHapTokenInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::TOKEN_DELETE)] =
        &AccessTokenManagerStub::DeleteTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GET_TOKEN_TYPE)] =
        &AccessTokenManagerStub::GetTokenTypeInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::CHECK_NATIVE_DCAP)] =
        &AccessTokenManagerStub::CheckNativeDCapInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GET_HAP_TOKEN_ID)] =
        &AccessTokenManagerStub::GetHapTokenIDInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::ALLOC_LOCAL_TOKEN_ID)] =
        &AccessTokenManagerStub::AllocLocalTokenIDInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GET_NATIVE_TOKENINFO)] =
        &AccessTokenManagerStub::GetNativeTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GET_HAP_TOKENINFO)] =
        &AccessTokenManagerStub::GetHapTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::UPDATE_HAP_TOKEN)] =
        &AccessTokenManagerStub::UpdateHapTokenInner;
}

AccessTokenManagerStub::~AccessTokenManagerStub()
{
    requestFuncMap_.clear();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
