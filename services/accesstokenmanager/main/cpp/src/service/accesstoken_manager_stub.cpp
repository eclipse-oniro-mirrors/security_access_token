/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
        ACCESSTOKEN_LOG_INFO(LABEL, "permission denied");
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

void AccessTokenManagerStub::VerifyNativeTokenInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int result = this->VerifyNativeToken(tokenID, permissionName);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetDefPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    std::string permissionName = data.ReadString();
    PermissionDefParcel permissionDefParcel;
    int result = this->GetDefPermission(permissionName, permissionDefParcel);
    reply.WriteParcelable(&permissionDefParcel);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetDefPermissionsInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID = data.ReadUint32();
    std::vector<PermissionDefParcel> permList;

    int result = this->GetDefPermissions(tokenID, permList);
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permList size: %{public}d", __func__, (int) permList.size());
    reply.WriteInt32((int32_t)permList.size());
    for (auto permDef : permList) {
        reply.WriteParcelable(&permDef);
    }
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetReqPermissionsInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID = data.ReadUint32();
    int isSystemGrant = data.ReadInt32();
    std::vector<PermissionStateFullParcel> permList;

    int result = this->GetReqPermissions(tokenID, permList, isSystemGrant);
    ACCESSTOKEN_LOG_INFO(LABEL, "permList size: %{public}d", (int) permList.size());
    reply.WriteInt32((int32_t)permList.size());
    for (auto permDef : permList) {
        reply.WriteParcelable(&permDef);
    }
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetSelfPermissionsStateInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<PermissionListStateParcel> permList;
    uint32_t size = data.ReadUint32();
    ACCESSTOKEN_LOG_INFO(LABEL, "permList size read from client data is %{public}d.", size);
    for (uint32_t i = 0; i < size; i++) {
        sptr<PermissionListStateParcel> permissionParcel = data.ReadParcelable<PermissionListStateParcel>();
        if (permissionParcel != nullptr) {
            permList.emplace_back(*permissionParcel);
        }
    }

    PermissionOper result = this->GetSelfPermissionsState(permList);

    reply.WriteInt32(result);

    reply.WriteUint32(permList.size());
    for (auto perm : permList) {
        reply.WriteParcelable(&perm);
    }
}

void AccessTokenManagerStub::GetPermissionFlagInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    ACCESSTOKEN_LOG_INFO(LABEL, "callingTokenID: %{public}d", callingTokenID);
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    if (!IsAuthorizedCalling() &&
        VerifyAccessToken(callingTokenID, "ohos.permission.GRANT_SENSITIVE_PERMISSIONS") == PERMISSION_DENIED &&
        VerifyAccessToken(callingTokenID, "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS") == PERMISSION_DENIED &&
        VerifyAccessToken(callingTokenID, "ohos.permission.GET_SENSITIVE_PERMISSIONS") == PERMISSION_DENIED) {
        ACCESSTOKEN_LOG_INFO(LABEL, "permission denied");
        reply.WriteInt32(DEFAULT_PERMISSION_FLAGS);
        return;
    }
    int result = this->GetPermissionFlag(tokenID, permissionName);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GrantPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    ACCESSTOKEN_LOG_INFO(LABEL, "callingTokenID: %{public}d", callingTokenID);
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int flag = data.ReadInt32();
    if (!IsAuthorizedCalling() &&
        VerifyAccessToken(callingTokenID, "ohos.permission.GRANT_SENSITIVE_PERMISSIONS") == PERMISSION_DENIED) {
        ACCESSTOKEN_LOG_INFO(LABEL, "permission denied");
        reply.WriteInt32(RET_FAILED);
        return;
    }
    int result = this->GrantPermission(tokenID, permissionName, flag);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::RevokePermissionInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    ACCESSTOKEN_LOG_INFO(LABEL, "callingTokenID: %{public}d", callingTokenID);
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int flag = data.ReadInt32();
    if (!IsAuthorizedCalling() &&
        VerifyAccessToken(callingTokenID, "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS") == PERMISSION_DENIED) {
        ACCESSTOKEN_LOG_INFO(LABEL, "permission denied");
        reply.WriteInt32(RET_FAILED);
        return;
    }
    int result = this->RevokePermission(tokenID, permissionName, flag);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::ClearUserGrantedPermissionStateInner(MessageParcel& data, MessageParcel& reply)
{
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

void AccessTokenManagerStub::GetHapTokenInfoFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    HapTokenInfoForSyncParcel hapTokenParcel;

    int result = this->GetHapTokenInfoFromRemote(tokenID, hapTokenParcel);
    reply.WriteParcelable(&hapTokenParcel);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetAllNativeTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    std::vector<NativeTokenInfoParcel> nativeTokenInfosRes;
    int result = this->GetAllNativeTokenInfo(nativeTokenInfosRes);
    reply.WriteUint32(nativeTokenInfosRes.size());
    for (auto native : nativeTokenInfosRes) {
        reply.WriteParcelable(&native);
    }
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::SetRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    std::string deviceID = data.ReadString();
    sptr<HapTokenInfoForSyncParcel> hapTokenParcel = data.ReadParcelable<HapTokenInfoForSyncParcel>();
    int result = this->SetRemoteHapTokenInfo(deviceID, *hapTokenParcel);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::SetRemoteNativeTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    std::string deviceID = data.ReadString();

    std::vector<NativeTokenInfoParcel> nativeTokenInfoParcel;
    uint32_t size = data.ReadUint32();

    for (uint32_t i = 0; i < size; i++) {
        sptr<NativeTokenInfoParcel> nativeParcel = data.ReadParcelable<NativeTokenInfoParcel>();
        nativeTokenInfoParcel.emplace_back(*nativeParcel);
    }

    int result = this->SetRemoteNativeTokenInfo(deviceID, nativeTokenInfoParcel);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::DeleteRemoteTokenInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    std::string deviceID = data.ReadString();
    AccessTokenID tokenID = data.ReadUint32();

    int result = this->DeleteRemoteToken(deviceID, tokenID);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetRemoteNativeTokenIDInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    std::string deviceID = data.ReadString();
    AccessTokenID tokenID = data.ReadUint32();

    AccessTokenID result = this->GetRemoteNativeTokenID(deviceID, tokenID);
    reply.WriteUint32(result);
}

void AccessTokenManagerStub::DeleteRemoteDeviceTokensInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    std::string deviceID = data.ReadString();

    int result = this->DeleteRemoteDeviceTokens(deviceID);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::DumpTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAuthorizedCalling()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permission denied", __func__);
        return;
    }
    std::string dumpInfo = "";
    this->DumpTokenInfo(dumpInfo);
    reply.WriteString(dumpInfo);
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
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::VERIFY_NATIVETOKEN)] =
        &AccessTokenManagerStub::VerifyNativeTokenInner;
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
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GET_HAP_TOKEN_FROM_REMOTE)] =
        &AccessTokenManagerStub::GetHapTokenInfoFromRemoteInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GET_ALL_NATIVE_TOKEN_FROM_REMOTE)] =
        &AccessTokenManagerStub::GetAllNativeTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::SET_REMOTE_HAP_TOKEN_INFO)] =
        &AccessTokenManagerStub::SetRemoteHapTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::SET_REMOTE_NATIVE_TOKEN_INFO)] =
        &AccessTokenManagerStub::SetRemoteNativeTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::DELETE_REMOTE_TOKEN_INFO)] =
        &AccessTokenManagerStub::DeleteRemoteTokenInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::DELETE_REMOTE_DEVICE_TOKEN)] =
        &AccessTokenManagerStub::DeleteRemoteDeviceTokensInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GET_NATIVE_REMOTE_TOKEN)] =
        &AccessTokenManagerStub::GetRemoteNativeTokenIDInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::DUMP_TOKENINFO)] =
        &AccessTokenManagerStub::DumpTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GET_PERMISSION_OPER_STATE)] =
        &AccessTokenManagerStub::GetSelfPermissionsStateInner;
}

AccessTokenManagerStub::~AccessTokenManagerStub()
{
    requestFuncMap_.clear();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
