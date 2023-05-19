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

#include <unistd.h>
#include "accesstoken_dfx_define.h"
#include "accesstoken_log.h"
#include "access_token_error.h"
#include "ipc_skeleton.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "ATMStub"};
constexpr int32_t FOUNDATION_UID = 5523;
static const int32_t DUMP_CAPACITY_SIZE = 2 * 1024 * 1000;
static const int MAX_PERMISSION_SIZE = 1000;
#ifdef TOKEN_SYNC_ENABLE
static const int MAX_NATIVE_TOKEN_INFO_SIZE = 20480;
#endif
const std::string GRANT_SENSITIVE_PERMISSIONS = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
const std::string REVOKE_SENSITIVE_PERMISSIONS = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS";
const std::string GET_SENSITIVE_PERMISSIONS = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
}

int32_t AccessTokenManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "code %{public}u token %{public}u", code, callingTokenID);
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
            // when valid code without any function to handle
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    } else {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option); // when code invalid
    }

    return NO_ERROR;
}

void AccessTokenManagerStub::DeleteTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsFoundationCalling() && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied");
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
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
    std::string permissionName = data.ReadString();
    PermissionDefParcel permissionDefParcel;
    int result = this->GetDefPermission(permissionName, permissionDefParcel);
    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        return;
    }
    reply.WriteParcelable(&permissionDefParcel);
}

void AccessTokenManagerStub::GetDefPermissionsInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID = data.ReadUint32();
    std::vector<PermissionDefParcel> permList;

    int result = this->GetDefPermissions(tokenID, permList);
    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        return;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called, permList size: %{public}zu", __func__, permList.size());
    reply.WriteUint32(permList.size());
    for (const auto& permDef : permList) {
        reply.WriteParcelable(&permDef);
    }
}

void AccessTokenManagerStub::GetReqPermissionsInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID = data.ReadUint32();
    int isSystemGrant = data.ReadInt32();
    std::vector<PermissionStateFullParcel> permList;

    int result = this->GetReqPermissions(tokenID, permList, isSystemGrant);
    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        return;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "permList size: %{public}zu", permList.size());
    reply.WriteUint32(permList.size());
    for (const auto& permDef : permList) {
        reply.WriteParcelable(&permDef);
    }
}

void AccessTokenManagerStub::GetSelfPermissionsStateInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<PermissionListStateParcel> permList;
    uint32_t size = 0;
    if (!data.ReadUint32(size)) {
        reply.WriteInt32(INVALID_OPER);
        return;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "permList size read from client data is %{public}d.", size);
    if (size > MAX_PERMISSION_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permList size %{public}d is invalid", size);
        reply.WriteInt32(INVALID_OPER);
        return;
    }
    for (uint32_t i = 0; i < size; i++) {
        sptr<PermissionListStateParcel> permissionParcel = data.ReadParcelable<PermissionListStateParcel>();
        if (permissionParcel != nullptr) {
            permList.emplace_back(*permissionParcel);
        }
    }

    PermissionOper result = this->GetSelfPermissionsState(permList);

    reply.WriteInt32(result);

    reply.WriteUint32(permList.size());
    for (const auto& perm : permList) {
        reply.WriteParcelable(&perm);
    }
}

void AccessTokenManagerStub::GetPermissionFlagInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GRANT_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED &&
        VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", callingTokenID);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    int32_t flag;
    int result = this->GetPermissionFlag(tokenID, permissionName, flag);
    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        return;
    }
    reply.WriteInt32(flag);
}

void AccessTokenManagerStub::GrantPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int flag = data.ReadInt32();
    if (!IsPrivilegedCalling() && !IsFoundationCalling() &&
        VerifyAccessToken(callingTokenID, GRANT_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callingTokenID, "PERMISSION_NAME", permissionName);
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", callingTokenID);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    int result = this->GrantPermission(tokenID, permissionName, flag);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::RevokePermissionInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int flag = data.ReadInt32();
    if (!IsPrivilegedCalling() && !IsFoundationCalling() &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callingTokenID, "PERMISSION_NAME", permissionName);
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", callingTokenID);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    int result = this->RevokePermission(tokenID, permissionName, flag);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::ClearUserGrantedPermissionStateInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() && !IsFoundationCalling() &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callingTokenID);
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", callingTokenID);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    int result = this->ClearUserGrantedPermissionState(tokenID);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::AllocHapTokenInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenIDEx res = {0};
    if (!IsFoundationCalling() && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }

    sptr<HapInfoParcel> hapInfoParcel = data.ReadParcelable<HapInfoParcel>();
    sptr<HapPolicyParcel> hapPolicyParcel = data.ReadParcelable<HapPolicyParcel>();
    if (hapInfoParcel == nullptr || hapPolicyParcel == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "read hapPolicyParcel or hapInfoParcel fail");
        reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED);
        return;
    }
    res = this->AllocHapToken(*hapInfoParcel, *hapPolicyParcel);
    reply.WriteUint64(res.tokenIDEx);
}

void AccessTokenManagerStub::GetTokenTypeInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID = data.ReadUint32();
    int result = this->GetTokenType(tokenID);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::CheckNativeDCapInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    std::string dCap = data.ReadString();
    int result = this->CheckNativeDCap(tokenID, dCap);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetHapTokenIDInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(INVALID_TOKENID);
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
    if ((!IsNativeProcessCalling()) && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(INVALID_TOKENID);
        return;
    }
    std::string remoteDeviceID = data.ReadString();
    AccessTokenID remoteTokenID = data.ReadUint32();
    AccessTokenID result = this->AllocLocalTokenID(remoteDeviceID, remoteTokenID);
    reply.WriteUint32(result);
}

void AccessTokenManagerStub::UpdateHapTokenInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsFoundationCalling() && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    std::string appIDDesc = data.ReadString();
    int32_t apiVersion = data.ReadInt32();
    sptr<HapPolicyParcel> policyParcel = data.ReadParcelable<HapPolicyParcel>();
    if (policyParcel == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "policyParcel read faild");
        reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED);
        return;
    }
    int32_t result = this->UpdateHapToken(tokenID, appIDDesc, apiVersion, *policyParcel);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    HapTokenInfoParcel hapTokenInfoParcel;
    AccessTokenID tokenID = data.ReadUint32();
    int result = this->GetHapTokenInfo(tokenID, hapTokenInfoParcel);
    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        return;
    }
    reply.WriteParcelable(&hapTokenInfoParcel);
}

void AccessTokenManagerStub::GetNativeTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    NativeTokenInfoParcel nativeTokenInfoParcel;
    int result = this->GetNativeTokenInfo(tokenID, nativeTokenInfoParcel);
    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        return;
    }
    reply.WriteParcelable(&nativeTokenInfoParcel);
}

void AccessTokenManagerStub::RegisterPermStateChangeCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", callingTokenID);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    sptr<PermStateChangeScopeParcel> scopeParcel = data.ReadParcelable<PermStateChangeScopeParcel>();
    if (scopeParcel == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "read scopeParcel fail");
        reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED);
        return;
    }
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "read callback fail");
        reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED);
        return;
    }
    int32_t result = this->RegisterPermStateChangeCallback(*scopeParcel, callback);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::UnRegisterPermStateChangeCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", callingTokenID);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "read callback fail");
        reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED);
        return;
    }
    int32_t result = this->UnRegisterPermStateChangeCallback(callback);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::ReloadNativeTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteUint32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    int32_t result = this->ReloadNativeTokenInfo();
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetNativeTokenIdInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteUint32(INVALID_TOKENID);
        return;
    }
    std::string processName;
    if (!data.ReadString(processName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "readString fail, processName=%{public}s", processName.c_str());
        return;
    }
    AccessTokenID result = this->GetNativeTokenId(processName);
    reply.WriteUint32(result);
}

#ifdef TOKEN_SYNC_ENABLE
void AccessTokenManagerStub::GetHapTokenInfoFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    HapTokenInfoForSyncParcel hapTokenParcel;

    int result = this->GetHapTokenInfoFromRemote(tokenID, hapTokenParcel);
    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        return;
    }
    reply.WriteParcelable(&hapTokenParcel);
}

void AccessTokenManagerStub::GetAllNativeTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    std::vector<NativeTokenInfoForSyncParcel> nativeTokenInfosRes;
    int result = this->GetAllNativeTokenInfo(nativeTokenInfosRes);
    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        return;
    }
    reply.WriteUint32(nativeTokenInfosRes.size());
    for (const auto& native : nativeTokenInfosRes) {
        reply.WriteParcelable(&native);
    }
}

void AccessTokenManagerStub::SetRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    std::string deviceID = data.ReadString();
    sptr<HapTokenInfoForSyncParcel> hapTokenParcel = data.ReadParcelable<HapTokenInfoForSyncParcel>();
    if (hapTokenParcel == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "hapTokenParcel read faild");
        reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED);
        return;
    }
    int result = this->SetRemoteHapTokenInfo(deviceID, *hapTokenParcel);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::SetRemoteNativeTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    std::string deviceID = data.ReadString();

    std::vector<NativeTokenInfoForSyncParcel> nativeParcelList;
    uint32_t size = data.ReadUint32();
    if (size > MAX_NATIVE_TOKEN_INFO_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "size %{public}u is invalid", size);
        reply.WriteInt32(AccessTokenError::ERR_OVERSIZE);
        return;
    }
    for (uint32_t i = 0; i < size; i++) {
        sptr<NativeTokenInfoForSyncParcel> nativeParcel = data.ReadParcelable<NativeTokenInfoForSyncParcel>();
        if (nativeParcel == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "nativeParcel read faild");
            reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED);
            return;
        }
        nativeParcelList.emplace_back(*nativeParcel);
    }

    int result = this->SetRemoteNativeTokenInfo(deviceID, nativeParcelList);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::DeleteRemoteTokenInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    std::string deviceID = data.ReadString();
    AccessTokenID tokenID = data.ReadUint32();

    int result = this->DeleteRemoteToken(deviceID, tokenID);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetRemoteNativeTokenIDInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(INVALID_TOKENID);
        return;
    }
    std::string deviceID = data.ReadString();
    AccessTokenID tokenID = data.ReadUint32();

    AccessTokenID result = this->GetRemoteNativeTokenID(deviceID, tokenID);
    reply.WriteUint32(result);
}

void AccessTokenManagerStub::DeleteRemoteDeviceTokensInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    std::string deviceID = data.ReadString();

    int result = this->DeleteRemoteDeviceTokens(deviceID);
    reply.WriteInt32(result);
}
#endif

void AccessTokenManagerStub::DumpTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called, permission denied", __func__);
        reply.WriteString("");
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    std::string dumpInfo = "";
    this->DumpTokenInfo(tokenID, dumpInfo);
    if (!reply.SetDataCapacity(DUMP_CAPACITY_SIZE)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "SetDataCapacity failed");
    }
    if (!reply.WriteString(dumpInfo)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteString failed");
    }
}

bool AccessTokenManagerStub::IsPrivilegedCalling() const
{
    // shell process is root in debug mode.
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == SYSTEM_UID || callingUid == ROOT_UID;
}

bool AccessTokenManagerStub::IsFoundationCalling() const
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == FOUNDATION_UID;
}

bool AccessTokenManagerStub::IsAccessTokenCalling()
{
    uint32_t tokenCaller = IPCSkeleton::GetCallingTokenID();
    if (tokenSyncId_ == 0) {
        tokenSyncId_ = this->GetNativeTokenId("token_sync_service");
    }
    return tokenCaller == tokenSyncId_;
}

bool AccessTokenManagerStub::IsNativeProcessCalling()
{
    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    return this->GetTokenType(tokenCaller) == TOKEN_NATIVE;
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
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::RELOAD_NATIVE_TOKEN_INFO)] =
        &AccessTokenManagerStub::ReloadNativeTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GET_NATIVE_TOKEN_ID)] =
        &AccessTokenManagerStub::GetNativeTokenIdInner;
#ifdef TOKEN_SYNC_ENABLE
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
#endif

    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::DUMP_TOKENINFO)] =
        &AccessTokenManagerStub::DumpTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::GET_PERMISSION_OPER_STATE)] =
        &AccessTokenManagerStub::GetSelfPermissionsStateInner;

    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::REGISTER_PERM_STATE_CHANGE_CALLBACK)] =
        &AccessTokenManagerStub::RegisterPermStateChangeCallbackInner;
    requestFuncMap_[static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::UNREGISTER_PERM_STATE_CHANGE_CALLBACK)] =
        &AccessTokenManagerStub::UnRegisterPermStateChangeCallbackInner;
}

AccessTokenManagerStub::~AccessTokenManagerStub()
{
    requestFuncMap_.clear();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
