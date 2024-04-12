/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "memory_guard.h"
#include "string_ex.h"
#include "tokenid_kit.h"
#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "ATMStub"};
const std::string MANAGE_HAP_TOKENID_PERMISSION = "ohos.permission.MANAGE_HAP_TOKENID";
static const int32_t DUMP_CAPACITY_SIZE = 2 * 1024 * 1000;
static const int MAX_PERMISSION_SIZE = 1000;
#ifdef TOKEN_SYNC_ENABLE
static const int MAX_NATIVE_TOKEN_INFO_SIZE = 20480;
#endif
const std::string GRANT_SENSITIVE_PERMISSIONS = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
const std::string REVOKE_SENSITIVE_PERMISSIONS = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS";
const std::string GET_SENSITIVE_PERMISSIONS = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
const std::string DISABLE_PERMISSION_DIALOG = "ohos.permission.DISABLE_PERMISSION_DIALOG";
#ifdef HICOLLIE_ENABLE
constexpr uint32_t TIMEOUT = 20; // 20s
#endif // HICOLLIE_ENABLE
}

int32_t AccessTokenManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "code %{public}u token %{public}u", code, callingTokenID);
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IAccessTokenManager::GetDescriptor()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return ERROR_IPC_REQUEST_FAIL;
    }

#ifdef HICOLLIE_ENABLE
    std::string name = "AtmTimer";
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer(name, TIMEOUT, nullptr, nullptr,
        HiviewDFX::XCOLLIE_FLAG_LOG);
#endif // HICOLLIE_ENABLE
    auto itFunc = requestFuncMap_.find(code);
    if (itFunc != requestFuncMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            (this->*requestFunc)(data, reply);
        } else {
            // when valid code without any function to handle
#ifdef HICOLLIE_ENABLE
            HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    } else {
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option); // when code invalid
    }

#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE

    return NO_ERROR;
}

void AccessTokenManagerStub::DeleteTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(callingTokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", callingTokenID);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    int result = this->DeleteToken(tokenID);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetUserGrantedPermissionUsedTypeInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        reply.WriteInt32(static_cast<int32_t>(PermUsedTypeEnum::INVALID_USED_TYPE));
        return;
    }
    uint32_t tokenID;
    if (!data.ReadUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to read tokenID.");
        reply.WriteInt32(static_cast<int32_t>(PermUsedTypeEnum::INVALID_USED_TYPE));
        return;
    }
    std::string permissionName;
    if (!data.ReadString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to read permissionName.");
        reply.WriteInt32(static_cast<int32_t>(PermUsedTypeEnum::INVALID_USED_TYPE));
        return;
    }
    PermUsedTypeEnum result = this->GetUserGrantedPermissionUsedType(tokenID, permissionName);
    int32_t type = static_cast<int32_t>(result);
    if (!reply.WriteInt32(type)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInt32 fail.");
    }
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
    PermissionGrantInfoParcel infoParcel;
    PermissionOper result = this->GetSelfPermissionsState(permList, infoParcel);

    reply.WriteInt32(result);

    reply.WriteUint32(permList.size());
    for (const auto& perm : permList) {
        reply.WriteParcelable(&perm);
    }
    reply.WriteParcelable(&infoParcel);
}

void AccessTokenManagerStub::GetPermissionsStatusInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", callingTokenID);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }

    AccessTokenID tokenID = data.ReadUint32();
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
    int32_t result = this->GetPermissionsStatus(tokenID, permList);

    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        return;
    }
    reply.WriteUint32(permList.size());
    for (const auto& perm : permList) {
        reply.WriteParcelable(&perm);
    }
}

void AccessTokenManagerStub::GetPermissionFlagInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP);
        return;
    }
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
    uint32_t flag;
    int result = this->GetPermissionFlag(tokenID, permissionName, flag);
    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        return;
    }
    reply.WriteUint32(flag);
}

void AccessTokenManagerStub::SetPermissionRequestToggleStatusInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP);
        return;
    }

    std::string permissionName = data.ReadString();
    uint32_t status = data.ReadUint32();
    int32_t userID = data.ReadInt32();
    if (!IsPrivilegedCalling() && VerifyAccessToken(callingTokenID, DISABLE_PERMISSION_DIALOG) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR, "CALLER_TOKENID",
            callingTokenID, "PERMISSION_NAME", permissionName, "INTERFACE", "SetToggleStatus");
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission denied(tokenID=%{public}d).", callingTokenID);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    int32_t result = this->SetPermissionRequestToggleStatus(permissionName, status, userID);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::GetPermissionRequestToggleStatusInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP);
        return;
    }

    std::string permissionName = data.ReadString();
    int32_t userID = data.ReadInt32();
    if (!IsShellProcessCalling() && !IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR, "CALLER_TOKENID",
            callingTokenID, "PERMISSION_NAME", permissionName, "INTERFACE", "GetToggleStatus");
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission denied(tokenID=%{public}d).", callingTokenID);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    uint32_t status;
    int32_t result = this->GetPermissionRequestToggleStatus(permissionName, status, userID);
    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        return;
    }
    reply.WriteUint32(status);
}

void AccessTokenManagerStub::GrantPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    uint32_t flag = data.ReadUint32();
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GRANT_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
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
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    uint32_t flag = data.ReadUint32();
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
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
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
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
    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(tokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", tokenID);
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

void AccessTokenManagerStub::InitHapTokenInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(tokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", tokenID);
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
    int32_t res;
    AccessTokenIDEx fullTokenId = { 0 };
    res = this->InitHapToken(*hapInfoParcel, *hapPolicyParcel, fullTokenId);
    if (!reply.WriteInt32(res)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInt32 fail");
    }

    if (res != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "res error %{public}d", res);
        return;
    }
    reply.WriteUint64(fullTokenId.tokenIDEx);
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        reply.WriteInt32(INVALID_TOKENID);
        return;
    }
    int userID = data.ReadInt32();
    std::string bundleName = data.ReadString();
    int instIndex = data.ReadInt32();
    AccessTokenIDEx tokenIdEx = this->GetHapTokenID(userID, bundleName, instIndex);
    reply.WriteUint64(tokenIdEx.tokenIDEx);
}

void AccessTokenManagerStub::AllocLocalTokenIDInner(MessageParcel& data, MessageParcel& reply)
{
    if ((!IsNativeProcessCalling()) && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
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
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(callingTokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", callingTokenID);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    UpdateHapInfoParams info;
    AccessTokenID tokenID = data.ReadUint32();
    info.isSystemApp = data.ReadBool();
    info.appIDDesc = data.ReadString();
    info.apiVersion = data.ReadInt32();
    info.appDistributionType = data.ReadString();
    AccessTokenIDEx tokenIdEx;
    tokenIdEx.tokenIdExStruct.tokenID = tokenID;
    sptr<HapPolicyParcel> policyParcel = data.ReadParcelable<HapPolicyParcel>();
    if (policyParcel == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "policyParcel read faild");
        reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED);
        return;
    }
    int32_t result = this->UpdateHapToken(tokenIdEx, info, *policyParcel);
    reply.WriteInt32(result);
    reply.WriteUint32(tokenIdEx.tokenIdExStruct.tokenAttr);
}

void AccessTokenManagerStub::GetHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
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
    MemoryGuard guard;

    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
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
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP);
        return;
    }
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
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingToken) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (VerifyAccessToken(callingToken, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", callingToken);
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

#ifndef ATM_BUILD_VARIANT_USER_ENABLE
void AccessTokenManagerStub::ReloadNativeTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        reply.WriteUint32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    int32_t result = this->ReloadNativeTokenInfo();
    reply.WriteInt32(result);
}
#endif

void AccessTokenManagerStub::GetNativeTokenIdInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    std::string deviceID = data.ReadString();

    int result = this->DeleteRemoteDeviceTokens(deviceID);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::RegisterTokenSyncCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission denied, tokenID=%{public}d", IPCSkeleton::GetCallingTokenID());
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }

    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Callback read failed.");
        reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED);
        return;
    }
    int32_t result = this->RegisterTokenSyncCallback(callback);
    reply.WriteInt32(result);
}

void AccessTokenManagerStub::UnRegisterTokenSyncCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission denied, tokenID=%{public}d", IPCSkeleton::GetCallingTokenID());
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }

    int32_t result = this->UnRegisterTokenSyncCallback();
    reply.WriteInt32(result);
}
#endif

void AccessTokenManagerStub::DumpPermDefInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsShellProcessCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }
    std::string dumpInfo = "";
    int32_t result = this->DumpPermDefInfo(dumpInfo);
    if (!reply.WriteInt32(result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write result failed.");
    }
    if (result != RET_SUCCESS) {
        return;
    }

    if (!reply.SetDataCapacity(DUMP_CAPACITY_SIZE)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "Set DataCapacity failed.");
    }
    if (!reply.WriteString(dumpInfo)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write String failed.");
    }
}

void AccessTokenManagerStub::GetVersionInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingToken) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP);
        return;
    }
    uint32_t version;
    int32_t result = this->GetVersion(version);
    if (!reply.WriteInt32(result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write result failed.");
    }
    if (result != RET_SUCCESS) {
        return;
    }
    if (!reply.WriteUint32(version)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write Uint32 failed.");
    }
}

void AccessTokenManagerStub::DumpTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsShellProcessCalling()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        reply.WriteString("");
        return;
    }
    sptr<AtmToolsParamInfoParcel> infoParcel = data.ReadParcelable<AtmToolsParamInfoParcel>();
    if (infoParcel == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "read infoParcel fail");
        reply.WriteString("read infoParcel fail");
        return;
    }
    std::string dumpInfo = "";
    this->DumpTokenInfo(*infoParcel, dumpInfo);
    if (!reply.SetDataCapacity(DUMP_CAPACITY_SIZE)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "SetDataCapacity failed");
    }
    if (!reply.WriteString(dumpInfo)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteString failed");
    }
}

void AccessTokenManagerStub::SetPermDialogCapInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, DISABLE_PERMISSION_DIALOG) == PERMISSION_DENIED) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(tokenID=%{public}d)", callingToken);
        reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED);
        return;
    }

    sptr<HapBaseInfoParcel> hapBaseInfoParcel = data.ReadParcelable<HapBaseInfoParcel>();
    if (hapBaseInfoParcel == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "read hapBaseInfoParcel fail");
        reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED);
        return;
    }
    bool enable = data.ReadBool();
    int32_t res = this->SetPermDialogCap(*hapBaseInfoParcel, enable);
    reply.WriteInt32(res);
}

bool AccessTokenManagerStub::IsPrivilegedCalling() const
{
    // shell process is root in debug mode.
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ROOT_UID;
#else
    return false;
#endif
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

bool AccessTokenManagerStub::IsShellProcessCalling()
{
    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    return this->GetTokenType(tokenCaller) == TOKEN_SHELL;
}

bool AccessTokenManagerStub::IsSystemAppCalling() const
{
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    return TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
}

#ifdef TOKEN_SYNC_ENABLE
void AccessTokenManagerStub::SetTokenSyncFuncInMap()
{
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_HAP_TOKEN_FROM_REMOTE)] =
        &AccessTokenManagerStub::GetHapTokenInfoFromRemoteInner;
    requestFuncMap_[
        static_cast<uint32_t>(AccessTokenInterfaceCode::GET_ALL_NATIVE_TOKEN_FROM_REMOTE)] =
        &AccessTokenManagerStub::GetAllNativeTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::SET_REMOTE_HAP_TOKEN_INFO)] =
        &AccessTokenManagerStub::SetRemoteHapTokenInfoInner;
    requestFuncMap_[
        static_cast<uint32_t>(AccessTokenInterfaceCode::SET_REMOTE_NATIVE_TOKEN_INFO)] =
        &AccessTokenManagerStub::SetRemoteNativeTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::DELETE_REMOTE_TOKEN_INFO)] =
        &AccessTokenManagerStub::DeleteRemoteTokenInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::DELETE_REMOTE_DEVICE_TOKEN)] =
        &AccessTokenManagerStub::DeleteRemoteDeviceTokensInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_NATIVE_REMOTE_TOKEN)] =
        &AccessTokenManagerStub::GetRemoteNativeTokenIDInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::REGISTER_TOKEN_SYNC_CALLBACK)] =
        &AccessTokenManagerStub::RegisterTokenSyncCallbackInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::UNREGISTER_TOKEN_SYNC_CALLBACK)] =
        &AccessTokenManagerStub::UnRegisterTokenSyncCallbackInner;
}
#endif

void AccessTokenManagerStub::SetLocalTokenOpFuncInMap()
{
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::ALLOC_TOKEN_HAP)] =
        &AccessTokenManagerStub::AllocHapTokenInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::INIT_TOKEN_HAP)] =
        &AccessTokenManagerStub::InitHapTokenInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::TOKEN_DELETE)] =
        &AccessTokenManagerStub::DeleteTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_TOKEN_TYPE)] =
        &AccessTokenManagerStub::GetTokenTypeInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::CHECK_NATIVE_DCAP)] =
        &AccessTokenManagerStub::CheckNativeDCapInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_HAP_TOKEN_ID)] =
        &AccessTokenManagerStub::GetHapTokenIDInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::ALLOC_LOCAL_TOKEN_ID)] =
        &AccessTokenManagerStub::AllocLocalTokenIDInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_NATIVE_TOKENINFO)] =
        &AccessTokenManagerStub::GetNativeTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_HAP_TOKENINFO)] =
        &AccessTokenManagerStub::GetHapTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::UPDATE_HAP_TOKEN)] =
        &AccessTokenManagerStub::UpdateHapTokenInner;
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::RELOAD_NATIVE_TOKEN_INFO)] =
        &AccessTokenManagerStub::ReloadNativeTokenInfoInner;
#endif
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_NATIVE_TOKEN_ID)] =
        &AccessTokenManagerStub::GetNativeTokenIdInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::SET_PERM_DIALOG_CAPABILITY)] =
        &AccessTokenManagerStub::SetPermDialogCapInner;
}

void AccessTokenManagerStub::SetPermissionOpFuncInMap()
{
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_USER_GRANTED_PERMISSION_USED_TYPE)] =
        &AccessTokenManagerStub::GetUserGrantedPermissionUsedTypeInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::VERIFY_ACCESSTOKEN)] =
        &AccessTokenManagerStub::VerifyAccessTokenInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_DEF_PERMISSION)] =
        &AccessTokenManagerStub::GetDefPermissionInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_DEF_PERMISSIONS)] =
        &AccessTokenManagerStub::GetDefPermissionsInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_REQ_PERMISSIONS)] =
        &AccessTokenManagerStub::GetReqPermissionsInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_PERMISSION_FLAG)] =
        &AccessTokenManagerStub::GetPermissionFlagInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GRANT_PERMISSION)] =
        &AccessTokenManagerStub::GrantPermissionInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::REVOKE_PERMISSION)] =
        &AccessTokenManagerStub::RevokePermissionInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::CLEAR_USER_GRANT_PERMISSION)] =
        &AccessTokenManagerStub::ClearUserGrantedPermissionStateInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_PERMISSION_OPER_STATE)] =
        &AccessTokenManagerStub::GetSelfPermissionsStateInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_PERMISSIONS_STATUS)] =
        &AccessTokenManagerStub::GetPermissionsStatusInner;
    requestFuncMap_[
        static_cast<uint32_t>(AccessTokenInterfaceCode::REGISTER_PERM_STATE_CHANGE_CALLBACK)] =
        &AccessTokenManagerStub::RegisterPermStateChangeCallbackInner;
    requestFuncMap_[
        static_cast<uint32_t>(AccessTokenInterfaceCode::UNREGISTER_PERM_STATE_CHANGE_CALLBACK)] =
        &AccessTokenManagerStub::UnRegisterPermStateChangeCallbackInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::DUMP_TOKENINFO)] =
        &AccessTokenManagerStub::DumpTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::DUMP_PERM_DEFINITION_INFO)] =
        &AccessTokenManagerStub::DumpPermDefInfoInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_VERSION)] =
        &AccessTokenManagerStub::GetVersionInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::SET_PERMISSION_REQUEST_TOGGLE_STATUS)] =
        &AccessTokenManagerStub::SetPermissionRequestToggleStatusInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_PERMISSION_REQUEST_TOGGLE_STATUS)] =
        &AccessTokenManagerStub::GetPermissionRequestToggleStatusInner;
}

AccessTokenManagerStub::AccessTokenManagerStub()
{
    SetPermissionOpFuncInMap();
    SetLocalTokenOpFuncInMap();
#ifdef TOKEN_SYNC_ENABLE
    SetTokenSyncFuncInMap();
#endif
}

AccessTokenManagerStub::~AccessTokenManagerStub()
{
    requestFuncMap_.clear();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
