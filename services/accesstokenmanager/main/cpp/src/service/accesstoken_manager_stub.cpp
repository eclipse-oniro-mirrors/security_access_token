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
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "ipc_skeleton.h"
#include "memory_guard.h"
#include "string_ex.h"
#include "tokenid_kit.h"
#include "hisysevent_adapter.h"
#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
const std::string MANAGE_HAP_TOKENID_PERMISSION = "ohos.permission.MANAGE_HAP_TOKENID";
static const int32_t DUMP_CAPACITY_SIZE = 2 * 1024 * 1000;
static const int MAX_PERMISSION_SIZE = 1000;
static const int32_t MAX_USER_POLICY_SIZE = 1024;
const std::string GRANT_SENSITIVE_PERMISSIONS = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
const std::string REVOKE_SENSITIVE_PERMISSIONS = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS";
const std::string GET_SENSITIVE_PERMISSIONS = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
const std::string DISABLE_PERMISSION_DIALOG = "ohos.permission.DISABLE_PERMISSION_DIALOG";
const std::string GRANT_SHORT_TERM_WRITE_MEDIAVIDEO = "ohos.permission.GRANT_SHORT_TERM_WRITE_MEDIAVIDEO";

#ifdef HICOLLIE_ENABLE
constexpr uint32_t TIMEOUT = 40; // 40s
#endif // HICOLLIE_ENABLE
}

int32_t AccessTokenManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    MemoryGuard guard;

    ClearThreadErrorMsg();
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    LOGD(ATM_DOMAIN, ATM_TAG, "Code %{public}u token %{public}u", code, callingTokenID);
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IAccessTokenManager::GetDescriptor()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
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

#ifdef HICOLLIE_ENABLE
            HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
            ReportSysCommonEventError(code, 0);
            return NO_ERROR;
        }
    }

#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option); // when code invalid
}

void AccessTokenManagerStub::DeleteTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(callingTokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    if (this->GetTokenType(tokenID) != TOKEN_HAP) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PARAM_INVALID), "WriteInt32 failed.");
        return;
    }
    int result = this->DeleteToken(tokenID);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::GetPermissionUsedTypeInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(static_cast<int32_t>(PermUsedTypeEnum::INVALID_USED_TYPE)),
            "WriteInt32 failed.");
        return;
    }
    uint32_t tokenID;
    if (!data.ReadUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to read tokenID.");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(static_cast<int32_t>(PermUsedTypeEnum::INVALID_USED_TYPE)),
            "WriteInt32 failed.");
        return;
    }
    std::string permissionName;
    if (!data.ReadString(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to read permissionName.");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(
            static_cast<int32_t>(PermUsedTypeEnum::INVALID_USED_TYPE)), "WriteInt32 failed.");
        return;
    }
    PermUsedTypeEnum result = this->GetPermissionUsedType(tokenID, permissionName);
    int32_t type = static_cast<int32_t>(result);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(type), "WriteInt32 failed.");
}

void AccessTokenManagerStub::VerifyAccessTokenInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int result = this->VerifyAccessToken(tokenID, permissionName);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::VerifyAccessTokenWithListInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID;
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, data.ReadUint32(tokenID), "ReadUint32 failed.");
    
    std::vector<std::string> permissionList;
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, data.ReadStringVector(&permissionList), "ReadStringVector failed.");

    std::vector<int32_t> permStateList;
    this->VerifyAccessToken(tokenID, permissionList, permStateList);

    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32Vector(permStateList), "WriteInt32Vector failed.");
}

void AccessTokenManagerStub::GetDefPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    std::string permissionName = data.ReadString();
    PermissionDefParcel permissionDefParcel;
    int result = this->GetDefPermission(permissionName, permissionDefParcel);
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
    if (result != RET_SUCCESS) {
        return;
    }
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
        reply.WriteParcelable(&permissionDefParcel), "Write PermissionDefParcel fail.");
}

void AccessTokenManagerStub::GetReqPermissionsInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP), "WriteInt32 failed.");
        return;
    }
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    
    AccessTokenID tokenID = data.ReadUint32();
    int isSystemGrant = data.ReadInt32();
    std::vector<PermissionStatusParcel> permList;

    int result = this->GetReqPermissions(tokenID, permList, isSystemGrant);
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
    if (result != RET_SUCCESS) {
        return;
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "PermList size: %{public}zu", permList.size());
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(permList.size()), "WriteInt32 failed.");
    for (const auto& permDef : permList) {
        IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteParcelable(&permDef), "WriteParcelable fail.");
    }
}

void AccessTokenManagerStub::GetSelfPermissionsStateInner(MessageParcel& data, MessageParcel& reply)
{
    std::vector<PermissionListStateParcel> permList;
    uint32_t size = 0;
    if (!data.ReadUint32(size)) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(INVALID_OPER), "WriteInt32 failed.");
        return;
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "PermList size read from client data is %{public}d.", size);
    if (size > MAX_PERMISSION_SIZE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermList size %{public}d is invalid", size);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(INVALID_OPER), "WriteInt32 failed.");
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
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");

    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteUint32(permList.size()), "WriteUint32 failed.");
    for (const auto& perm : permList) {
        IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteParcelable(&perm), "WriteParcelable failed.");
    }
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteParcelable(&infoParcel), "WriteParcelable failed.");
}

void AccessTokenManagerStub::GetPermissionsStatusInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP), "WriteInt32 failed.");
        return;
    }
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }

    AccessTokenID tokenID = data.ReadUint32();
    std::vector<PermissionListStateParcel> permList;
    uint32_t size = 0;
    if (!data.ReadUint32(size)) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(INVALID_OPER), "WriteInt32 failed.");
        return;
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "PermList size read from client data is %{public}d.", size);
    if (size > MAX_PERMISSION_SIZE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermList size %{public}d is oversize", size);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(INVALID_OPER), "WriteInt32 failed.");
        return;
    }
    for (uint32_t i = 0; i < size; i++) {
        sptr<PermissionListStateParcel> permissionParcel = data.ReadParcelable<PermissionListStateParcel>();
        if (permissionParcel != nullptr) {
            permList.emplace_back(*permissionParcel);
        }
    }
    int32_t result = this->GetPermissionsStatus(tokenID, permList);

    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
    if (result != RET_SUCCESS) {
        return;
    }
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteUint32(permList.size()), "WriteUint32 failed.");
    for (const auto& perm : permList) {
        IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteParcelable(&perm), "WriteParcelable failed.");
    }
}

void AccessTokenManagerStub::GetPermissionFlagInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP), "WriteInt32 failed.");
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GRANT_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED &&
        VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    uint32_t flag;
    int result = this->GetPermissionFlag(tokenID, permissionName, flag);
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
    if (result != RET_SUCCESS) {
        return;
    }

    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteUint32(flag), "WriteUint32 failed.");
}

void AccessTokenManagerStub::SetPermissionRequestToggleStatusInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP), "WriteInt32 failed.");
        return;
    }

    std::string permissionName = data.ReadString();
    uint32_t status = data.ReadUint32();
    int32_t userID = data.ReadInt32();
    if (!IsPrivilegedCalling() && VerifyAccessToken(callingTokenID, DISABLE_PERMISSION_DIALOG) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR, "CALLER_TOKENID",
            callingTokenID, "PERMISSION_NAME", permissionName, "INTERFACE", "SetToggleStatus");
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d).", callingTokenID);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    int32_t result = this->SetPermissionRequestToggleStatus(permissionName, status, userID);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::GetPermissionRequestToggleStatusInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP), "WriteInt32 failed.");
        return;
    }

    std::string permissionName = data.ReadString();
    int32_t userID = data.ReadInt32();
    if (!IsShellProcessCalling() && !IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR, "CALLER_TOKENID",
            callingTokenID, "PERMISSION_NAME", permissionName, "INTERFACE", "GetToggleStatus");
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d).", callingTokenID);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    uint32_t status;
    int32_t result = this->GetPermissionRequestToggleStatus(permissionName, status, userID);
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
    if (result != RET_SUCCESS) {
        return;
    }
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(status), "WriteInt32 failed.");
}

void AccessTokenManagerStub::RequestAppPermOnSettingInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsSystemAppCalling()) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP), "WriteInt32 failed.");
        return;
    }

    AccessTokenID tokenID;
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, data.ReadUint32(tokenID), "ReadUint32 failed.");

    int result = this->RequestAppPermOnSetting(tokenID);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::GrantPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP), "WriteInt32 failed.");
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    int result = this->GrantPermission(tokenID, permissionName, flag);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::RevokePermissionInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP), "WriteInt32 failed.");
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    int result = this->RevokePermission(tokenID, permissionName, flag);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::GrantPermissionForSpecifiedTimeInner(MessageParcel& data, MessageParcel& reply)
{
    unsigned int callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP), "WriteInt32 failed.");
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    uint32_t onceTime = data.ReadUint32();
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GRANT_SHORT_TERM_WRITE_MEDIAVIDEO) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callingTokenID, "PERMISSION_NAME", permissionName);
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    int result = this->GrantPermissionForSpecifiedTime(tokenID, permissionName, onceTime);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::ClearUserGrantedPermissionStateInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callingTokenID);
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    int result = this->ClearUserGrantedPermissionState(tokenID);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::AllocHapTokenInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenIDEx res = {0};
    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(tokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", tokenID);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }

    sptr<HapInfoParcel> hapInfoParcel = data.ReadParcelable<HapInfoParcel>();
    sptr<HapPolicyParcel> hapPolicyParcel = data.ReadParcelable<HapPolicyParcel>();
    if (hapInfoParcel == nullptr || hapPolicyParcel == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read hapPolicyParcel or hapInfoParcel fail");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", tokenID);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }

    sptr<HapInfoParcel> hapInfoParcel = data.ReadParcelable<HapInfoParcel>();
    sptr<HapPolicyParcel> hapPolicyParcel = data.ReadParcelable<HapPolicyParcel>();
    if (hapInfoParcel == nullptr || hapPolicyParcel == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read hapPolicyParcel or hapInfoParcel fail");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
        return;
    }
    int32_t res;
    AccessTokenIDEx fullTokenId = { 0 };
    HapInfoCheckResult result;
    res = this->InitHapToken(*hapInfoParcel, *hapPolicyParcel, fullTokenId, result);
    if (!reply.WriteInt32(res)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInt32 fail");
    }

    if (res != RET_SUCCESS) {
        if (!result.permCheckResult.permissionName.empty()) {
            IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG,
                reply.WriteString(result.permCheckResult.permissionName), "WriteString failed.");
            IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG,
                reply.WriteInt32(result.permCheckResult.rule),  "WriteInt32 failed.");
        }
        LOGE(ATM_DOMAIN, ATM_TAG, "Res error %{public}d.", res);
        return;
    }
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteUint64(fullTokenId.tokenIDEx), "WriteUint64 failed.");
}

void AccessTokenManagerStub::GetTokenTypeInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID = data.ReadUint32();
    int result = this->GetTokenType(tokenID);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::GetHapTokenIDInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(INVALID_TOKENID), "WriteInt32 failed.");
        return;
    }
    int userID = data.ReadInt32();
    std::string bundleName = data.ReadString();
    int instIndex = data.ReadInt32();
    AccessTokenIDEx tokenIdEx = this->GetHapTokenID(userID, bundleName, instIndex);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteUint64(tokenIdEx.tokenIDEx), "WriteUint64 failed.");
}

void AccessTokenManagerStub::AllocLocalTokenIDInner(MessageParcel& data, MessageParcel& reply)
{
    if ((!IsNativeProcessCalling()) && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(INVALID_TOKENID), "WriteInt32 failed.");
        return;
    }
    std::string remoteDeviceID = data.ReadString();
    AccessTokenID remoteTokenID = data.ReadUint32();
    AccessTokenID result = this->AllocLocalTokenID(remoteDeviceID, remoteTokenID);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteUint32(result), "WriteUint32 failed.");
}

void AccessTokenManagerStub::UpdateHapTokenInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(callingTokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
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
        LOGE(ATM_DOMAIN, ATM_TAG, "PolicyParcel read faild");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
        return;
    }
    info.isAtomicService = data.ReadBool();
    HapInfoCheckResult resultInfo;
    int32_t result = this->UpdateHapToken(tokenIdEx, info, *policyParcel, resultInfo);
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
        reply.WriteUint32(tokenIdEx.tokenIdExStruct.tokenAttr), "WriteUint32 failed.");
    if (result != RET_SUCCESS) {
        if (!resultInfo.permCheckResult.permissionName.empty()) {
            IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG,
                reply.WriteString(resultInfo.permCheckResult.permissionName), "WriteString failed.");
            IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG,
                reply.WriteInt32(resultInfo.permCheckResult.rule),  "WriteInt32 failed.");
        }
        LOGE(ATM_DOMAIN, ATM_TAG, "Res error %{public}d", result);
        return;
    }
}

void AccessTokenManagerStub::GetTokenIDByUserIDInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    std::unordered_set<AccessTokenID> tokenIdList;
    int32_t userID = 0;
    if (!data.ReadInt32(userID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to read userId.");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
        return;
    }
    int32_t result = this->GetTokenIDByUserID(userID, tokenIdList);
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
    if (result != RET_SUCCESS) {
        return;
    }
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteUint32(tokenIdList.size()), "WriteUint32 failed.");
    for (const auto& tokenId : tokenIdList) {
        IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteUint32(tokenId), "WriteUint32 failed.");
    }
}

void AccessTokenManagerStub::GetHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    HapTokenInfoParcel hapTokenInfoParcel;
    AccessTokenID tokenID = data.ReadUint32();
    int result = this->GetHapTokenInfo(tokenID, hapTokenInfoParcel);
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
    if (result != RET_SUCCESS) {
        return;
    }
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteParcelable(&hapTokenInfoParcel), "Write parcel failed.");
}

void AccessTokenManagerStub::GetHapTokenInfoExtensionInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    HapTokenInfoParcel hapTokenInfoParcel;
    std::string appID;
    AccessTokenID tokenID = data.ReadUint32();
    int result = this->GetHapTokenInfoExtension(tokenID, hapTokenInfoParcel, appID);
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
    if (result != RET_SUCCESS) {
        return;
    }
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteParcelable(&hapTokenInfoParcel), "Write parcel failed.");
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteString(appID), "Write string failed.");
}

void AccessTokenManagerStub::GetNativeTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d).", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    NativeTokenInfoParcel nativeTokenInfoParcel;
    int result = this->GetNativeTokenInfo(tokenID, nativeTokenInfoParcel);
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
    if (result != RET_SUCCESS) {
        return;
    }
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteParcelable(&nativeTokenInfoParcel), "WriteInt32 failed.");
}

void AccessTokenManagerStub::RegisterPermStateChangeCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP), "WriteInt32 failed.");
        return;
    }
    if (VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    sptr<PermStateChangeScopeParcel> scopeParcel = data.ReadParcelable<PermStateChangeScopeParcel>();
    if (scopeParcel == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read scopeParcel fail");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
        return;
    }
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read callback fail");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
        return;
    }
    int32_t result = this->RegisterPermStateChangeCallback(*scopeParcel, callback);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::UnRegisterPermStateChangeCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingToken) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP), "WriteInt32 failed.");
        return;
    }
    if (VerifyAccessToken(callingToken, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingToken);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read callback fail");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
        return;
    }
    int32_t result = this->UnRegisterPermStateChangeCallback(callback);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::RegisterSelfPermStateChangeCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (this->GetTokenType(callingTokenID) != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is not hap.");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PARAM_INVALID), "WriteInt32 failed.");
        return;
    }
    sptr<PermStateChangeScopeParcel> scopeParcel = data.ReadParcelable<PermStateChangeScopeParcel>();
    if (scopeParcel == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read scopeParcel fail");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
        return;
    }
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read callback fail");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
        return;
    }
    int32_t result = this->RegisterSelfPermStateChangeCallback(*scopeParcel, callback);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::UnRegisterSelfPermStateChangeCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (this->GetTokenType(callingToken) != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is not hap.");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PARAM_INVALID), "WriteInt32 failed.");
        return;
    }
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read callback fail");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
        return;
    }
    int32_t result = this->UnRegisterSelfPermStateChangeCallback(callback);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

#ifndef ATM_BUILD_VARIANT_USER_ENABLE
void AccessTokenManagerStub::ReloadNativeTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteUint32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    int32_t result = this->ReloadNativeTokenInfo();
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}
#endif

void AccessTokenManagerStub::GetNativeTokenIdInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteUint32(INVALID_TOKENID), "WriteUint32 failed.");
        return;
    }
    std::string processName;
    if (!data.ReadString(processName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadString fail, processName=%{public}s", processName.c_str());
        return;
    }
    AccessTokenID result = this->GetNativeTokenId(processName);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::GetKernelPermissionsInner(MessageParcel& data, MessageParcel& reply)
{
    auto callingToken = IPCSkeleton::GetCallingTokenID();
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingToken);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteUint32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteUint32 failed.");
        return;
    }

    AccessTokenID tokenID;
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, data.ReadUint32(tokenID), "ReadUint32 failed.");
    std::vector<PermissionWithValue> kernelPermList;
    int32_t result = this->GetKernelPermissions(tokenID, kernelPermList);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
    if (result != RET_SUCCESS) {
        return;
    }
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteUint32(kernelPermList.size()), "WriteUint32 failed.");
    for (const auto& perm : kernelPermList) {
        IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteString(perm.permissionName), "WriteString failed.");
        IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteString(perm.value), "WriteString failed.");
    }
}

void AccessTokenManagerStub::GetReqPermissionByNameInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteUint32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteUint32 failed.");
        return;
    }

    AccessTokenID tokenID;
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, data.ReadUint32(tokenID), "ReadUint32 failed.");
    std::string permissionName;
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, data.ReadString(permissionName), "ReadUint32 failed.");
    std::string resultValue;
    int32_t result = this->GetReqPermissionByName(tokenID, permissionName, resultValue);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
    if (result != RET_SUCCESS) {
        return;
    }
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteString(resultValue), "WriteString failed.");
}

#ifdef TOKEN_SYNC_ENABLE
void AccessTokenManagerStub::GetHapTokenInfoFromRemoteInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    HapTokenInfoForSyncParcel hapTokenParcel;

    int result = this->GetHapTokenInfoFromRemote(tokenID, hapTokenParcel);
    IF_FALSE_RETURN_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
    if (result != RET_SUCCESS) {
        return;
    }
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteParcelable(&hapTokenParcel), "WriteParcelable failed.");
}

void AccessTokenManagerStub::SetRemoteHapTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    std::string deviceID = data.ReadString();
    sptr<HapTokenInfoForSyncParcel> hapTokenParcel = data.ReadParcelable<HapTokenInfoForSyncParcel>();
    if (hapTokenParcel == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "HapTokenParcel read faild");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
        return;
    }
    int result = this->SetRemoteHapTokenInfo(deviceID, *hapTokenParcel);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::DeleteRemoteTokenInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    std::string deviceID = data.ReadString();
    AccessTokenID tokenID = data.ReadUint32();

    int result = this->DeleteRemoteToken(deviceID, tokenID);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::GetRemoteNativeTokenIDInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(INVALID_TOKENID), "WriteInt32 failed.");
        return;
    }
    std::string deviceID = data.ReadString();
    AccessTokenID tokenID = data.ReadUint32();

    AccessTokenID result = this->GetRemoteNativeTokenID(deviceID, tokenID);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::DeleteRemoteDeviceTokensInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    std::string deviceID = data.ReadString();

    int result = this->DeleteRemoteDeviceTokens(deviceID);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::RegisterTokenSyncCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied, tokenID=%{public}d", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }

    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Callback read failed.");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
        return;
    }
    int32_t result = this->RegisterTokenSyncCallback(callback);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}

void AccessTokenManagerStub::UnRegisterTokenSyncCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied, tokenID=%{public}d", IPCSkeleton::GetCallingTokenID());
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }

    int32_t result = this->UnRegisterTokenSyncCallback();
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
}
#endif

void AccessTokenManagerStub::GetVersionInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingToken) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_NOT_SYSTEM_APP), "WriteInt32 failed.");
        return;
    }
    uint32_t version;
    int32_t result = this->GetVersion(version);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(result), "WriteInt32 failed.");
    if (result != RET_SUCCESS) {
        return;
    }
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteUint32(version), "WriteUint32 failed.");
}

void AccessTokenManagerStub::DumpTokenInfoInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsShellProcessCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        reply.WriteString("");
        return;
    }
    sptr<AtmToolsParamInfoParcel> infoParcel = data.ReadParcelable<AtmToolsParamInfoParcel>();
    if (infoParcel == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read infoParcel fail");
        reply.WriteString("read infoParcel fail");
        return;
    }
    std::string dumpInfo = "";
    this->DumpTokenInfo(*infoParcel, dumpInfo);
    if (!reply.SetDataCapacity(DUMP_CAPACITY_SIZE)) {
        LOGW(ATM_DOMAIN, ATM_TAG, "SetDataCapacity failed");
    }
    if (!reply.WriteString(dumpInfo)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString failed");
    }
}

void AccessTokenManagerStub::SetPermDialogCapInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, DISABLE_PERMISSION_DIALOG) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingToken);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }

    sptr<HapBaseInfoParcel> hapBaseInfoParcel = data.ReadParcelable<HapBaseInfoParcel>();
    if (hapBaseInfoParcel == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read hapBaseInfoParcel fail");
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
        return;
    }
    bool enable = data.ReadBool();
    int32_t res = this->SetPermDialogCap(*hapBaseInfoParcel, enable);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(res), "WriteInt32 failed.");
}

void AccessTokenManagerStub::GetPermissionManagerInfoInner(MessageParcel& data, MessageParcel& reply)
{
    PermissionGrantInfoParcel infoParcel;
    this->GetPermissionManagerInfo(infoParcel);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteParcelable(&infoParcel), "WriteParcelable failed.");
}

void AccessTokenManagerStub::InitUserPolicyInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingToken);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    std::vector<UserState> userList;
    std::vector<std::string> permList;
    uint32_t userSize = data.ReadUint32();
    uint32_t permSize = data.ReadUint32();
    if ((userSize > MAX_USER_POLICY_SIZE) || (permSize > MAX_USER_POLICY_SIZE)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Size %{public}u is invalid", userSize);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_OVERSIZE), "WriteParcelable failed.");
        return;
    }
    for (uint32_t i = 0; i < userSize; i++) {
        UserState userInfo;
        if (!data.ReadInt32(userInfo.userId)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to read userId.");
            IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
                reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
            return;
        }
        if (!data.ReadBool(userInfo.isActive)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to read isActive.");
            IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
                reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
            return;
        }
        userList.emplace_back(userInfo);
    }
    for (uint32_t i = 0; i < permSize; i++) {
        std::string permission;
        if (!data.ReadString(permission)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to read permission.");
            IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
                reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
            return;
        }
        permList.emplace_back(permission);
    }
    int32_t res = this->InitUserPolicy(userList, permList);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(res), "WriteInt32 failed.");
}

void AccessTokenManagerStub::UpdateUserPolicyInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingToken);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }
    std::vector<UserState> userList;
    uint32_t userSize = data.ReadUint32();
    if (userSize > MAX_USER_POLICY_SIZE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Size %{public}u is invalid", userSize);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(AccessTokenError::ERR_OVERSIZE), "WriteInt32 failed.");
        return;
    }
    for (uint32_t i = 0; i < userSize; i++) {
        UserState userInfo;
        if (!data.ReadInt32(userInfo.userId)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to read userId.");
            IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
                reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
            return;
        }
        if (!data.ReadBool(userInfo.isActive)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to read isActive.");
            IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
                reply.WriteInt32(AccessTokenError::ERR_READ_PARCEL_FAILED), "WriteInt32 failed.");
            return;
        }
        userList.emplace_back(userInfo);
    }
    int32_t res = this->UpdateUserPolicy(userList);
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(res), "WriteInt32 failed.");
}

void AccessTokenManagerStub::ClearUserPolicyInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingToken);
        IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG,
            reply.WriteInt32(AccessTokenError::ERR_PERMISSION_DENIED), "WriteInt32 failed.");
        return;
    }

    int32_t res = this->ClearUserPolicy();
    IF_FALSE_PRINT_LOG(ATM_DOMAIN, ATM_TAG, reply.WriteInt32(res), "WriteInt32 failed.");
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
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::SET_REMOTE_HAP_TOKEN_INFO)] =
        &AccessTokenManagerStub::SetRemoteHapTokenInfoInner;
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
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_HAP_TOKEN_ID)] =
        &AccessTokenManagerStub::GetHapTokenIDInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::ALLOC_LOCAL_TOKEN_ID)] =
        &AccessTokenManagerStub::AllocLocalTokenIDInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_NATIVE_TOKENINFO)] =
        &AccessTokenManagerStub::GetNativeTokenInfoInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_TOKEN_ID_BY_USER_ID)] =
        &AccessTokenManagerStub::GetTokenIDByUserIDInner;
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
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_PERMISSION_MANAGER_INFO)] =
        &AccessTokenManagerStub::GetPermissionManagerInfoInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::INIT_USER_POLICY)] =
        &AccessTokenManagerStub::InitUserPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::UPDATE_USER_POLICY)] =
        &AccessTokenManagerStub::UpdateUserPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::CLEAR_USER_POLICY)] =
        &AccessTokenManagerStub::ClearUserPolicyInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_HAP_TOKENINFO_EXT)] =
        &AccessTokenManagerStub::GetHapTokenInfoExtensionInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_KERNEL_PERMISSIONS)] =
        &AccessTokenManagerStub::GetKernelPermissionsInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_PERMISSION_BY_NAME)] =
        &AccessTokenManagerStub::GetReqPermissionByNameInner;
}

void AccessTokenManagerStub::SetPermissionOpFuncInMap()
{
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_USER_GRANTED_PERMISSION_USED_TYPE)] =
        &AccessTokenManagerStub::GetPermissionUsedTypeInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::VERIFY_ACCESSTOKEN)] =
        &AccessTokenManagerStub::VerifyAccessTokenInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::VERIFY_ACCESSTOKEN_WITH_LIST)] =
        &AccessTokenManagerStub::VerifyAccessTokenWithListInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_DEF_PERMISSION)] =
        &AccessTokenManagerStub::GetDefPermissionInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_REQ_PERMISSIONS)] =
        &AccessTokenManagerStub::GetReqPermissionsInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_PERMISSION_FLAG)] =
        &AccessTokenManagerStub::GetPermissionFlagInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GRANT_PERMISSION)] =
        &AccessTokenManagerStub::GrantPermissionInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::REVOKE_PERMISSION)] =
        &AccessTokenManagerStub::RevokePermissionInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GRANT_PERMISSION_FOR_SPECIFIEDTIME)] =
        &AccessTokenManagerStub::GrantPermissionForSpecifiedTimeInner;
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
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_VERSION)] =
        &AccessTokenManagerStub::GetVersionInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::SET_PERMISSION_REQUEST_TOGGLE_STATUS)] =
        &AccessTokenManagerStub::SetPermissionRequestToggleStatusInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::GET_PERMISSION_REQUEST_TOGGLE_STATUS)] =
        &AccessTokenManagerStub::GetPermissionRequestToggleStatusInner;
    requestFuncMap_[
        static_cast<uint32_t>(AccessTokenInterfaceCode::REGISTER_SELF_PERM_STATE_CHANGE_CALLBACK)] =
        &AccessTokenManagerStub::RegisterSelfPermStateChangeCallbackInner;
    requestFuncMap_[
        static_cast<uint32_t>(AccessTokenInterfaceCode::UNREGISTER_SELF_PERM_STATE_CHANGE_CALLBACK)] =
        &AccessTokenManagerStub::UnRegisterSelfPermStateChangeCallbackInner;
    requestFuncMap_[static_cast<uint32_t>(AccessTokenInterfaceCode::REQUEST_APP_PERM_ON_SETTING)] =
        &AccessTokenManagerStub::RequestAppPermOnSettingInner;
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
