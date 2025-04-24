/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "privacy_manager_stub.h"

#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "ipc_skeleton.h"
#include "memory_guard.h"
#include "on_permission_used_record_callback_proxy.h"
#include "privacy_error.h"
#include "privacy_manager_proxy_death_param.h"
#include "string_ex.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const uint32_t PERM_LIST_SIZE_MAX = 1024;
constexpr const char* PERMISSION_USED_STATS = "ohos.permission.PERMISSION_USED_STATS";
constexpr const char* PERMISSION_RECORD_TOGGLE = "ohos.permission.PERMISSION_RECORD_TOGGLE";
constexpr const char* SET_FOREGROUND_HAP_REMINDER = "ohos.permission.SET_FOREGROUND_HAP_REMINDER";
constexpr const char* SET_MUTE_POLICY = "ohos.permission.SET_MUTE_POLICY";
}

PrivacyManagerStub::PrivacyManagerStub()
{
    SetPrivacyFuncInMap();
}

void PrivacyManagerStub::SetPrivacyFuncInMap()
{
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::ADD_PERMISSION_USED_RECORD)] =
        &PrivacyManagerStub::AddPermissionUsedRecordInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::START_USING_PERMISSION)] =
        &PrivacyManagerStub::StartUsingPermissionInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::START_USING_PERMISSION_CALLBACK)] =
        &PrivacyManagerStub::StartUsingPermissionCallbackInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::STOP_USING_PERMISSION)] =
        &PrivacyManagerStub::StopUsingPermissionInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::DELETE_PERMISSION_USED_RECORDS)] =
        &PrivacyManagerStub::RemovePermissionUsedRecordsInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::GET_PERMISSION_USED_RECORDS)] =
        &PrivacyManagerStub::GetPermissionUsedRecordsInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::GET_PERMISSION_USED_RECORDS_ASYNC)] =
        &PrivacyManagerStub::GetPermissionUsedRecordsAsyncInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::REGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK)] =
        &PrivacyManagerStub::RegisterPermActiveStatusCallbackInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::UNREGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK)] =
        &PrivacyManagerStub::UnRegisterPermActiveStatusCallbackInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::IS_ALLOWED_USING_PERMISSION)] =
        &PrivacyManagerStub::IsAllowedUsingPermissionInner;
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::REGISTER_SEC_COMP_ENHANCE)] =
        &PrivacyManagerStub::RegisterSecCompEnhanceInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::UPDATE_SEC_COMP_ENHANCE)] =
        &PrivacyManagerStub::UpdateSecCompEnhanceInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::GET_SEC_COMP_ENHANCE)] =
        &PrivacyManagerStub::GetSecCompEnhanceInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::GET_SPECIAL_SEC_COMP_ENHANCE)] =
        &PrivacyManagerStub::GetSpecialSecCompEnhanceInner;
#endif
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::GET_PERMISSION_USED_TYPE_INFOS)] =
        &PrivacyManagerStub::GetPermissionUsedTypeInfosInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::SET_MUTE_POLICY)] =
        &PrivacyManagerStub::SetMutePolicyInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::SET_HAP_WITH_FOREGROUND_REMINDER)] =
        &PrivacyManagerStub::SetHapWithFGReminderInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::SET_PERMISSION_USED_RECORD_TOGGLE_STATUS)] =
        &PrivacyManagerStub::SetPermissionUsedRecordToggleStatusInner;
    requestMap_[static_cast<uint32_t>(PrivacyInterfaceCode::GET_PERMISSION_USED_RECORD_TOGGLE_STATUS)] =
        &PrivacyManagerStub::GetPermissionUsedRecordToggleStatusInner;
}
int32_t PrivacyManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    MemoryGuard cacheGuard;
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IPrivacyManager::GetDescriptor()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return ERROR_IPC_REQUEST_FAIL;
    }

    auto itFunc = requestMap_.find(code);
    if (itFunc != requestMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            (this->*requestFunc)(data, reply);
            return NO_ERROR;
        }
    }

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

void PrivacyManagerStub::AddPermissionUsedRecordInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    sptr<AddPermParamInfoParcel> infoParcel = data.ReadParcelable<AddPermParamInfoParcel>();
    if (infoParcel == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "ReadParcelable faild");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    reply.WriteInt32(this->AddPermissionUsedRecord(*infoParcel));
}

void PrivacyManagerStub::SetPermissionUsedRecordToggleStatusInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (!IsPrivilegedCalling() && !VerifyPermission(PERMISSION_RECORD_TOGGLE)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    int32_t userID = 0;
    if (!data.ReadInt32(userID)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to read userId.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    if (userID != 0 && !IsPrivilegedCalling()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "User version only get calling userID.");
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    bool status = true;
    if (!data.ReadBool(status)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to read status.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    reply.WriteInt32(this->SetPermissionUsedRecordToggleStatus(userID, status));
}

void PrivacyManagerStub::GetPermissionUsedRecordToggleStatusInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (!IsPrivilegedCalling() && !VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    int32_t userID = 0;
    if (!data.ReadInt32(userID)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to read userId.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    if (userID != 0 && !IsPrivilegedCalling()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "User version only get calling userID.");
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    bool status = true;
    reply.WriteInt32(this->GetPermissionUsedRecordToggleStatus(userID, status));
    reply.WriteBool(status);
}

void PrivacyManagerStub::StartUsingPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    sptr<PermissionUsedTypeInfoParcel> info = data.ReadParcelable<PermissionUsedTypeInfoParcel>();
    if (info == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Read parcel fail.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    sptr<IRemoteObject> anonyStub = data.ReadRemoteObject();
    if (anonyStub == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Read ReadRemoteObject fail.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    reply.WriteInt32(this->StartUsingPermission(*info, anonyStub));
}

void PrivacyManagerStub::StartUsingPermissionCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }

    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    sptr<PermissionUsedTypeInfoParcel> info = data.ReadParcelable<PermissionUsedTypeInfoParcel>();
    if (info == nullptr) {
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Read ReadRemoteObject fail");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    sptr<IRemoteObject> anonyStub = data.ReadRemoteObject();
    if (anonyStub == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Read ReadRemoteObject fail.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    reply.WriteInt32(this->StartUsingPermission(*info, callback, anonyStub));
}

void PrivacyManagerStub::StopUsingPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    AccessTokenID tokenId = data.ReadUint32();
    int32_t pid = data.ReadInt32();
    std::string permissionName = data.ReadString();
    reply.WriteInt32(this->StopUsingPermission(tokenId, pid, permissionName));
}

void PrivacyManagerStub::RemovePermissionUsedRecordsInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }

    if (!IsAccessTokenCalling() && !VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }

    AccessTokenID tokenId = data.ReadUint32();
    reply.WriteInt32(this->RemovePermissionUsedRecords(tokenId));
}

void PrivacyManagerStub::GetPermissionUsedRecordsInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }
    PermissionUsedResultParcel responseParcel;
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    sptr<PermissionUsedRequestParcel> requestParcel = data.ReadParcelable<PermissionUsedRequestParcel>();
    if (requestParcel == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "ReadParcelable faild");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    int32_t result = this->GetPermissionUsedRecords(*requestParcel, responseParcel);
    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        LOGE(PRI_DOMAIN, PRI_TAG, "WriteInt32 faild");
        return;
    }
    reply.WriteParcelable(&responseParcel);
}

void PrivacyManagerStub::GetPermissionUsedRecordsAsyncInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }

    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    sptr<PermissionUsedRequestParcel> requestParcel = data.ReadParcelable<PermissionUsedRequestParcel>();
    if (requestParcel == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "ReadParcelable failed");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    sptr<OnPermissionUsedRecordCallback> callback = new OnPermissionUsedRecordCallbackProxy(data.ReadRemoteObject());
    if (callback == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Callback is null");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    reply.WriteInt32(this->GetPermissionUsedRecords(*requestParcel, callback));
}

void PrivacyManagerStub::RegisterPermActiveStatusCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    uint32_t permListSize = data.ReadUint32();
    if (permListSize > PERM_LIST_SIZE_MAX) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Read permListSize fail");
        reply.WriteInt32(PrivacyError::ERR_OVERSIZE);
        return;
    }
    std::vector<std::string> permList;
    for (uint32_t i = 0; i < permListSize; i++) {
        std::string perm = data.ReadString();
        permList.emplace_back(perm);
    }
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Read ReadRemoteObject fail");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    reply.WriteInt32(this->RegisterPermActiveStatusCallback(permList, callback));
}

void PrivacyManagerStub::UnRegisterPermActiveStatusCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Read scopeParcel fail");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    reply.WriteInt32(this->UnRegisterPermActiveStatusCallback(callback));
}

void PrivacyManagerStub::IsAllowedUsingPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        reply.WriteBool(false);
        return;
    }

    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteBool(false);
        return;
    }

    AccessTokenID tokenId = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int32_t pid = data.ReadInt32();

    bool result = this->IsAllowedUsingPermission(tokenId, permissionName, pid);
    if (!reply.WriteBool(result)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to WriteBool(%{public}s)", permissionName.c_str());
        reply.WriteBool(false);
        return;
    }
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
void PrivacyManagerStub::RegisterSecCompEnhanceInner(MessageParcel& data, MessageParcel& reply)
{
    sptr<SecCompEnhanceDataParcel> requestParcel = data.ReadParcelable<SecCompEnhanceDataParcel>();
    if (requestParcel == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "ReadParcelable faild");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    reply.WriteInt32(this->RegisterSecCompEnhance(*requestParcel));
}

void PrivacyManagerStub::UpdateSecCompEnhanceInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsSecCompServiceCalling()) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }

    int32_t pid = data.ReadInt32();
    uint32_t seqNum = data.ReadUint32();
    reply.WriteInt32(this->UpdateSecCompEnhance(pid, seqNum));
}

void PrivacyManagerStub::GetSecCompEnhanceInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsSecCompServiceCalling()) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }

    int32_t pid = data.ReadInt32();
    SecCompEnhanceDataParcel parcel;
    int32_t result = this->GetSecCompEnhance(pid, parcel);
    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        return;
    }

    reply.WriteParcelable(&parcel);
}

void PrivacyManagerStub::GetSpecialSecCompEnhanceInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsSecCompServiceCalling()) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }

    std::string bundleName = data.ReadString();
    std::vector<SecCompEnhanceDataParcel> parcelList;
    int32_t result = this->GetSpecialSecCompEnhance(bundleName, parcelList);
    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        return;
    }
    reply.WriteUint32(parcelList.size());
    for (const auto& parcel : parcelList) {
        reply.WriteParcelable(&parcel);
    }
}

bool PrivacyManagerStub::IsSecCompServiceCalling()
{
    uint32_t tokenCaller = IPCSkeleton::GetCallingTokenID();
    if (secCompTokenId_ == 0) {
        secCompTokenId_ = AccessTokenKit::GetNativeTokenId("security_component_service");
    }
    return tokenCaller == secCompTokenId_;
}
#endif

void PrivacyManagerStub::GetPermissionUsedTypeInfosInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    AccessTokenID tokenId = data.ReadUint32();
    std::string permissionName = data.ReadString();
    std::vector<PermissionUsedTypeInfoParcel> resultsParcel;
    int32_t result = this->GetPermissionUsedTypeInfos(tokenId, permissionName, resultsParcel);
    if (!reply.WriteInt32(result)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to WriteInt32(%{public}d-%{public}s)", tokenId, permissionName.c_str());
        return;
    }
    reply.WriteUint32(resultsParcel.size());
    for (const auto& parcel : resultsParcel) {
        reply.WriteParcelable(&parcel);
    }
}

void PrivacyManagerStub::SetMutePolicyInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenTypeFlag(callingTokenID) != TOKEN_NATIVE) &&
        (AccessTokenKit::GetTokenTypeFlag(callingTokenID) != TOKEN_SHELL)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }

    if (!VerifyPermission(SET_MUTE_POLICY)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    uint32_t policyType;
    if (!data.ReadUint32(policyType)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to read policyType.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    uint32_t callerType;
    if (!data.ReadUint32(callerType)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to read callerType.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    bool isMute;
    if (!data.ReadBool(isMute)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to read isMute.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    uint32_t tokenID;
    if (!data.ReadUint32(tokenID)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to read tokenID.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }

    int32_t result = this->SetMutePolicy(policyType, callerType, isMute, tokenID);
    if (!reply.WriteInt32(result)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to WriteInt32.");
        return;
    }
}

void PrivacyManagerStub::SetHapWithFGReminderInner(MessageParcel& data, MessageParcel& reply)
{
    if (!VerifyPermission(SET_FOREGROUND_HAP_REMINDER)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    uint32_t tokenId;
    if (!data.ReadUint32(tokenId)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to read tokenId.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    bool isAllowed;
    if (!data.ReadBool(isAllowed)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to read isAllowed.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }

    int32_t result = this->SetHapWithFGReminder(tokenId, isAllowed);
    if (!reply.WriteInt32(result)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to WriteInt32.");
        return;
    }
}

bool PrivacyManagerStub::IsPrivilegedCalling() const
{
    // shell process is root in debug mode.
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ROOT_UID;
#else
    return false;
#endif
}

bool PrivacyManagerStub::IsAccessTokenCalling() const
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ACCESSTOKEN_UID;
}

bool PrivacyManagerStub::IsSystemAppCalling() const
{
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    return TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
}

bool PrivacyManagerStub::VerifyPermission(const std::string& permission) const
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::VerifyAccessToken(callingTokenID, permission) == PERMISSION_DENIED) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Permission denied(callingTokenID=%{public}d)", callingTokenID);
        return false;
    }
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
