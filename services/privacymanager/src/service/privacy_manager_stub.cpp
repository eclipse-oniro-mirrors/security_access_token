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
#include "accesstoken_log.h"
#include "ipc_skeleton.h"
#include "memory_guard.h"
#include "privacy_error.h"
#include "string_ex.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyManagerStub"
};
static const uint32_t PERM_LIST_SIZE_MAX = 1024;
static const std::string PERMISSION_USED_STATS = "ohos.permission.PERMISSION_USED_STATS";
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
}
int32_t PrivacyManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    MemoryGuard cacheGuard;
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IPrivacyManager::GetDescriptor()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
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
    if ((AccessTokenKit::GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    sptr<AddPermParamInfoParcel> infoParcel = data.ReadParcelable<AddPermParamInfoParcel>();
    if (infoParcel == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable faild");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    int32_t result = this->AddPermissionUsedRecord(*infoParcel);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::StartUsingPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    AccessTokenID tokenId = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int32_t result = this->StartUsingPermission(tokenId, permissionName);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::StartUsingPermissionCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    AccessTokenID tokenId = data.ReadUint32();
    std::string permissionName = data.ReadString();
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "read ReadRemoteObject fail");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    int32_t result = this->StartUsingPermission(tokenId, permissionName, callback);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::StopUsingPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    AccessTokenID tokenId = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int32_t result = this->StopUsingPermission(tokenId, permissionName);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::RemovePermissionUsedRecordsInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsAccessTokenCalling() && !VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }

    AccessTokenID tokenId = data.ReadUint32();
    std::string deviceID = data.ReadString();
    int32_t result = this->RemovePermissionUsedRecords(tokenId, deviceID);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::GetPermissionUsedRecordsInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable faild");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    int32_t result = this->GetPermissionUsedRecords(*requestParcel, responseParcel);
    reply.WriteInt32(result);
    reply.WriteParcelable(&responseParcel);
}

void PrivacyManagerStub::GetPermissionUsedRecordsAsyncInner(MessageParcel& data, MessageParcel& reply)
{
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    sptr<PermissionUsedRequestParcel> requestParcel = data.ReadParcelable<PermissionUsedRequestParcel>();
    if (requestParcel == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable failed");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    sptr<OnPermissionUsedRecordCallback> callback = iface_cast<OnPermissionUsedRecordCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback is null");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    int32_t result = this->GetPermissionUsedRecords(*requestParcel, callback);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::RegisterPermActiveStatusCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    uint32_t permListSize = data.ReadUint32();
    if (permListSize > PERM_LIST_SIZE_MAX) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "read permListSize fail");
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "read ReadRemoteObject fail");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    int32_t result = this->RegisterPermActiveStatusCallback(permList, callback);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::UnRegisterPermActiveStatusCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((AccessTokenKit::GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        reply.WriteInt32(PrivacyError::ERR_NOT_SYSTEM_APP);
        return;
    }
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "read scopeParcel fail");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }

    int32_t result = this->UnRegisterPermActiveStatusCallback(callback);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::IsAllowedUsingPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteBool(false);
        return;
    }
    AccessTokenID tokenId = data.ReadUint32();

    std::string permissionName = data.ReadString();
    bool result = this->IsAllowedUsingPermission(tokenId, permissionName);
    if (!reply.WriteBool(result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteBool(%{public}s)", permissionName.c_str());
        return;
    }
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
bool PrivacyManagerStub::HandleSecCompReq(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    switch (code) {
        case static_cast<uint32_t>(PrivacyInterfaceCode::REGISTER_SEC_COMP_ENHANCE):
            RegisterSecCompEnhanceInner(data, reply);
            break;
        case static_cast<uint32_t>(PrivacyInterfaceCode::UPDATE_SEC_COMP_ENHANCE):
            UpdateSecCompEnhanceInner(data, reply);
            break;
        case static_cast<uint32_t>(PrivacyInterfaceCode::GET_SEC_COMP_ENHANCE):
            GetSecCompEnhanceInner(data, reply);
            break;
        case static_cast<uint32_t>(PrivacyInterfaceCode::GET_SPECIAL_SEC_COMP_ENHANCE):
            GetSpecialSecCompEnhanceInner(data, reply);
            break;
        default:
            return false;
    }
    return true;
}

void PrivacyManagerStub::RegisterSecCompEnhanceInner(MessageParcel& data, MessageParcel& reply)
{
    sptr<SecCompEnhanceDataParcel> requestParcel = data.ReadParcelable<SecCompEnhanceDataParcel>();
    if (requestParcel == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable faild");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    int32_t result = this->RegisterSecCompEnhance(*requestParcel);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::UpdateSecCompEnhanceInner(MessageParcel& data, MessageParcel& reply)
{
    if (!IsSecCompServiceCalling()) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }

    int32_t pid = data.ReadInt32();
    
    int32_t seqNum = data.ReadInt32();

    int32_t result = this->UpdateSecCompEnhance(pid, seqNum);
    reply.WriteInt32(result);
    if (result != RET_SUCCESS) {
        return;
    }
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteInt32(%{public}d-%{public}s)", tokenId, permissionName.c_str());
        return;
    }
    reply.WriteUint32(resultsParcel.size());
    for (const auto& parcel : resultsParcel) {
        reply.WriteParcelable(&parcel);
    }
}

void PrivacyManagerStub::SetMutePolicyInner(MessageParcel& data, MessageParcel& reply)
{
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    uint32_t policyType;
    if (!data.ReadUint32(policyType)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to read policyType.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    uint32_t callerType;
    if (!data.ReadUint32(callerType)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to read callerType.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    bool isMute;
    if (!data.ReadBool(isMute)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to read isMute.");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }

    int32_t result = this->SetMutePolicy(policyType, callerType, isMute);
    if (!reply.WriteInt32(result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteInt32.");
        return;
    }
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission denied(callingTokenID=%{public}d)", callingTokenID);
        return false;
    }
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
