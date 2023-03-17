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

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyManagerStub"
};
static const uint32_t PERM_LIST_SIZE_MAX = 1024;
static const int32_t ERROR = -1;
static const std::string PERMISSION_USED_STATS = "ohos.permission.PERMISSION_USED_STATS";
}

int32_t PrivacyManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    MemoryGuard cacheGuard;
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IPrivacyManager::GetDescriptor()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return ERROR;
    }
    switch (code) {
        case static_cast<uint32_t>(IPrivacyManager::InterfaceCode::ADD_PERMISSION_USED_RECORD):
            AddPermissionUsedRecordInner(data, reply);
            break;
        case static_cast<uint32_t>(IPrivacyManager::InterfaceCode::START_USING_PERMISSION):
            StartUsingPermissionInner(data, reply);
            break;
        case static_cast<uint32_t>(IPrivacyManager::InterfaceCode::START_USING_PERMISSION_CALLBACK):
            StartUsingPermissionCallbackInner(data, reply);
            break;
        case static_cast<uint32_t>(IPrivacyManager::InterfaceCode::STOP_USING_PERMISSION):
            StopUsingPermissionInner(data, reply);
            break;
        case static_cast<uint32_t>(IPrivacyManager::InterfaceCode::DELETE_PERMISSION_USED_RECORDS):
            RemovePermissionUsedRecordsInner(data, reply);
            break;
        case static_cast<uint32_t>(IPrivacyManager::InterfaceCode::GET_PERMISSION_USED_RECORDS):
            GetPermissionUsedRecordsInner(data, reply);
            break;
        case static_cast<uint32_t>(IPrivacyManager::InterfaceCode::GET_PERMISSION_USED_RECORDS_ASYNC):
            GetPermissionUsedRecordsAsyncInner(data, reply);
            break;
        case static_cast<uint32_t>(IPrivacyManager::InterfaceCode::REGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK):
            RegisterPermActiveStatusCallbackInner(data, reply);
            break;
        case static_cast<uint32_t>(IPrivacyManager::InterfaceCode::UNREGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK):
            UnRegisterPermActiveStatusCallbackInner(data, reply);
            break;
        case static_cast<uint32_t>(IPrivacyManager::InterfaceCode::IS_ALLOWED_USING_PERMISSION):
            IsAllowedUsingPermissionInner(data, reply);
            break;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return NO_ERROR;
}

void PrivacyManagerStub::AddPermissionUsedRecordInner(MessageParcel& data, MessageParcel& reply)
{
    if (!VerifyPermission(PERMISSION_USED_STATS)) {
        reply.WriteInt32(PrivacyError::ERR_PERMISSION_DENIED);
        return;
    }
    AccessTokenID tokenId = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int32_t successCount = data.ReadInt32();
    int32_t failCount = data.ReadInt32();
    int32_t result = this->AddPermissionUsedRecord(tokenId, permissionName, successCount, failCount);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::StartUsingPermissionInner(MessageParcel& data, MessageParcel& reply)
{
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable faild");
        reply.WriteInt32(PrivacyError::ERR_READ_PARCEL_FAILED);
        return;
    }
    sptr<OnPermissionUsedRecordCallback> callback = iface_cast<OnPermissionUsedRecordCallback>(data.ReadRemoteObject());
    int32_t result = this->GetPermissionUsedRecords(*requestParcel, callback);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::RegisterPermActiveStatusCallbackInner(MessageParcel& data, MessageParcel& reply)
{
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

bool PrivacyManagerStub::IsAccessTokenCalling() const
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ACCESSTOKEN_UID;
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
