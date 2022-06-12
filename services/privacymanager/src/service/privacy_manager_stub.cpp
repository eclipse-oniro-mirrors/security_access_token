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

#include "privacy_manager_stub.h"

#include "accesstoken_kit.h"
#include "accesstoken_log.h"

#include "ipc_skeleton.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyManagerStub"
};
}

int32_t PrivacyManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IPrivacyManager::GetDescriptor()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return -1;
    }
    switch (code) {
        case static_cast<uint32_t>(IPrivacyManager::InterfaceCode::ADD_PERMISSION_USED_RECORD):
            AddPermissionUsedRecordInner(data, reply);
            break;
        case static_cast<uint32_t>(IPrivacyManager::InterfaceCode::START_USING_PERMISSION):
            StartUsingPermissionInner(data, reply);
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
        case static_cast<uint32_t>(IPrivacyManager::InterfaceCode::DUMP_RECORD_INFO):
            DumpRecordInfoInner(data, reply);
            break;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return NO_ERROR;
}

void PrivacyManagerStub::AddPermissionUsedRecordInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::VerifyAccessToken(
        callingTokenID, "ohos.permission.PERMISSION_USED_STATS") == PERMISSION_DENIED) {
        ACCESSTOKEN_LOG_INFO(LABEL, "permission denied");
        reply.WriteInt32(RET_FAILED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int32_t successCount = data.ReadInt32();
    int32_t failCount = data.ReadInt32();
    int32_t result = this->AddPermissionUsedRecord(tokenID, permissionName, successCount, failCount);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::StartUsingPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int32_t result = this->StartUsingPermission(tokenID, permissionName);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::StopUsingPermissionInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int32_t result = this->StopUsingPermission(tokenID, permissionName);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::RemovePermissionUsedRecordsInner(MessageParcel& data, MessageParcel& reply)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsAccessTokenCalling() || AccessTokenKit::VerifyAccessToken(
        callingTokenID, "ohos.permission.PERMISSION_USED_STATS") == PERMISSION_DENIED) {
        ACCESSTOKEN_LOG_INFO(LABEL, "permission denied");
        reply.WriteInt32(RET_FAILED);
        return;
    }
    AccessTokenID tokenID = data.ReadUint32();
    std::string deviceID = data.ReadString();
    int32_t result = this->RemovePermissionUsedRecords(tokenID, deviceID);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::GetPermissionUsedRecordsInner(MessageParcel& data, MessageParcel& reply)
{
    PermissionUsedResultParcel responseParcel;
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::VerifyAccessToken(
        callingTokenID, "ohos.permission.PERMISSION_USED_STATS") == PERMISSION_DENIED) {
        ACCESSTOKEN_LOG_INFO(LABEL, "permission denied");
        reply.WriteParcelable(&responseParcel);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    sptr<PermissionUsedRequestParcel> requestParcel = data.ReadParcelable<PermissionUsedRequestParcel>();
    if (requestParcel == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable faild");
        reply.WriteParcelable(&responseParcel);
        reply.WriteInt32(RET_FAILED);
        return;
    }
    int32_t result = this->GetPermissionUsedRecords(*requestParcel, responseParcel);
    reply.WriteParcelable(&responseParcel);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::GetPermissionUsedRecordsAsyncInner(MessageParcel& data, MessageParcel& reply)
{
    sptr<PermissionUsedRequestParcel> requestParcel = data.ReadParcelable<PermissionUsedRequestParcel>();
    if (requestParcel == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable faild");
        reply.WriteInt32(RET_FAILED);
        return;
    }
    sptr<OnPermissionUsedRecordCallback> callback = iface_cast<OnPermissionUsedRecordCallback>(data.ReadRemoteObject());
    int32_t result = this->GetPermissionUsedRecords(*requestParcel, callback);
    reply.WriteInt32(result);
}

void PrivacyManagerStub::DumpRecordInfoInner(MessageParcel& data, MessageParcel& reply)
{
    std::string bundleName = data.ReadString();
    std::string permissionName = data.ReadString();
    std::string dumpInfo = this->DumpRecordInfo(bundleName, permissionName);
    reply.WriteString(dumpInfo);
}

bool PrivacyManagerStub::IsAccessTokenCalling() const
{
    int callingUid = IPCSkeleton::GetCallingTokenID();
    return callingUid == ACCESSTOKEN_UID;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
