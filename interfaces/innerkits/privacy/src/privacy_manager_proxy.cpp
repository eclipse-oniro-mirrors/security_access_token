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

#include "privacy_manager_proxy.h"

#include "accesstoken_log.h"
#include "privacy_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyManagerProxy"
};
}

PrivacyManagerProxy::PrivacyManagerProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IPrivacyManager>(impl) {
}

PrivacyManagerProxy::~PrivacyManagerProxy()
{}

int32_t PrivacyManagerProxy::AddPermissionUsedRecord(AccessTokenID tokenID, const std::string& permissionName,
    int32_t successCount, int32_t failCount)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(%{public}d)", tokenID);
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteString(permissionName)");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteInt32(successCount)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(successCount)");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteInt32(failCount)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(failCount)");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(IPrivacyManager::InterfaceCode::ADD_PERMISSION_USED_RECORD, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    return reply.ReadInt32();
}

int32_t PrivacyManagerProxy::StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(%{public}d)", tokenID);
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteString(permissionName)");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(IPrivacyManager::InterfaceCode::START_USING_PERMISSION, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    return reply.ReadInt32();
}

int32_t PrivacyManagerProxy::StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName,
    const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(%{public}d)", tokenID);
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteString(permissionName)");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write remote object.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(IPrivacyManager::InterfaceCode::START_USING_PERMISSION_CALLBACK, data, reply)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest fail");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t ret = reply.ReadInt32();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "get result from server data = %{public}d", ret);
    return ret;
}

int32_t PrivacyManagerProxy::StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(%{public}d)", tokenID);
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteString(permissionName)");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(IPrivacyManager::InterfaceCode::STOP_USING_PERMISSION, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    return reply.ReadInt32();
}

int32_t PrivacyManagerProxy::RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(%{public}d)", tokenID);
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteString(deviceID)");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(IPrivacyManager::InterfaceCode::DELETE_PERMISSION_USED_RECORDS, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    return reply.ReadInt32();
}

int32_t PrivacyManagerProxy::GetPermissionUsedRecords(const PermissionUsedRequestParcel& request,
    PermissionUsedResultParcel& result)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!data.WriteParcelable(&request)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteParcelable(request)");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(IPrivacyManager::InterfaceCode::GET_PERMISSION_USED_RECORDS, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t ret = reply.ReadInt32();
    if (ret != RET_SUCCESS) {
        return ret;
    }
    sptr<PermissionUsedResultParcel> resultSptr = reply.ReadParcelable<PermissionUsedResultParcel>();
    if (resultSptr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable fail");
        return PrivacyError::ERR_READ_PARCEL_FAILED;
    }
    result = *resultSptr;
    return ret;
}

int32_t PrivacyManagerProxy::GetPermissionUsedRecords(const PermissionUsedRequestParcel& request,
    const sptr<OnPermissionUsedRecordCallback>& callback)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!data.WriteParcelable(&request)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteParcelable(request)");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteRemoteObject(callback)");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(IPrivacyManager::InterfaceCode::GET_PERMISSION_USED_RECORDS_ASYNC, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    return reply.ReadInt32();
}

int32_t PrivacyManagerProxy::RegisterPermActiveStatusCallback(
    std::vector<std::string>& permList, const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    uint32_t listSize = permList.size();
    if (!data.WriteUint32(listSize)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write listSize");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    for (uint32_t i = 0; i < listSize; i++) {
        if (!data.WriteString(permList[i])) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permList[%{public}d], %{public}s", i, permList[i].c_str());
            return PrivacyError::ERR_WRITE_PARCEL_FAILED;
        }
    }

    if (!data.WriteRemoteObject(callback)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write remote object.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    MessageParcel reply;
    if (!SendRequest(IPrivacyManager::InterfaceCode::REGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    return reply.ReadInt32();
}

int32_t PrivacyManagerProxy::UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write remote object.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    MessageParcel reply;
    if (!SendRequest(IPrivacyManager::InterfaceCode::UNREGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    return reply.ReadInt32();
}

bool PrivacyManagerProxy::IsAllowedUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return false;
    }
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(%{public}d)", tokenID);
        return false;
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteString(%{public}s)", permissionName.c_str());
        return false;
    }
    if (!SendRequest(IPrivacyManager::InterfaceCode::IS_ALLOWED_USING_PERMISSION, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    return reply.ReadBool();
}

bool PrivacyManagerProxy::SendRequest(
    IPrivacyManager::InterfaceCode code, MessageParcel& data, MessageParcel& reply)
{
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remote service null.");
        return false;
    }

    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest fail, result: %{public}d", result);
        return false;
    }
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
