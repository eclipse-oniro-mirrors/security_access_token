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

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyManagerProxy"
};
}

const static int32_t ERROR = -1;

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
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(%{public}d)",tokenID);
        return ERROR;
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteString(permissionName)");
        return ERROR;
    }
    if (!data.WriteInt32(successCount)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(successCount)");
        return ERROR;
    }
    if (!data.WriteInt32(failCount)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(failCount)");
        return ERROR;
    }

    MessageParcel reply;
    int32_t requestResult = SendRequest(IPrivacyManager::InterfaceCode::ADD_PERMISSION_USED_RECORD, data, reply);
    if (!requestResult) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "add result fail, result: %{public}d", requestResult);
    }
    int32_t ret = reply.ReadInt32();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "get result from server data = %{public}d", ret);
    return ret;
}

int32_t PrivacyManagerProxy::StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(%{public}d)",tokenID);
        return ERROR;
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteString(permissionName)");
        return ERROR;
    }

    MessageParcel reply;
    int32_t requestResult = SendRequest(IPrivacyManager::InterfaceCode::START_USING_PERMISSION, data, reply);
    if (!requestResult) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "add result fail, result: %{public}d", requestResult);
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(%{public}d)",tokenID);
        return ERROR;
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteString(permissionName)");
        return ERROR;
    }

    MessageParcel reply;
    int32_t requestResult = SendRequest(IPrivacyManager::InterfaceCode::STOP_USING_PERMISSION, data, reply);
    if (!requestResult) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "add result fail, result: %{public}d", requestResult);
    }
    int32_t ret = reply.ReadInt32();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "get result from server data = %{public}d", ret);
    return ret;
}

int32_t PrivacyManagerProxy::RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(%{public}d)",tokenID);
        return ERROR;
    }
    if (!data.WriteString(deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteString(deviceID)");
        return ERROR;
    }

    MessageParcel reply;
    int32_t requestResult = SendRequest(IPrivacyManager::InterfaceCode::DELETE_PERMISSION_USED_RECORDS, data, reply);
    if (!requestResult) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "add result fail, result: %{public}d", requestResult);
    }
    int32_t ret = reply.ReadInt32();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "get result from server data = %{public}d", ret);
    return ret;
}

int32_t PrivacyManagerProxy::GetPermissionUsedRecords(const PermissionUsedRequestParcel& request,
    PermissionUsedResultParcel& result)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!data.WriteParcelable(&request)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteParcelable(request)");
        return ERROR;
    }

    MessageParcel reply;
    int32_t requestResult = SendRequest(IPrivacyManager::InterfaceCode::GET_PERMISSION_USED_RECORDS, data, reply);
    if (!requestResult) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "send request fail, result: %{public}d", requestResult);
        return ERROR;
    }

    sptr<PermissionUsedResultParcel> resultSptr = reply.ReadParcelable<PermissionUsedResultParcel>();
    if (resultSptr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable fail");
        return ERROR;
    }
    result = *resultSptr;
    int32_t ret = reply.ReadInt32();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "get result from server data = %{public}d", ret);
    return ret;
}

int32_t PrivacyManagerProxy::GetPermissionUsedRecords(const PermissionUsedRequestParcel& request,
    const sptr<OnPermissionUsedRecordCallback>& callback)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!data.WriteParcelable(&request)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteParcelable(request)");
        return ERROR;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteRemoteObject(callback)");
        return ERROR;
    }

    MessageParcel reply;
    int32_t requestResult = SendRequest(IPrivacyManager::InterfaceCode::GET_PERMISSION_USED_RECORDS_ASYNC, data, reply);
    if (!requestResult) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "send request fail, result: %{public}d", requestResult);
        return ERROR;
    }
    int32_t ret = reply.ReadInt32();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "get result from server data = %{public}d", ret);
    return ret;
}

std::string PrivacyManagerProxy::DumpRecordInfo(AccessTokenID tokenID, const std::string& permissionName)
{
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(%{public}d)",tokenID);
        return "";
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteString(%{public}s)", permissionName.c_str());
        return "";
    }
    int32_t requestResult = SendRequest(IPrivacyManager::InterfaceCode::DUMP_RECORD_INFO, data, reply);
    if (!requestResult) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "send request fail, result: %{public}d", requestResult);
        return "";
    }
    std::string dumpInfo = reply.ReadString();
    return dumpInfo;
}

int32_t PrivacyManagerProxy::RegisterPermActiveStatusCallback(
    std::vector<std::string>& permList, const sptr<IRemoteObject>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return ERROR;
    }

    uint32_t listSize = permList.size();
    if (!data.WriteUint32(listSize)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write listSize");
        return ERROR;
    }
    for (uint32_t i = 0; i < listSize; i++) {
        if (!data.WriteString(permList[i])) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permList[%{public}d], %{public}s", i, permList[i].c_str());
            return ERROR;
        }
    }

    if (!data.WriteRemoteObject(callback)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write remote object.");
        return ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remote service null.");
        return ERROR;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IPrivacyManager::InterfaceCode::REGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK),
        data, reply, option);
    if (requestResult != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "request fail, result: %{public}d.", requestResult);
        return ERROR;
    }

    int32_t result;
    if (!reply.ReadInt32(result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 fail");
        return ERROR;
    }
    return result;
}

int32_t PrivacyManagerProxy::UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return ERROR;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write remote object.");
        return ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remote service null.");
        return ERROR;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IPrivacyManager::InterfaceCode::UNREGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK),
        data, reply, option);
    if (requestResult != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "request fail, result: %{public}d.", requestResult);
        return ERROR;
    }

    int32_t result;
    if (!reply.ReadInt32(result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 fail");
        return ERROR;
    }
    return result;
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
