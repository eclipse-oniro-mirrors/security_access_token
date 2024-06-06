/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
static const int MAX_SEC_COMP_ENHANCE_SIZE = 1000;
#endif
// if change this, copy value in privacy_kit_test.cpp should change together
static const uint32_t MAX_PERMISSION_USED_TYPE_SIZE = 2000;
}

PrivacyManagerProxy::PrivacyManagerProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IPrivacyManager>(impl) {
}

PrivacyManagerProxy::~PrivacyManagerProxy()
{}

int32_t PrivacyManagerProxy::AddPermissionUsedRecord(const AddPermParamInfoParcel& infoParcel, bool asyncMode)
{
    MessageParcel addData;
    addData.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!addData.WriteParcelable(&infoParcel)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteParcelable(infoParcel)");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(PrivacyInterfaceCode::ADD_PERMISSION_USED_RECORD, addData, reply, asyncMode)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

int32_t PrivacyManagerProxy::StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    MessageParcel startData;
    startData.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!startData.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!startData.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permissionName");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(PrivacyInterfaceCode::START_USING_PERMISSION, startData, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

int32_t PrivacyManagerProxy::StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName,
    const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permissionName");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write remote object.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(PrivacyInterfaceCode::START_USING_PERMISSION_CALLBACK, data, reply)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest fail");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

int32_t PrivacyManagerProxy::StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    MessageParcel stopData;
    stopData.WriteInterfaceToken(IPrivacyManager::GetDescriptor());
    if (!stopData.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!stopData.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permissionName");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(PrivacyInterfaceCode::STOP_USING_PERMISSION, stopData, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
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
    if (!SendRequest(PrivacyInterfaceCode::DELETE_PERMISSION_USED_RECORDS, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
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
    if (!SendRequest(PrivacyInterfaceCode::GET_PERMISSION_USED_RECORDS, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t ret = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", ret);
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
    if (!SendRequest(PrivacyInterfaceCode::GET_PERMISSION_USED_RECORDS_ASYNC, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
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
    if (!SendRequest(PrivacyInterfaceCode::REGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
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
    if (!SendRequest(
        PrivacyInterfaceCode::UNREGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
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
    if (!SendRequest(PrivacyInterfaceCode::IS_ALLOWED_USING_PERMISSION, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    bool result = reply.ReadBool();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
int32_t PrivacyManagerProxy::RegisterSecCompEnhance(const SecCompEnhanceDataParcel& enhance)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteParcelable(&enhance)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write parcel.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    if (!SendRequest(PrivacyInterfaceCode::REGISTER_SEC_COMP_ENHANCE, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

int32_t PrivacyManagerProxy::UpdateSecCompEnhance(int32_t pid, int32_t seqNum)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write GetDescriptor.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteInt32(pid)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write pid=%{public}d.", pid);
        return false;
    }
    if (!data.WriteInt32(seqNum)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write seqNum=%{public}d.", seqNum);
        return false;
    }
    if (!SendRequest(PrivacyInterfaceCode::UPDATE_SEC_COMP_ENHANCE, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "Result=%{public}d", result);
    return result;
}

int32_t PrivacyManagerProxy::GetSecCompEnhance(int32_t pid, SecCompEnhanceDataParcel& enhanceParcel)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteInt32(pid)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteInt32(%{public}d)", pid);
        return false;
    }
    if (!SendRequest(PrivacyInterfaceCode::GET_SEC_COMP_ENHANCE, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }

    sptr<SecCompEnhanceDataParcel> parcel = reply.ReadParcelable<SecCompEnhanceDataParcel>();
    if (parcel != nullptr) {
        enhanceParcel = *parcel;
    }
    return result;
}

int32_t PrivacyManagerProxy::GetSpecialSecCompEnhance(const std::string& bundleName,
    std::vector<SecCompEnhanceDataParcel>& enhanceParcelList)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteString(bundleName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write string.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    if (!SendRequest(PrivacyInterfaceCode::GET_SPECIAL_SEC_COMP_ENHANCE, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }

    uint32_t size = reply.ReadUint32();
    if (size > MAX_SEC_COMP_ENHANCE_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "size = %{public}d get from request is invalid", size);
        return PrivacyError::ERR_OVERSIZE;
    }
    for (uint32_t i = 0; i < size; i++) {
        sptr<SecCompEnhanceDataParcel> parcel = reply.ReadParcelable<SecCompEnhanceDataParcel>();
        if (parcel != nullptr) {
            enhanceParcelList.emplace_back(*parcel);
        }
    }
    return result;
}
#endif

int32_t PrivacyManagerProxy::GetPermissionUsedTypeInfos(const AccessTokenID tokenId, const std::string& permissionName,
    std::vector<PermissionUsedTypeInfoParcel>& resultsParcel)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(tokenId)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(%{public}d)", tokenId);
        return false;
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteString(%{public}s)", permissionName.c_str());
        return false;
    }

    if (!SendRequest(PrivacyInterfaceCode::GET_PERMISSION_USED_TYPE_INFOS, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server is %{public}d.", result);
    if (result != RET_SUCCESS) {
        return result;
    }

    uint32_t size = reply.ReadUint32();
    if (size > MAX_PERMISSION_USED_TYPE_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed, results oversize %{public}d, please add query params!", size);
        return PrivacyError::ERR_OVERSIZE;
    }
    for (uint32_t i = 0; i < size; i++) {
        sptr<PermissionUsedTypeInfoParcel> parcel = reply.ReadParcelable<PermissionUsedTypeInfoParcel>();
        if (parcel != nullptr) {
            resultsParcel.emplace_back(*parcel);
        }
    }
    return result;
}

int32_t PrivacyManagerProxy::SetMutePolicy(uint32_t policyType, uint32_t callerType, bool isMute)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteUint32(policyType)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(%{public}d)", policyType);
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(callerType)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteUint32(%{public}d)", callerType);
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteBool(isMute)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteBool(%{public}d)", isMute);
        return PrivacyError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!SendRequest(PrivacyInterfaceCode::SET_MUTE_POLICY, data, reply)) {
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server is %{public}d.", result);
    return result;
}

bool PrivacyManagerProxy::SendRequest(
    PrivacyInterfaceCode code, MessageParcel& data, MessageParcel& reply, bool asyncMode)
{
    int flag = 0;
    if (asyncMode) {
        flag = static_cast<int>(MessageOption::TF_ASYNC);
    } else {
        flag = static_cast<int>(MessageOption::TF_SYNC);
    }
    MessageOption option(flag);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remote service null.");
        return false;
    }

    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest(code=%{public}d) fail, result: %{public}d", code, result);
        return false;
    }
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
