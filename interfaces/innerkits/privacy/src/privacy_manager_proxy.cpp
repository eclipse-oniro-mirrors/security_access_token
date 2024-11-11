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
#include "parcel_utils.h"
#include "privacy_error.h"
#include "securec.h"

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

int32_t PrivacyManagerProxy::AddPermissionUsedRecord(const AddPermParamInfo& info, bool asyncMode)
{
    MessageParcel data;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(info.tokenId), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(
        LABEL, data.WriteString(info.permissionName), ERR_WRITE_PARCEL_FAILED, "WriteString failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInt32(info.successCount), ERR_WRITE_PARCEL_FAILED, "WriteInt32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInt32(info.failCount), ERR_WRITE_PARCEL_FAILED, "WriteInt32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(info.type), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");

    MessageParcel reply;
    if (!SendRequest(PrivacyInterfaceCode::ADD_PERMISSION_USED_RECORD, data, reply, asyncMode)) {
        return ERR_SERVICE_ABNORMAL;
    }
    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", result);
    return result;
}

int32_t PrivacyManagerProxy::StartUsingPermission(
    AccessTokenID tokenID, int32_t pid, const std::string& permissionName)
{
    MessageParcel data;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(tokenID), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(pid), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteString(permissionName), ERR_WRITE_PARCEL_FAILED, "WriteString failed.");

    MessageParcel reply;
    if (!SendRequest(PrivacyInterfaceCode::START_USING_PERMISSION, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", result);
    return result;
}

int32_t PrivacyManagerProxy::StartUsingPermission(
    AccessTokenID tokenID, int32_t pid, const std::string& permissionName,
    const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(tokenID), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(pid), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteString(permissionName), ERR_WRITE_PARCEL_FAILED, "WriteString failed.");
    IF_FALSE_RETURN_VAL_LOG(
        LABEL, data.WriteRemoteObject(callback), ERR_WRITE_PARCEL_FAILED, "WriteRemoteObject failed.");

    MessageParcel reply;
    if (!SendRequest(PrivacyInterfaceCode::START_USING_PERMISSION_CALLBACK, data, reply)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest fail");
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", result);
    return result;
}

int32_t PrivacyManagerProxy::StopUsingPermission(
    AccessTokenID tokenID, int32_t pid, const std::string& permissionName)
{
    MessageParcel data;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(tokenID), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(pid), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteString(permissionName), ERR_WRITE_PARCEL_FAILED, "WriteString failed.");

    MessageParcel reply;
    if (!SendRequest(PrivacyInterfaceCode::STOP_USING_PERMISSION, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", result);
    return result;
}

int32_t PrivacyManagerProxy::RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID)
{
    MessageParcel data;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(tokenID), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteString(deviceID), ERR_WRITE_PARCEL_FAILED, "WriteString failed.");

    MessageParcel reply;
    if (!SendRequest(PrivacyInterfaceCode::DELETE_PERMISSION_USED_RECORDS, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", result);
    return result;
}

int32_t PrivacyManagerProxy::GetPermissionUsedRecords(const PermissionUsedRequest& request,
    PermissionUsedResultParcel& result)
{
    MessageParcel data;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(request.tokenId), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteBool(request.isRemote), ERR_WRITE_PARCEL_FAILED, "WriteBool failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteString(request.deviceId), ERR_WRITE_PARCEL_FAILED, "WriteString failed.");
    IF_FALSE_RETURN_VAL_LOG(
        LABEL, data.WriteString(request.bundleName), ERR_WRITE_PARCEL_FAILED, "WriteString failed.");

    IF_FALSE_RETURN_VAL_LOG(LABEL,
        data.WriteUint32(request.permissionList.size()), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    for (const auto& perm : request.permissionList) {
        IF_FALSE_RETURN_VAL_LOG(
            LABEL, data.WriteString(perm), ERR_WRITE_PARCEL_FAILED, "WriteString(%{public}s) failed.", perm.c_str());
    }
    IF_FALSE_RETURN_VAL_LOG(
        LABEL, data.WriteInt64(request.beginTimeMillis), ERR_WRITE_PARCEL_FAILED, "WriteInt64 failed.");
    IF_FALSE_RETURN_VAL_LOG(
        LABEL, data.WriteInt64(request.endTimeMillis), ERR_WRITE_PARCEL_FAILED, "WriteInt64 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInt32(request.flag), ERR_WRITE_PARCEL_FAILED, "WriteInt32 failed.");

    MessageParcel reply;
    if (!SendRequest(PrivacyInterfaceCode::GET_PERMISSION_USED_RECORDS, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t ret = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(ret), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", ret);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    sptr<PermissionUsedResultParcel> resultSptr = reply.ReadParcelable<PermissionUsedResultParcel>();
    if (resultSptr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable fail");
        return ERR_READ_PARCEL_FAILED;
    }
    result = *resultSptr;
    return ret;
}

int32_t PrivacyManagerProxy::GetPermissionUsedRecords(const PermissionUsedRequest& request,
    const sptr<OnPermissionUsedRecordCallback>& callback)
{
    MessageParcel data;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(request.tokenId), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteBool(request.isRemote), ERR_WRITE_PARCEL_FAILED, "WriteBool failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteString(request.deviceId), ERR_WRITE_PARCEL_FAILED, "WriteString failed.");
    IF_FALSE_RETURN_VAL_LOG(
        LABEL, data.WriteString(request.bundleName), ERR_WRITE_PARCEL_FAILED, "WriteString failed.");

    IF_FALSE_RETURN_VAL_LOG(LABEL,
        data.WriteUint32(request.permissionList.size()), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    for (const auto& permission : request.permissionList) {
        IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteString(permission),
            ERR_WRITE_PARCEL_FAILED, "WriteString(%{public}s) failed.", permission.c_str());
    }
    IF_FALSE_RETURN_VAL_LOG(LABEL,
        data.WriteInt64(request.beginTimeMillis), ERR_WRITE_PARCEL_FAILED, "WriteInt64 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL,
        data.WriteInt64(request.endTimeMillis), ERR_WRITE_PARCEL_FAILED, "WriteInt64 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInt32(request.flag), ERR_WRITE_PARCEL_FAILED, "WriteInt32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL,
        data.WriteRemoteObject(callback->AsObject()), ERR_WRITE_PARCEL_FAILED, "WriteRemoteObject failed.");

    MessageParcel reply;
    if (!SendRequest(PrivacyInterfaceCode::GET_PERMISSION_USED_RECORDS_ASYNC, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", result);
    return result;
}

int32_t PrivacyManagerProxy::RegisterPermActiveStatusCallback(
    std::vector<std::string>& permList, const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");

    uint32_t listSize = permList.size();
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(listSize), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    for (uint32_t i = 0; i < listSize; i++) {
        IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteString(permList[i]), ERR_WRITE_PARCEL_FAILED,
            "Failed to write permList[%{public}d], %{public}s", i, permList[i].c_str());
    }

    IF_FALSE_RETURN_VAL_LOG(
        LABEL, data.WriteRemoteObject(callback), ERR_WRITE_PARCEL_FAILED, "WriteRemoteObject failed.");
    MessageParcel reply;
    if (!SendRequest(PrivacyInterfaceCode::REGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", result);
    return result;
}

int32_t PrivacyManagerProxy::UnRegisterPermActiveStatusCallback(const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(
        LABEL, data.WriteRemoteObject(callback), ERR_WRITE_PARCEL_FAILED, "WriteRemoteObject failed.");
    MessageParcel reply;
    if (!SendRequest(
        PrivacyInterfaceCode::UNREGISTER_PERM_ACTIVE_STATUS_CHANGE_CALLBACK, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", result);
    return result;
}

bool PrivacyManagerProxy::IsAllowedUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    MessageParcel data;
    MessageParcel reply;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), false, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(tokenID), false, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteString(permissionName), false, "WriteString failed.");
    if (!SendRequest(PrivacyInterfaceCode::IS_ALLOWED_USING_PERMISSION, data, reply)) {
        return false;
    }

    bool result = false;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadBool(result), false, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", result);
    return result;
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
int32_t PrivacyManagerProxy::RegisterSecCompEnhance(const SecCompEnhanceData& enhance)
{
    MessageParcel data;
    MessageParcel reply;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(
        LABEL, data.WriteUint32(enhance.token), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint64(enhance.challenge), ERR_WRITE_PARCEL_FAILED, "WriteUint64 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(enhance.sessionId), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(enhance.seqNum), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(
        LABEL, data.WriteBuffer(enhance.key, AES_KEY_STORAGE_LEN), ERR_WRITE_PARCEL_FAILED, "WriteBuffer failed.");
    IF_FALSE_RETURN_VAL_LOG(
        LABEL, data.WriteRemoteObject(enhance.callback), ERR_WRITE_PARCEL_FAILED, "WriteRemoteObject failed.");

    if (!SendRequest(PrivacyInterfaceCode::REGISTER_SEC_COMP_ENHANCE, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", result);
    return result;
}

int32_t PrivacyManagerProxy::UpdateSecCompEnhance(int32_t pid, uint32_t seqNum)
{
    MessageParcel data;
    MessageParcel reply;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInt32(pid), ERR_WRITE_PARCEL_FAILED, "WriteInt32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(seqNum), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    if (!SendRequest(PrivacyInterfaceCode::UPDATE_SEC_COMP_ENHANCE, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result=%{public}d", result);
    return result;
}

static bool ReadEnhanceData(MessageParcel& in, SecCompEnhanceData& data)
{
    RETURN_IF_FALSE(in.ReadUint32(data.token));
    RETURN_IF_FALSE(in.ReadUint64(data.challenge));
    RETURN_IF_FALSE(in.ReadUint32(data.sessionId));
    RETURN_IF_FALSE(in.ReadUint32(data.seqNum));
    const uint8_t* ptr = in.ReadBuffer(AES_KEY_STORAGE_LEN);
    if (ptr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadBuffer failed.");
        return false;
    }
    if (memcpy_s(data.key, AES_KEY_STORAGE_LEN, ptr, AES_KEY_STORAGE_LEN) != EOK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "memcpy_s failed.");
        return false;
    }

    data.callback = in.ReadRemoteObject();
    if (data.callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadBuffer failed.");
        return false;
    }
    return true;
}

int32_t PrivacyManagerProxy::GetSecCompEnhance(int32_t pid, SecCompEnhanceData& enhance)
{
    MessageParcel data;
    MessageParcel reply;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInt32(pid), ERR_WRITE_PARCEL_FAILED, "WriteInt32 failed.");
    if (!SendRequest(PrivacyInterfaceCode::GET_SEC_COMP_ENHANCE, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    IF_FALSE_RETURN_VAL_LOG(LABEL, ReadEnhanceData(reply, enhance), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    return result;
}

int32_t PrivacyManagerProxy::GetSpecialSecCompEnhance(const std::string& bundleName,
    std::vector<SecCompEnhanceData>& enhanceList)
{
    MessageParcel data;
    MessageParcel reply;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteString(bundleName), ERR_WRITE_PARCEL_FAILED, "WriteString failed.");

    if (!SendRequest(PrivacyInterfaceCode::GET_SPECIAL_SEC_COMP_ENHANCE, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }

    uint32_t size = 0;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadUint32(size), ERR_READ_PARCEL_FAILED, "ReadUint32 failed.");
    if (size > MAX_SEC_COMP_ENHANCE_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Size = %{public}d get from request is invalid", size);
        return ERR_OVERSIZE;
    }
    for (uint32_t i = 0; i < size; i++) {
        SecCompEnhanceData tmp;
        IF_FALSE_RETURN_VAL_LOG(LABEL, ReadEnhanceData(reply, tmp), ERR_READ_PARCEL_FAILED, "ReadUint32 failed.");
        enhanceList.emplace_back(tmp);
    }
    return result;
}
#endif

int32_t PrivacyManagerProxy::GetPermissionUsedTypeInfos(const AccessTokenID tokenId, const std::string& permissionName,
    std::vector<PermissionUsedTypeInfoParcel>& resultsParcel)
{
    MessageParcel data;
    MessageParcel reply;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(tokenId), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteString(permissionName), ERR_WRITE_PARCEL_FAILED, "WriteString failed.");

    if (!SendRequest(PrivacyInterfaceCode::GET_PERMISSION_USED_TYPE_INFOS, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server is %{public}d.", result);
    if (result != RET_SUCCESS) {
        return result;
    }

    uint32_t size = 0;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadUint32(size), ERR_READ_PARCEL_FAILED, "ReadUint32 failed.");
    if (size > MAX_PERMISSION_USED_TYPE_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed, results oversize %{public}d, please add query params!", size);
        return ERR_OVERSIZE;
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
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(policyType), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(callerType), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteBool(isMute), ERR_WRITE_PARCEL_FAILED, "WriteBool failed.");

    if (!SendRequest(PrivacyInterfaceCode::SET_MUTE_POLICY, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }
    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server is %{public}d.", result);
    return result;
}

int32_t PrivacyManagerProxy::SetHapWithFGReminder(uint32_t tokenId, bool isAllowed)
{
    MessageParcel data;
    MessageParcel reply;
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteInterfaceToken(
        IPrivacyManager::GetDescriptor()), ERR_WRITE_PARCEL_FAILED, "WriteInterfaceToken failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteUint32(tokenId), ERR_WRITE_PARCEL_FAILED, "WriteUint32 failed.");
    IF_FALSE_RETURN_VAL_LOG(LABEL, data.WriteBool(isAllowed), ERR_WRITE_PARCEL_FAILED, "WriteBool failed.");

    if (!SendRequest(PrivacyInterfaceCode::SET_HAP_WITH_FOREGROUND_REMINDER, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }
    int32_t result = NO_ERROR;
    IF_FALSE_RETURN_VAL_LOG(LABEL, reply.ReadInt32(result), ERR_READ_PARCEL_FAILED, "ReadInt32 failed.");
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server is %{public}d.", result);
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "Remote service null.");
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
