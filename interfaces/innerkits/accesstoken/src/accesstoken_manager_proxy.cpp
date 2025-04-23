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

#include "accesstoken_manager_proxy.h"

#include "accesstoken_log.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"

#include "parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "ATMProxy"};
static const int MAX_PERMISSION_SIZE = 1000;
static const int32_t MAX_USER_POLICY_SIZE = 1024;
static const int32_t MAX_EXTENDED_VALUE_LIST_SIZE = 512;
}

AccessTokenManagerProxy::AccessTokenManagerProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IAccessTokenManager>(impl) {
}

AccessTokenManagerProxy::~AccessTokenManagerProxy()
{}

bool AccessTokenManagerProxy::SendRequest(
    AccessTokenInterfaceCode code, MessageParcel& data, MessageParcel& reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Code: %{public}d remote service null.", code);
        return false;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(code), data, reply, option);
    if (requestResult != NO_ERROR) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Code: %{public}d request fail, result: %{public}d", code, requestResult);
        return false;
    }
    return true;
}

PermUsedTypeEnum AccessTokenManagerProxy::GetPermissionUsedType(
    AccessTokenID tokenID, const std::string &permissionName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    if (!data.WriteString(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString failed.");
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_USER_GRANTED_PERMISSION_USED_TYPE, data, reply)) {
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }

    int32_t ret;
    if (!reply.ReadInt32(ret)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt32t failed.");
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    PermUsedTypeEnum result = static_cast<PermUsedTypeEnum>(ret);
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (type=%{public}d).", result);
    return result;
}

int AccessTokenManagerProxy::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return PERMISSION_DENIED;
    }
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return PERMISSION_DENIED;
    }
    if (!data.WriteString(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString failed.");
        return PERMISSION_DENIED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::VERIFY_ACCESSTOKEN, data, reply)) {
        return PERMISSION_DENIED;
    }

    int32_t result = reply.ReadInt32();
    LOGD(ATM_DOMAIN, ATM_TAG, "Result from server (status=%{public}d).", result);
    return result;
}

int AccessTokenManagerProxy::VerifyAccessToken(AccessTokenID tokenID,
    const std::vector<std::string>& permissionList, std::vector<int32_t>& permStateList)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteStringVector(permissionList)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteStringVector failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::VERIFY_ACCESSTOKEN_WITH_LIST, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    if (!reply.ReadInt32Vector(&permStateList)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt32Vector failed.");
        return ERR_READ_PARCEL_FAILED;
    }

    return ERR_OK;
}

int AccessTokenManagerProxy::GetDefPermission(
    const std::string& permissionName, PermissionDefParcel& permissionDefResult)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_DEF_PERMISSION, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    sptr<PermissionDefParcel> resultSptr = reply.ReadParcelable<PermissionDefParcel>();
    if (resultSptr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadParcelable failed.");
        return ERR_READ_PARCEL_FAILED;
    }
    permissionDefResult = *resultSptr;
    return result;
}

int AccessTokenManagerProxy::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStatusParcel>& reqPermList, bool isSystemGrant)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteInt32(isSystemGrant)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInt32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_REQ_PERMISSIONS, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGD(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    uint32_t reqPermSize = reply.ReadUint32();
    if (reqPermSize > MAX_PERMISSION_SIZE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Size(%{public}u) is oversize.", reqPermSize);
        return ERR_OVERSIZE;
    }
    for (uint32_t i = 0; i < reqPermSize; i++) {
        sptr<PermissionStatusParcel> permissionReq = reply.ReadParcelable<PermissionStatusParcel>();
        if (permissionReq != nullptr) {
            reqPermList.emplace_back(*permissionReq);
        }
    }
    return result;
}

int32_t AccessTokenManagerProxy::SetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t status,
    int32_t userID = 0)
{
    MessageParcel sendData;
    if (!sendData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!sendData.WriteString(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!sendData.WriteUint32(status)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!sendData.WriteInt32(userID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInt32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::SET_PERMISSION_REQUEST_TOGGLE_STATUS, sendData, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    return result;
}

int32_t AccessTokenManagerProxy::GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status,
    int32_t userID = 0)
{
    MessageParcel sendData;
    if (!sendData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!sendData.WriteString(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!sendData.WriteInt32(userID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInt32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_PERMISSION_REQUEST_TOGGLE_STATUS, sendData, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    if (result == RET_SUCCESS) {
        status = reply.ReadUint32();
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d, status=%{public}d).", result, status);
    return result;
}

int32_t AccessTokenManagerProxy::RequestAppPermOnSetting(AccessTokenID tokenID)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInt32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::REQUEST_APP_PERM_ON_SETTING, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result;
    if (!reply.ReadInt32(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt32 failed.");
        return ERR_READ_PARCEL_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (result=%{public}d).", result);
    return result;
}

int AccessTokenManagerProxy::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag)
{
    MessageParcel sendData;
    if (!sendData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!sendData.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!sendData.WriteString(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_PERMISSION_FLAG, sendData, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    if (result == RET_SUCCESS) {
        flag = reply.ReadUint32();
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d, flag=%{public}d).", result, flag);
    return result;
}

int32_t AccessTokenManagerProxy::GetSelfPermissionStatus(const std::string& permissionName, int32_t& status)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return INVALID_OPER;
    }
    if (!data.WriteString(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_SELF_PERMISSION_STATUS, data, reply)) {
        return INVALID_OPER;
    }

    int32_t result = reply.ReadInt32();
    if (result == RET_SUCCESS) {
        status = reply.ReadInt32();
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d, status=%{public}d).", result, status);
    return result;
}

PermissionOper AccessTokenManagerProxy::GetSelfPermissionsState(std::vector<PermissionListStateParcel>& permListParcel,
    PermissionGrantInfoParcel& infoParcel)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return INVALID_OPER;
    }
    if (!data.WriteUint32(permListParcel.size())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return INVALID_OPER;
    }
    for (const auto& permission : permListParcel) {
        if (!data.WriteParcelable(&permission)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "WriteParcelable failed.");
            return INVALID_OPER;
        }
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_PERMISSION_OPER_STATE, data, reply)) {
        return INVALID_OPER;
    }

    PermissionOper result = static_cast<PermissionOper>(reply.ReadInt32());
    size_t size = reply.ReadUint32();
    if (size != permListParcel.size()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Size(%{public}zu) from server is not equal inputSize(%{public}zu)!",
            size, permListParcel.size());
        return INVALID_OPER;
    }
    if (size > MAX_PERMISSION_SIZE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Size(%{public}zu) is oversize.", size);
        return INVALID_OPER;
    }
    for (uint32_t i = 0; i < size; i++) {
        sptr<PermissionListStateParcel> permissionReq = reply.ReadParcelable<PermissionListStateParcel>();
        if (permissionReq != nullptr) {
            permListParcel[i].permsState.state = permissionReq->permsState.state;
            permListParcel[i].permsState.errorReason = permissionReq->permsState.errorReason;
        }
    }

    sptr<PermissionGrantInfoParcel> resultSptr = reply.ReadParcelable<PermissionGrantInfoParcel>();
    if (resultSptr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadParcelable failed.");
        return INVALID_OPER;
    }
    infoParcel = *resultSptr;

    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (status=%{public}d).", result);
    return result;
}

int32_t AccessTokenManagerProxy::GetPermissionsStatus(AccessTokenID tokenID,
    std::vector<PermissionListStateParcel>& permListParcel)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(permListParcel.size())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    for (const auto& permission : permListParcel) {
        if (!data.WriteParcelable(&permission)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "WriteParcelable failed.");
            return ERR_WRITE_PARCEL_FAILED;
        }
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_PERMISSIONS_STATUS, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    size_t size = reply.ReadUint32();
    if (size != permListParcel.size()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Size(%{public}zu) from server is not equal inputSize(%{public}zu)!",
            size, permListParcel.size());
        return ERR_SIZE_NOT_EQUAL;
    }
    for (uint32_t i = 0; i < size; i++) {
        sptr<PermissionListStateParcel> permissionReq = reply.ReadParcelable<PermissionListStateParcel>();
        if (permissionReq != nullptr) {
            permListParcel[i].permsState.state = permissionReq->permsState.state;
        }
    }
    return result;
}

int AccessTokenManagerProxy::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    MessageParcel inData;
    if (!inData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!inData.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!inData.WriteString(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!inData.WriteUint32(flag)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GRANT_PERMISSION, inData, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    return result;
}

int AccessTokenManagerProxy::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(flag)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::REVOKE_PERMISSION, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    return result;
}

int AccessTokenManagerProxy::GrantPermissionForSpecifiedTime(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t onceTime)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(onceTime)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GRANT_PERMISSION_FOR_SPECIFIEDTIME, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result;
    if (!reply.ReadInt32(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt32 failed.");
        return ERR_READ_PARCEL_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (result=%{public}d).", result);
    return result;
}

int AccessTokenManagerProxy::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::CLEAR_USER_GRANT_PERMISSION, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    return result;
}

int32_t AccessTokenManagerProxy::RegisterPermStateChangeCallback(
    const PermStateChangeScopeParcel& scope, const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteParcelable(&scope)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteParcelable failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteRemoteObject(callback)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteRemoteObject failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::REGISTER_PERM_STATE_CHANGE_CALLBACK, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t ret;
    if (!reply.ReadInt32(ret)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt32 failed.");
        return ERR_READ_PARCEL_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", ret);
    return ret;
}

int32_t AccessTokenManagerProxy::UnRegisterPermStateChangeCallback(const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteRemoteObject(callback)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteRemoteObject failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(
        AccessTokenInterfaceCode::UNREGISTER_PERM_STATE_CHANGE_CALLBACK, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result;
    if (!reply.ReadInt32(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt32 failed.");
        return ERR_READ_PARCEL_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    return result;
}

int32_t AccessTokenManagerProxy::RegisterSelfPermStateChangeCallback(
    const PermStateChangeScopeParcel& scope, const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteParcelable(&scope)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteParcelable failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteRemoteObject(callback)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteRemoteObject failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::REGISTER_SELF_PERM_STATE_CHANGE_CALLBACK, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t ret;
    if (!reply.ReadInt32(ret)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt32 failed.");
        return ERR_READ_PARCEL_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", ret);
    return ret;
}

int32_t AccessTokenManagerProxy::UnRegisterSelfPermStateChangeCallback(const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteRemoteObject(callback)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteRemoteObject failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(
        AccessTokenInterfaceCode::UNREGISTER_SELF_PERM_STATE_CHANGE_CALLBACK, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result;
    if (!reply.ReadInt32(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt32 failed.");
        return ERR_READ_PARCEL_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    return result;
}

AccessTokenIDEx AccessTokenManagerProxy::AllocHapToken(
    const HapInfoParcel& hapInfo, const HapPolicyParcel& policyParcel)
{
    MessageParcel data;
    AccessTokenIDEx res = { 0 };
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return res;
    }

    if (!data.WriteParcelable(&hapInfo)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteParcelable failed.");
        return res;
    }
    if (!data.WriteParcelable(&policyParcel)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteParcelable failed.");
        return res;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::ALLOC_TOKEN_HAP, data, reply)) {
        return res;
    }

    unsigned long long result = reply.ReadUint64();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (id=%{public}llu).", result);
    res.tokenIDEx = result;
    return res;
}

int32_t AccessTokenManagerProxy::InitHapToken(const HapInfoParcel& hapInfoParcel, HapPolicyParcel& policyParcel,
    AccessTokenIDEx& fullTokenId, HapInfoCheckResult& resultInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteParcelable(&hapInfoParcel)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteParcelable failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteParcelable(&policyParcel)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteParcelable failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::INIT_TOKEN_HAP, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }
    int32_t result = 0;
    if (!reply.ReadInt32(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt32 failed.");
        return ERR_READ_PARCEL_FAILED;
    }
    if (result == RET_SUCCESS) {
        uint64_t tokenId = 0;
        if (!reply.ReadUint64(tokenId)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "ReadUint64 faild.");
            return ERR_READ_PARCEL_FAILED;
        }
        fullTokenId.tokenIDEx = tokenId;
    } else {
        if (reply.GetDataSize() > reply.GetReadPosition()) {
            IF_FALSE_RETURN_VALUE_LOG(LABEL, reply.ReadString(resultInfo.permCheckResult.permissionName),
                ERR_READ_PARCEL_FAILED, "ReadString faild.");

            int32_t rule;
            IF_FALSE_RETURN_VALUE_LOG(LABEL, reply.ReadInt32(rule),
                ERR_READ_PARCEL_FAILED, "ReadString faild.");
            resultInfo.permCheckResult.rule = static_cast<PermissionRulesEnum>(rule);
        }
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d, id=%{public}llu).",
        result, fullTokenId.tokenIDEx);
    return result;
}

int AccessTokenManagerProxy::DeleteToken(AccessTokenID tokenID)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::TOKEN_DELETE, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int result = reply.ReadInt32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d, id=%{public}u).", result, tokenID);
    return result;
}

int AccessTokenManagerProxy::GetTokenType(AccessTokenID tokenID)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write tokenID");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_TOKEN_TYPE, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int result = reply.ReadInt32();
    LOGD(ATM_DOMAIN, ATM_TAG, "Result from server (type=%{public}d).", result);
    return result;
}

AccessTokenIDEx AccessTokenManagerProxy::GetHapTokenID(int32_t userID, const std::string& bundleName, int32_t instIndex)
{
    AccessTokenIDEx tokenIdEx = {0};
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return tokenIdEx;
    }

    if (!data.WriteInt32(userID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write tokenID");
        return tokenIdEx;
    }
    if (!data.WriteString(bundleName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write dcap");
        return tokenIdEx;
    }
    if (!data.WriteInt32(instIndex)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write dcap");
        return tokenIdEx;
    }
    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_HAP_TOKEN_ID, data, reply)) {
        return tokenIdEx;
    }

    tokenIdEx.tokenIDEx = reply.ReadUint64();
    LOGD(ATM_DOMAIN, ATM_TAG, "Result from server (id=%{public}llu).", tokenIdEx.tokenIDEx);
    return tokenIdEx;
}

AccessTokenID AccessTokenManagerProxy::AllocLocalTokenID(
    const std::string& remoteDeviceID, AccessTokenID remoteTokenID)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return 0;
    }

    if (!data.WriteString(remoteDeviceID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write dcap");
        return 0;
    }
    if (!data.WriteUint32(remoteTokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write dcap");
        return 0;
    }
    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::ALLOC_LOCAL_TOKEN_ID, data, reply)) {
        return 0;
    }

    AccessTokenID result = reply.ReadUint32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (id=%{public}d).", result);
    return result;
}

int AccessTokenManagerProxy::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& nativeTokenInfoRes)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_NATIVE_TOKENINFO, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGD(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    sptr<NativeTokenInfoParcel> resultSptr = reply.ReadParcelable<NativeTokenInfoParcel>();
    if (resultSptr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadParcelable fail");
        return ERR_READ_PARCEL_FAILED;
    }
    nativeTokenInfoRes = *resultSptr;
    return result;
}

int32_t AccessTokenManagerProxy::GetTokenIDByUserID(int32_t userID, std::unordered_set<AccessTokenID>& tokenIdList)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteInt32(userID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInt32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_TOKEN_ID_BY_USER_ID, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = 0;
    if (!reply.ReadInt32(result)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
        return ERR_READ_PARCEL_FAILED;
    }
    if (result != RET_SUCCESS) {
        return result;
    }

    uint32_t tokenIDListSize = 0;
    if (!reply.ReadUint32(tokenIDListSize)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadUint32 failed.");
        return ERR_READ_PARCEL_FAILED;
    }
    for (uint32_t i = 0; i < tokenIDListSize; i++) {
        AccessTokenID tokenId = 0;
        if (!reply.ReadUint32(tokenId)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "ReadUint32 failed.");
            return ERR_READ_PARCEL_FAILED;
        }
        tokenIdList.emplace(tokenId);
    }
    return result;
}

int AccessTokenManagerProxy::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& hapTokenInfoRes)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_HAP_TOKENINFO, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGD(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    sptr<HapTokenInfoParcel> resultSptr = reply.ReadParcelable<HapTokenInfoParcel>();
    if (resultSptr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadParcelable failed.");
        return ERR_READ_PARCEL_FAILED;
    }
    hapTokenInfoRes = *resultSptr;
    return result;
}

int32_t UpdateHapTokenWriteParam(MessageParcel& data, AccessTokenID tokenID, const UpdateHapInfoParams& info,
    const HapPolicyParcel& policyParcel)
{
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write tokenID failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteBool(info.isSystemApp)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write isSystemApp failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(info.appIDDesc)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write appIDDesc failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteInt32(info.apiVersion)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write apiVersion failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(info.appDistributionType)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write appDistributionType failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteParcelable(&policyParcel)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write policyParcel failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteBool(info.isAtomicService)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write isAtomicService failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    return ERR_OK;
}

int32_t AccessTokenManagerProxy::UpdateHapToken(AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info,
    const HapPolicyParcel& policyParcel, HapInfoCheckResult& resultInfo)
{
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    MessageParcel data;
    if (UpdateHapTokenWriteParam(data, tokenID, info, policyParcel) != ERR_OK) {
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::UPDATE_HAP_TOKEN, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }
    int32_t result = reply.ReadInt32();
    tokenIdEx.tokenIdExStruct.tokenAttr = reply.ReadUint32();
    if (result != RET_SUCCESS && reply.GetDataSize() > reply.GetReadPosition()) {
        IF_FALSE_RETURN_VALUE_LOG(LABEL, reply.ReadString(resultInfo.permCheckResult.permissionName),
            ERR_READ_PARCEL_FAILED, "ReadString faild.");

        int32_t rule;
        IF_FALSE_RETURN_VALUE_LOG(LABEL, reply.ReadInt32(rule),
            ERR_READ_PARCEL_FAILED, "ReadString faild.");
        resultInfo.permCheckResult.rule = static_cast<PermissionRulesEnum>(rule);
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    return result;
}

#ifndef ATM_BUILD_VARIANT_USER_ENABLE
int32_t AccessTokenManagerProxy::ReloadNativeTokenInfo()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::RELOAD_NATIVE_TOKEN_INFO, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    return result;
}

#endif

int AccessTokenManagerProxy::GetHapTokenInfoExtension(AccessTokenID tokenID,
    HapTokenInfoParcel& hapTokenInfoRes, std::string& appID)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteUint32 fail");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_HAP_TOKENINFO_EXT, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    sptr<HapTokenInfoParcel> hapResult = reply.ReadParcelable<HapTokenInfoParcel>();
    if (hapResult == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadParcelable fail.");
        return ERR_READ_PARCEL_FAILED;
    }
    hapTokenInfoRes = *hapResult;
    if (!reply.ReadString(appID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadString fail.");
        return ERR_READ_PARCEL_FAILED;
    }

    return result;
}

AccessTokenID AccessTokenManagerProxy::GetNativeTokenId(const std::string& processName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return INVALID_TOKENID;
    }

    if (!data.WriteString(processName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteString failed.");
        return INVALID_TOKENID;
    }
    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_NATIVE_TOKEN_ID, data, reply)) {
        return INVALID_TOKENID;
    }
    AccessTokenID id;
    if (!reply.ReadUint32(id)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "ReadInt32 failed.");
        return INVALID_TOKENID;
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "Result from server (process=%{public}s, id=%{public}d).", processName.c_str(), id);
    return id;
}

#ifdef TOKEN_SYNC_ENABLE
int AccessTokenManagerProxy::GetHapTokenInfoFromRemote(AccessTokenID tokenID,
    HapTokenInfoForSyncParcel& hapSyncParcel)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(tokenID)) {
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_HAP_TOKEN_FROM_REMOTE, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    sptr<HapTokenInfoForSyncParcel> hapResult = reply.ReadParcelable<HapTokenInfoForSyncParcel>();
    if (hapResult == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadParcelable fail");
        return ERR_READ_PARCEL_FAILED;
    }
    hapSyncParcel = *hapResult;
    return result;
}

int AccessTokenManagerProxy::SetRemoteHapTokenInfo(const std::string& deviceID,
    HapTokenInfoForSyncParcel& hapSyncParcel)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(deviceID)) {
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteParcelable(&hapSyncParcel)) {
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::SET_REMOTE_HAP_TOKEN_INFO, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    return result;
}

int AccessTokenManagerProxy::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteString(deviceID)) {
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteUint32(tokenID)) {
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::DELETE_REMOTE_TOKEN_INFO, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    return result;
}

AccessTokenID AccessTokenManagerProxy::GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return 0;
    }
    if (!data.WriteString(deviceID)) {
        return 0;
    }

    if (!data.WriteUint32(tokenID)) {
        return 0;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_NATIVE_REMOTE_TOKEN, data, reply)) {
        return 0;
    }

    AccessTokenID id = reply.ReadUint32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (id=%{public}d).", id);
    return id;
}

int AccessTokenManagerProxy::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(deviceID)) {
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::DELETE_REMOTE_DEVICE_TOKEN, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    return result;
}

int32_t AccessTokenManagerProxy::RegisterTokenSyncCallback(const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteRemoteObject(callback)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteRemoteObject failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(
        AccessTokenInterfaceCode::REGISTER_TOKEN_SYNC_CALLBACK, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result;
    if (!reply.ReadInt32(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt32 failed.");
        return ERR_READ_PARCEL_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    return result;
}

int32_t AccessTokenManagerProxy::UnRegisterTokenSyncCallback()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(
        AccessTokenInterfaceCode::UNREGISTER_TOKEN_SYNC_CALLBACK, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result;
    if (!reply.ReadInt32(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadInt32 failed.");
        return ERR_READ_PARCEL_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    return result;
}
#endif

void AccessTokenManagerProxy::DumpTokenInfo(const AtmToolsParamInfoParcel& infoParcel, std::string& dumpInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return;
    }

    if (!data.WriteParcelable(&infoParcel)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write infoParcel failed.");
        return;
    }
    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::DUMP_TOKENINFO, data, reply)) {
        return;
    }
    if (!reply.ReadString(dumpInfo)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadString failed.");
    }
}

int32_t AccessTokenManagerProxy::GetVersion(uint32_t& version)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write interface token failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_VERSION, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }
    int32_t result = reply.ReadInt32();
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d).", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    if (!reply.ReadUint32(version)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadUint32 failed.");
        return ERR_READ_PARCEL_FAILED;
    }
    return result;
}

int32_t AccessTokenManagerProxy::SetPermDialogCap(const HapBaseInfoParcel& hapBaseInfo, bool enable)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteParcelable(&hapBaseInfo)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteParcelable failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteBool(enable)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteBool failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::SET_PERM_DIALOG_CAPABILITY, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }
    return reply.ReadInt32();
}

void AccessTokenManagerProxy::GetPermissionManagerInfo(PermissionGrantInfoParcel& infoParcel)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_PERMISSION_MANAGER_INFO, data, reply)) {
        return;
    }

    sptr<PermissionGrantInfoParcel> parcel = reply.ReadParcelable<PermissionGrantInfoParcel>();
    if (parcel == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ReadParcelable failed.");
        return;
    }
    infoParcel = *parcel;
}

int32_t AccessTokenManagerProxy::InitUserPolicy(
    const std::vector<UserState>& userList, const std::vector<std::string>& permList)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write interface token failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    size_t userLen = userList.size();
    size_t permLen = permList.size();
    if ((userLen == 0) || (userLen > MAX_USER_POLICY_SIZE) || (permLen == 0) || (permLen > MAX_USER_POLICY_SIZE)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "UserLen %{public}zu or permLen %{public}zu is invalid", userLen, permLen);
        return ERR_PARAM_INVALID;
    }

    if (!data.WriteUint32(userLen)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write userLen size.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(permLen)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write permLen size.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    for (const auto& userInfo : userList) {
        if (!data.WriteInt32(userInfo.userId)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write userId.");
            return ERR_WRITE_PARCEL_FAILED;
        }
        if (!data.WriteBool(userInfo.isActive)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write isActive.");
            return ERR_WRITE_PARCEL_FAILED;
        }
    }
    for (const auto& permission : permList) {
        if (!data.WriteString(permission)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write permission.");
            return ERR_WRITE_PARCEL_FAILED;
        }
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::INIT_USER_POLICY, data, reply)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read replay failed");
        return ERR_SERVICE_ABNORMAL;
    }
    int32_t result;
    if (!reply.ReadInt32(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read Int32 failed");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server data = %{public}d", result);
    return result;
}

int32_t AccessTokenManagerProxy::ClearUserPolicy()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write interface token failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::CLEAR_USER_POLICY, data, reply)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read replay failed");
        return ERR_SERVICE_ABNORMAL;
    }
    int32_t result;
    if (!reply.ReadInt32(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read Int32 failed");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server data = %{public}d", result);
    return result;
}

int32_t AccessTokenManagerProxy::UpdateUserPolicy(const std::vector<UserState>& userList)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write interface token failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    size_t userLen = userList.size();
    if ((userLen == 0) || (userLen > MAX_USER_POLICY_SIZE)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "UserLen %{public}zu is invalid.", userLen);
        return ERR_PARAM_INVALID;
    }

    if (!data.WriteUint32(userLen)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write userLen size.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    for (const auto& userInfo : userList) {
        if (!data.WriteInt32(userInfo.userId)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write userId.");
            return ERR_WRITE_PARCEL_FAILED;
        }
        if (!data.WriteBool(userInfo.isActive)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write isActive.");
            return ERR_WRITE_PARCEL_FAILED;
        }
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::UPDATE_USER_POLICY, data, reply)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read replay failed");
        return ERR_SERVICE_ABNORMAL;
    }
    int32_t result;
    if (!reply.ReadInt32(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read Int32 failed");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server data = %{public}d", result);
    return result;
}

int32_t AccessTokenManagerProxy::GetKernelPermissions(
    AccessTokenID tokenID, std::vector<PermissionWithValue>& kernelPermList)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write interface token failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write tokenID.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_KERNEL_PERMISSIONS, data, reply)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read replay failed");
        return ERR_SERVICE_ABNORMAL;
    }
    int32_t result;
    if (!reply.ReadInt32(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read result failed");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    uint32_t size;
    if (!reply.ReadUint32(size)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read size failed");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    if (size > MAX_EXTENDED_VALUE_LIST_SIZE) {
        return AccessTokenError::ERR_OVERSIZE;
    }
    for (uint32_t i = 0; i < size; ++i) {
        PermissionWithValue perm;
        if (!reply.ReadString(perm.permissionName)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Read permission name failed.");
            return AccessTokenError::ERR_READ_PARCEL_FAILED;
        }
        if (!reply.ReadString(perm.value)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Read value failed.");
            return AccessTokenError::ERR_READ_PARCEL_FAILED;
        }
        if (perm.value == "true") {
            perm.value.clear();
        }
        kernelPermList.emplace_back(perm);
    }
    return RET_SUCCESS;
}

int32_t AccessTokenManagerProxy::GetReqPermissionByName(
    AccessTokenID tokenID, const std::string& permissionName, std::string& value)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write interface token failed.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write tokenID.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteString(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write tokenID.");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_PERMISSION_BY_NAME, data, reply)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read replay failed");
        return ERR_SERVICE_ABNORMAL;
    }
    int32_t result;
    if (!reply.ReadInt32(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read result failed");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    if (!reply.ReadString(value)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read value failed");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }

    return RET_SUCCESS;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
