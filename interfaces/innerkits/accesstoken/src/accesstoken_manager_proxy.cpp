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
#include "access_token_error.h"

#include "parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "ATMProxy"};
static const int MAX_PERMISSION_SIZE = 1000;
#ifdef TOKEN_SYNC_ENABLE
static const int MAX_NATIVE_TOKEN_INFO_SIZE = 20480;
#endif
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "code: %{public}d remote service null.", code);
        return false;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(code), data, reply, option);
    if (requestResult != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "code: %{public}d request fail, result: %{public}d", code, requestResult);
        return false;
    }
    return true;
}

PermUsedTypeEnum AccessTokenManagerProxy::GetUserGrantedPermissionUsedType(
    AccessTokenID tokenID, const std::string &permissionName)
{
    MessageParcel data;

    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write descriptor failed.");
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write tokenID failed.");
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write permissionName failed.");
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_USER_GRANTED_PERMISSION_USED_TYPE, data, reply)) {
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }

    int32_t ret;
    if (!reply.ReadInt32(ret)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Read result failed.");
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    PermUsedTypeEnum result = static_cast<PermUsedTypeEnum>(ret);
    ACCESSTOKEN_LOG_INFO(LABEL, "Get result from server, result=%{public}d.", result);
    return result;
}

int AccessTokenManagerProxy::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return PERMISSION_DENIED;
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permissionName");
        return PERMISSION_DENIED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::VERIFY_ACCESSTOKEN, data, reply)) {
        return PERMISSION_DENIED;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "result from server data = %{public}d", result);
    return result;
}

int AccessTokenManagerProxy::GetDefPermission(
    const std::string& permissionName, PermissionDefParcel& permissionDefResult)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permissionName");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_DEF_PERMISSION, data, reply)) {
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    sptr<PermissionDefParcel> resultSptr = reply.ReadParcelable<PermissionDefParcel>();
    if (resultSptr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "read permission def parcel fail");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    permissionDefResult = *resultSptr;
    return result;
}

int AccessTokenManagerProxy::GetDefPermissions(AccessTokenID tokenID,
    std::vector<PermissionDefParcel>& permList)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_DEF_PERMISSIONS, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    uint32_t defPermSize = reply.ReadUint32();
    if (defPermSize > MAX_PERMISSION_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "size = %{public}d get from request is invalid", defPermSize);
        return ERR_OVERSIZE;
    }
    for (uint32_t i = 0; i < defPermSize; i++) {
        sptr<PermissionDefParcel> permissionDef = reply.ReadParcelable<PermissionDefParcel>();
        if (permissionDef != nullptr) {
            permList.emplace_back(*permissionDef);
        }
    }
    return result;
}

int AccessTokenManagerProxy::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStateFullParcel>& reqPermList, bool isSystemGrant)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteInt32(isSystemGrant)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write isSystemGrant");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_REQ_PERMISSIONS, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    uint32_t reqPermSize = reply.ReadUint32();
    if (reqPermSize > MAX_PERMISSION_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "size = %{public}d get from request is invalid", reqPermSize);
        return ERR_OVERSIZE;
    }
    for (uint32_t i = 0; i < reqPermSize; i++) {
        sptr<PermissionStateFullParcel> permissionReq = reply.ReadParcelable<PermissionStateFullParcel>();
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write interface token failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!sendData.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write permissionName failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!sendData.WriteUint32(status)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write status failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!sendData.WriteInt32(userID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write userID failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::SET_PERMISSION_REQUEST_TOGGLE_STATUS, sendData, reply)) {
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data=%{public}d.", result);
    return result;
}

int32_t AccessTokenManagerProxy::GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status,
    int32_t userID = 0)
{
    MessageParcel sendData;
    if (!sendData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write interface token failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!sendData.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write permissionName failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!sendData.WriteInt32(userID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write userID failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_PERMISSION_REQUEST_TOGGLE_STATUS, sendData, reply)) {
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data=%{public}d.", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    status = reply.ReadUint32();
    return result;
}

int AccessTokenManagerProxy::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag)
{
    MessageParcel sendData;
    sendData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!sendData.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!sendData.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permissionName");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_PERMISSION_FLAG, sendData, reply)) {
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    flag = reply.ReadUint32();
    return result;
}

PermissionOper AccessTokenManagerProxy::GetSelfPermissionsState(std::vector<PermissionListStateParcel>& permListParcel,
    PermissionGrantInfoParcel& infoParcel)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteUint32(permListParcel.size())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permListParcel size.");
        return INVALID_OPER;
    }
    for (const auto& permission : permListParcel) {
        if (!data.WriteParcelable(&permission)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permListParcel.");
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "permListParcel size from server is invalid!");
        return INVALID_OPER;
    }
    if (size > MAX_PERMISSION_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "size = %{public}zu get from request is invalid", size);
        return INVALID_OPER;
    }
    for (uint32_t i = 0; i < size; i++) {
        sptr<PermissionListStateParcel> permissionReq = reply.ReadParcelable<PermissionListStateParcel>();
        if (permissionReq != nullptr) {
            permListParcel[i].permsState.state = permissionReq->permsState.state;
        }
    }

    sptr<PermissionGrantInfoParcel> resultSptr = reply.ReadParcelable<PermissionGrantInfoParcel>();
    if (resultSptr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "read permission grant info parcel fail");
        return INVALID_OPER;
    }
    infoParcel = *resultSptr;

    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

int32_t AccessTokenManagerProxy::GetPermissionsStatus(AccessTokenID tokenID,
    std::vector<PermissionListStateParcel>& permListParcel)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(permListParcel.size())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permListParcel size.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    for (const auto& permission : permListParcel) {
        if (!data.WriteParcelable(&permission)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permListParcel.");
            return ERR_WRITE_PARCEL_FAILED;
        }
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_PERMISSIONS_STATUS, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    size_t size = reply.ReadUint32();
    if (size != permListParcel.size()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permListParcel size from server is invalid!");
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
    inData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!inData.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!inData.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permissionName");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!inData.WriteUint32(flag)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write flag");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GRANT_PERMISSION, inData, reply)) {
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

int AccessTokenManagerProxy::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permissionName");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(flag)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write flag");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::REVOKE_PERMISSION, data, reply)) {
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

int AccessTokenManagerProxy::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::CLEAR_USER_GRANT_PERMISSION, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

int32_t AccessTokenManagerProxy::RegisterPermStateChangeCallback(
    const PermStateChangeScopeParcel& scope, const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteParcelable(&scope)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write PermStateChangeScopeParcel.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write remote object.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::REGISTER_PERM_STATE_CHANGE_CALLBACK, data, reply)) {
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    int32_t ret;
    if (!reply.ReadInt32(ret)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 fail");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", ret);
    return ret;
}

int32_t AccessTokenManagerProxy::UnRegisterPermStateChangeCallback(const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write remote object.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(
        AccessTokenInterfaceCode::UNREGISTER_PERM_STATE_CHANGE_CALLBACK, data, reply)) {
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result;
    if (!reply.ReadInt32(result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadInt32 fail");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

AccessTokenIDEx AccessTokenManagerProxy::AllocHapToken(
    const HapInfoParcel& hapInfo, const HapPolicyParcel& policyParcel)
{
    MessageParcel data;
    AccessTokenIDEx res = { 0 };
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInterfaceToken failed.");
        return res;
    }

    if (!data.WriteParcelable(&hapInfo)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteParcelable hapInfo failed.");
        return res;
    }
    if (!data.WriteParcelable(&policyParcel)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteParcelable policyParcel failed.");
        return res;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::ALLOC_TOKEN_HAP, data, reply)) {
        return res;
    }

    unsigned long long result = reply.ReadUint64();
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}llu.", result);
    res.tokenIDEx = result;
    return res;
}

int32_t AccessTokenManagerProxy::InitHapToken(const HapInfoParcel& hapInfoParcel, HapPolicyParcel& policyParcel,
    AccessTokenIDEx& fullTokenId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteInterfaceToken failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteParcelable(&hapInfoParcel)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteParcelable hapInfo failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteParcelable(&policyParcel)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "WriteParcelable policyParcel failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::INIT_TOKEN_HAP, data, reply)) {
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    int32_t result = 0;
    if (!reply.ReadInt32(result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to read result.");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    if (result != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Result error = %{public}d.", result);
        return result;
    }
    uint64_t tokenId;
    if (!reply.ReadUint64(tokenId)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to read fullTokenId.");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    fullTokenId.tokenIDEx = tokenId;
    return RET_SUCCESS;
}

int AccessTokenManagerProxy::DeleteToken(AccessTokenID tokenID)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());

    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::TOKEN_DELETE, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID = %{public}u, result = %{public}d", tokenID, result);
    return result;
}

int AccessTokenManagerProxy::GetTokenType(AccessTokenID tokenID)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());

    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_TOKEN_TYPE, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int result = reply.ReadInt32();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "result from server data = %{public}d", result);
    return result;
}

int AccessTokenManagerProxy::CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());

    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(dcap)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write dcap");
        return ERR_WRITE_PARCEL_FAILED;
    }
    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::CHECK_NATIVE_DCAP, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

AccessTokenIDEx AccessTokenManagerProxy::GetHapTokenID(int32_t userID, const std::string& bundleName, int32_t instIndex)
{
    AccessTokenIDEx tokenIdEx = {0};
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());

    if (!data.WriteInt32(userID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write tokenID");
        return tokenIdEx;
    }
    if (!data.WriteString(bundleName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write dcap");
        return tokenIdEx;
    }
    if (!data.WriteInt32(instIndex)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write dcap");
        return tokenIdEx;
    }
    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_HAP_TOKEN_ID, data, reply)) {
        return tokenIdEx;
    }

    tokenIdEx.tokenIDEx = reply.ReadUint64();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "result from server data = %{public}llu", tokenIdEx.tokenIDEx);
    return tokenIdEx;
}

AccessTokenID AccessTokenManagerProxy::AllocLocalTokenID(
    const std::string& remoteDeviceID, AccessTokenID remoteTokenID)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());

    if (!data.WriteString(remoteDeviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write dcap");
        return 0;
    }
    if (!data.WriteUint32(remoteTokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write dcap");
        return 0;
    }
    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::ALLOC_LOCAL_TOKEN_ID, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    AccessTokenID result = reply.ReadUint32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

int AccessTokenManagerProxy::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& nativeTokenInfoRes)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permissionName");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_NATIVE_TOKENINFO, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    sptr<NativeTokenInfoParcel> resultSptr = reply.ReadParcelable<NativeTokenInfoParcel>();
    if (resultSptr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable fail");
        return ERR_READ_PARCEL_FAILED;
    }
    nativeTokenInfoRes = *resultSptr;
    return result;
}

int AccessTokenManagerProxy::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& hapTokenInfoRes)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permissionName");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_HAP_TOKENINFO, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    sptr<HapTokenInfoParcel> resultSptr = reply.ReadParcelable<HapTokenInfoParcel>();
    if (resultSptr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable fail");
        return ERR_READ_PARCEL_FAILED;
    }
    hapTokenInfoRes = *resultSptr;
    return result;
}

int32_t AccessTokenManagerProxy::UpdateHapToken(
    AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info, const HapPolicyParcel& policyParcel)
{
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteBool(info.isSystemApp)) {
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(info.appIDDesc)) {
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteInt32(info.apiVersion)) {
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString(info.appDistributionType)) {
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteParcelable(&policyParcel)) {
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::UPDATE_HAP_TOKEN, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }
    int32_t result = reply.ReadInt32();
    tokenIdEx.tokenIdExStruct.tokenAttr = reply.ReadUint32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

#ifndef ATM_BUILD_VARIANT_USER_ENABLE
int32_t AccessTokenManagerProxy::ReloadNativeTokenInfo()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return ERR_WRITE_PARCEL_FAILED;
    }
    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::RELOAD_NATIVE_TOKEN_INFO, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}
#endif

AccessTokenID AccessTokenManagerProxy::GetNativeTokenId(const std::string& processName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return INVALID_TOKENID;
    }

    if (!data.WriteString(processName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write processName");
        return INVALID_TOKENID;
    }
    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_NATIVE_TOKEN_ID, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }
    AccessTokenID result;
    if (!reply.ReadUint32(result)) {
        ACCESSTOKEN_LOG_INFO(LABEL, "readInt32 failed, result: %{public}d", result);
        return INVALID_TOKENID;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "result from server data = %{public}d", result);
    return result;
}

#ifdef TOKEN_SYNC_ENABLE
int AccessTokenManagerProxy::GetHapTokenInfoFromRemote(AccessTokenID tokenID,
    HapTokenInfoForSyncParcel& hapSyncParcel)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteUint32(tokenID)) {
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_HAP_TOKEN_FROM_REMOTE, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    sptr<HapTokenInfoForSyncParcel> hapResult = reply.ReadParcelable<HapTokenInfoForSyncParcel>();
    if (hapResult == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable fail");
        return ERR_READ_PARCEL_FAILED;
    }
    hapSyncParcel = *hapResult;
    return result;
}

int AccessTokenManagerProxy::GetAllNativeTokenInfo(std::vector<NativeTokenInfoForSyncParcel>& nativeTokenInfoRes)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_ALL_NATIVE_TOKEN_FROM_REMOTE, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    uint32_t size = reply.ReadUint32();
    if (size > MAX_NATIVE_TOKEN_INFO_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "size = %{public}d get from request is invalid", size);
        return ERR_OVERSIZE;
    }
    for (uint32_t i = 0; i < size; i++) {
        sptr<NativeTokenInfoForSyncParcel> nativeResult = reply.ReadParcelable<NativeTokenInfoForSyncParcel>();
        if (nativeResult != nullptr) {
            nativeTokenInfoRes.emplace_back(*nativeResult);
        }
    }

    return result;
}

int AccessTokenManagerProxy::SetRemoteHapTokenInfo(const std::string& deviceID,
    HapTokenInfoForSyncParcel& hapSyncParcel)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
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
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

int AccessTokenManagerProxy::SetRemoteNativeTokenInfo(const std::string& deviceID,
    std::vector<NativeTokenInfoForSyncParcel>& nativeTokenInfoForSyncParcel)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteString(deviceID)) {
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteUint32(nativeTokenInfoForSyncParcel.size())) {
        return ERR_WRITE_PARCEL_FAILED;
    }
    for (const NativeTokenInfoForSyncParcel& parcel : nativeTokenInfoForSyncParcel) {
        if (!data.WriteParcelable(&parcel)) {
            return ERR_WRITE_PARCEL_FAILED;
        }
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::SET_REMOTE_NATIVE_TOKEN_INFO, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
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
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

AccessTokenID AccessTokenManagerProxy::GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteString(deviceID)) {
        return 0;
    }

    if (!data.WriteUint32(tokenID)) {
        return 0;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_NATIVE_REMOTE_TOKEN, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    AccessTokenID result = reply.ReadUint32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

int AccessTokenManagerProxy::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!data.WriteString(deviceID)) {
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::DELETE_REMOTE_DEVICE_TOKEN, data, reply)) {
        return ERR_SERVICE_ABNORMAL;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    return result;
}

int32_t AccessTokenManagerProxy::RegisterTokenSyncCallback(const sptr<IRemoteObject>& callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write WriteInterfaceToken failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteRemoteObject(callback)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write remote object failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(
        AccessTokenInterfaceCode::REGISTER_TOKEN_SYNC_CALLBACK, data, reply)) {
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result;
    if (!reply.ReadInt32(result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Read Int32 failed");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", result);
    return result;
}

int32_t AccessTokenManagerProxy::UnRegisterTokenSyncCallback()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write WriteInterfaceToken failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(
        AccessTokenInterfaceCode::UNREGISTER_TOKEN_SYNC_CALLBACK, data, reply)) {
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    int32_t result;
    if (!reply.ReadInt32(result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Read Int32 failed");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Result from server data = %{public}d", result);
    return result;
}
#endif

void AccessTokenManagerProxy::DumpTokenInfo(const AtmToolsParamInfoParcel& infoParcel, std::string& dumpInfo)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());

    if (!data.WriteParcelable(&infoParcel)) {
        return;
    }
    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::DUMP_TOKENINFO, data, reply)) {
        return;
    }
    if (!reply.ReadString(dumpInfo)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadString failed.");
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server dumpInfo = %{public}s", dumpInfo.c_str());
}

int32_t AccessTokenManagerProxy::DumpPermDefInfo(std::string& dumpInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write interface token failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::DUMP_PERM_DEFINITION_INFO, data, reply)) {
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_INFO(LABEL, "result from server data = %{public}d", result);
    if (result != RET_SUCCESS) {
        return result;
    }
    if (!reply.ReadString(dumpInfo)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadString failed.");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    return result;
}

int32_t AccessTokenManagerProxy::GetVersion(uint32_t& version)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Write interface token failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::GET_VERSION, data, reply)) {
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    int32_t result = reply.ReadInt32();
    if (result != RET_SUCCESS) {
        return result;
    }
    if (!reply.ReadUint32(version)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ReadUint32 failed.");
        return AccessTokenError::ERR_READ_PARCEL_FAILED;
    }
    return result;
}

int32_t AccessTokenManagerProxy::SetPermDialogCap(const HapBaseInfoParcel& hapBaseInfo, bool enable)
{
    MessageParcel data;
    data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());

    if (!data.WriteParcelable(&hapBaseInfo)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "write hapBaseInfo failed");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteBool(enable)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "write enable failed");
        return ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel reply;
    if (!SendRequest(AccessTokenInterfaceCode::SET_PERM_DIALOG_CAPABILITY, data, reply)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "read replay failed");
        return ERR_SERVICE_ABNORMAL;
    }
    return reply.ReadInt32();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
