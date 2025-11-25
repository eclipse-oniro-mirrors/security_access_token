/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "accesstoken_compat_proxy.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
using namespace OHOS::Security::AccessToken;

int32_t AccessTokenCompatProxy::VerifyAccessToken(uint32_t tokenID, const std::string& permissionName, int32_t& state)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write interface token failed!");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write [tokenID] failed!");
        return ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteString16(Str8ToStr16(permissionName))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write [permissionName] failed!");
        return ERR_WRITE_PARCEL_FAILED;
    }

    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remote is nullptr!");
        return ERROR_IPC_REQUEST_FAIL;
    }
    int32_t result = remote->SendRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_VERIFY_ACCESS_TOKEN), data, reply, option);
    if (FAILED(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Send request failed, err:%{public}d!", result);
        return result;
    }

    int32_t errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read result failed, code is: %{public}d, errCode is %{public}d.",
            static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_VERIFY_ACCESS_TOKEN), errCode);
        return errCode;
    }

    state = reply.ReadInt32();
    return ERR_OK;
}

int32_t AccessTokenCompatProxy::GetNativeTokenId(const std::string& processName, uint32_t& tokenID)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write interface token failed!");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteString16(Str8ToStr16(processName))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write [processName] failed!");
        return ERR_WRITE_PARCEL_FAILED;
    }

    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remote is nullptr!");
        return ERROR_IPC_REQUEST_FAIL;
    }
    int32_t result = remote->SendRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_NATIVE_TOKEN_ID), data, reply, option);
    if (FAILED(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Send request failed, err:%{public}d!", result);
        return result;
    }

    int32_t err = reply.ReadInt32();
    if (FAILED(err)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read result failed, code is: %{public}d, process: %{public}s, err: %{public}d.",
            static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_NATIVE_TOKEN_ID), processName.c_str(), err);
        return err;
    }

    tokenID = reply.ReadUint32();
    return ERR_OK;
}

int32_t AccessTokenCompatProxy::GetHapTokenInfo(uint32_t tokenID, HapTokenInfoCompatParcel& hapTokenInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write interface token failed!");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteUint32(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write [tokenID] failed!");
        return ERR_WRITE_PARCEL_FAILED;
    }

    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remote is nullptr!");
        return ERROR_IPC_REQUEST_FAIL;
    }
    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_GET_HAP_TOKEN_INFO_IN_UNSIGNED_INT_OUT_HAPTOKENINFOCOMPATIDL);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (FAILED(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Send request failed, err:%{public}d!", result);
        return result;
    }

    int32_t errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read result failed, code is: %{public}d, errCode is %{public}d.", code, errCode);
        return errCode;
    }

    if (HapTokenInfoCompatUnmarshalling(reply, hapTokenInfo) != ERR_NONE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read [hapTokenInfo] failed!");
        return ERR_READ_PARCEL_FAILED;
    }
    return ERR_OK;
}

int32_t AccessTokenCompatProxy::GetPermissionCode(const std::string& permission, uint32_t& permCode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write interface token failed!");
        return ERR_WRITE_PARCEL_FAILED;
    }

    if (!data.WriteString16(Str8ToStr16(permission))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write [permission] failed!");
        return ERR_WRITE_PARCEL_FAILED;
    }

    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remote is nullptr!");
        return ERROR_IPC_REQUEST_FAIL;
    }
    int32_t result = remote->SendRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_PERMISSION_CODE), data, reply, option);
    if (FAILED(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Send request failed, err:%{public}d!", result);
        return result;
    }

    int32_t errCode = reply.ReadInt32();
    if (FAILED(errCode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Read result failed, code is: %{public}d, errCode is %{public}d.",
            static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_PERMISSION_CODE), errCode);
        return errCode;
    }

    permCode = reply.ReadUint32();
    return ERR_OK;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
