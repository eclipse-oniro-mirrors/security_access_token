/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "el5_filekey_manager_proxy.h"

#include "el5_filekey_manager_error.h"
#include "el5_filekey_manager_log.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
El5FilekeyManagerProxy::El5FilekeyManagerProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<El5FilekeyManagerInterface>(impl)
{
}

El5FilekeyManagerProxy::~El5FilekeyManagerProxy()
{
}

int32_t El5FilekeyManagerProxy::AcquireAccess(DataLockType type)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor())) {
        LOG_ERROR("Failed to write WriteInterfaceToken.");
        return EFM_ERR_IPC_WRITE_DATA;
    }
    if (!data.WriteInt32(static_cast<int32_t>(type))) {
        LOG_ERROR("Failed to WriteInt32(%{public}d).", type);
        return EFM_ERR_IPC_WRITE_DATA;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERROR("Remote service is null.");
        return EFM_ERR_REMOTE_CONNECTION;
    }
    int32_t result = remote->SendRequest(static_cast<int32_t>(EFMInterfaceCode::ACQUIRE_ACCESS), data, reply, option);
    if (result != NO_ERROR) {
        LOG_ERROR("SendRequest failed, result: %{public}d.", result);
    } else {
        result = reply.ReadInt32();
    }
    return result;
}

int32_t El5FilekeyManagerProxy::ReleaseAccess(DataLockType type)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor())) {
        LOG_ERROR("Failed to write WriteInterfaceToken.");
        return EFM_ERR_IPC_WRITE_DATA;
    }
    if (!data.WriteInt32(static_cast<int32_t>(type))) {
        LOG_ERROR("Failed to WriteInt32(%{public}d).", type);
        return EFM_ERR_IPC_WRITE_DATA;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERROR("Remote service is null.");
        return EFM_ERR_REMOTE_CONNECTION;
    }
    int32_t result = remote->SendRequest(static_cast<int32_t>(EFMInterfaceCode::RELEASE_ACCESS), data, reply, option);
    if (result != NO_ERROR) {
        LOG_ERROR("SendRequest failed, result: %{public}d.", result);
    } else {
        result = reply.ReadInt32();
    }
    return result;
}

int32_t El5FilekeyManagerProxy::GenerateAppKey(uint32_t uid, const std::string& bundleName, std::string& keyId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor())) {
        LOG_ERROR("Failed to write WriteInterfaceToken.");
        return EFM_ERR_IPC_WRITE_DATA;
    }
    if (!data.WriteUint32(uid)) {
        LOG_ERROR("Failed to WriteUint32(%{public}d).", uid);
        return EFM_ERR_IPC_WRITE_DATA;
    }
    if (!data.WriteString(bundleName)) {
        LOG_ERROR("Failed to WriteString(%{public}s).", bundleName.c_str());
        return EFM_ERR_IPC_WRITE_DATA;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERROR("Remote service is null.");
        return EFM_ERR_REMOTE_CONNECTION;
    }
    int32_t result = remote->SendRequest(
        static_cast<int32_t>(EFMInterfaceCode::GENERATE_APP_KEY), data, reply, option);
    if (result != NO_ERROR) {
        LOG_ERROR("SendRequest failed, result: %{public}d.", result);
    } else {
        result = reply.ReadInt32();
        keyId = reply.ReadString();
    }
    return result;
}

int32_t El5FilekeyManagerProxy::DeleteAppKey(const std::string& keyId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor())) {
        LOG_ERROR("Failed to write WriteInterfaceToken.");
        return EFM_ERR_IPC_WRITE_DATA;
    }
    if (!data.WriteString(keyId)) {
        LOG_ERROR("Failed to WriteString(%{public}s).", keyId.c_str());
        return EFM_ERR_IPC_WRITE_DATA;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERROR("Remote service is null.");
        return EFM_ERR_REMOTE_CONNECTION;
    }
    int32_t result = remote->SendRequest(static_cast<int32_t>(EFMInterfaceCode::DELETE_APP_KEY), data, reply, option);
    if (result != NO_ERROR) {
        LOG_ERROR("SendRequest failed, result: %{public}d.", result);
    } else {
        result = reply.ReadInt32();
    }
    return result;
}

int32_t El5FilekeyManagerProxy::GetUserAppKey(int32_t userId, std::vector<std::pair<int32_t, std::string>> &keyInfos)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor())) {
        LOG_ERROR("Failed to write WriteInterfaceToken.");
        return EFM_ERR_IPC_WRITE_DATA;
    }
    if (!data.WriteUint32(userId)) {
        LOG_ERROR("Failed to WriteUint32(%{public}d).", userId);
        return EFM_ERR_IPC_WRITE_DATA;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERROR("Remote service is null.");
        return EFM_ERR_REMOTE_CONNECTION;
    }

    int32_t result = remote->SendRequest(
        static_cast<int32_t>(EFMInterfaceCode::GET_USER_APP_KEY), data, reply, option);
    if (result != NO_ERROR) {
        LOG_ERROR("SendRequest failed, result: %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result == EFM_SUCCESS) {
        uint32_t keyInfoSize = reply.ReadUint32();
        if (keyInfoSize > MAX_RECORD_SIZE) {
            LOG_ERROR("Parse keyInfos failed, results oversize %{public}d.", keyInfoSize);
            return EFM_ERR_IPC_READ_DATA;
        }
        for (uint32_t i = 0; i < keyInfoSize; ++i) {
            int32_t uid = reply.ReadInt32();
            std::string keyId = reply.ReadString();
            keyInfos.emplace_back(std::make_pair(uid, keyId));
        }
    }
    return result;
}

int32_t El5FilekeyManagerProxy::ChangeUserAppkeysLoadInfo(int32_t userId,
    std::vector<std::pair<std::string, bool>> &loadInfos)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor())) {
        LOG_ERROR("Failed to write WriteInterfaceToken.");
        return EFM_ERR_IPC_WRITE_DATA;
    }
    if (!data.WriteUint32(userId)) {
        LOG_ERROR("Failed to WriteUint32(%{public}d).", userId);
        return EFM_ERR_IPC_WRITE_DATA;
    }
    if (!data.WriteUint32(loadInfos.size())) {
        LOG_ERROR("Failed to WriteUint32(%{public}d).", static_cast<uint32_t>(loadInfos.size()));
        return EFM_ERR_IPC_WRITE_DATA;
    }
    for (std::pair<std::string, bool> loadInfo : loadInfos) {
        if (!data.WriteString(loadInfo.first)) {
            LOG_ERROR("Failed to write keyId.");
            return EFM_ERR_IPC_WRITE_DATA;
        }
        if (!data.WriteBool(loadInfo.second)) {
            LOG_ERROR("Failed to write load status.");
            return EFM_ERR_IPC_WRITE_DATA;
        }
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERROR("Remote service is null.");
        return EFM_ERR_REMOTE_CONNECTION;
    }

    int32_t result = remote->SendRequest(
        static_cast<int32_t>(EFMInterfaceCode::CHANGE_USER_APP_KEYS_LOAD_INFO), data, reply, option);
    if (result != NO_ERROR) {
        LOG_ERROR("SendRequest failed, result: %{public}d.", result);
    } else {
        result = reply.ReadInt32();
    }
    return result;
}

int32_t El5FilekeyManagerProxy::SetFilePathPolicy()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor())) {
        LOG_ERROR("Failed to write WriteInterfaceToken.");
        return EFM_ERR_IPC_WRITE_DATA;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERROR("Remote service is null.");
        return EFM_ERR_REMOTE_CONNECTION;
    }

    int32_t result = remote->SendRequest(
        static_cast<int32_t>(EFMInterfaceCode::SET_FILE_PATH_POLICY), data, reply, option);
    if (result != NO_ERROR) {
        LOG_ERROR("SendRequest failed, result: %{public}d.", result);
    } else {
        result = reply.ReadInt32();
    }
    return result;
}

int32_t El5FilekeyManagerProxy::RegisterCallback(const sptr<El5FilekeyCallbackInterface> &callback)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor())) {
        LOG_ERROR("Failed to write WriteInterfaceToken.");
        return EFM_ERR_IPC_WRITE_DATA;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        LOG_ERROR("Failed to write callback.");
        return EFM_ERR_IPC_WRITE_DATA;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERROR("Remote service is null.");
        return EFM_ERR_REMOTE_CONNECTION;
    }

    int32_t result = remote->SendRequest(
        static_cast<int32_t>(EFMInterfaceCode::REGISTER_CALLBACK), data, reply, option);
    if (result != NO_ERROR) {
        LOG_ERROR("SendRequest failed, result: %{public}d.", result);
    } else {
        result = reply.ReadInt32();
    }
    return result;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
