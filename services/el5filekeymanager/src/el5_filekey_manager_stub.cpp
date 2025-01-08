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

#include "el5_filekey_manager_stub.h"

#include "el5_filekey_manager_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr uint32_t MAX_KEY_SIZE = 1000;
}

El5FilekeyManagerStub::El5FilekeyManagerStub()
{
    SetFuncInMap();
}

El5FilekeyManagerStub::~El5FilekeyManagerStub()
{
    requestMap_.clear();
}

void El5FilekeyManagerStub::SetFuncInMap()
{
    requestMap_[static_cast<uint32_t>(EFMInterfaceCode::GENERATE_APP_KEY)] =
        &El5FilekeyManagerStub::GenerateAppKeyInner;
    requestMap_[static_cast<uint32_t>(EFMInterfaceCode::DELETE_APP_KEY)] =
        &El5FilekeyManagerStub::DeleteAppKeyInner;
    requestMap_[static_cast<uint32_t>(EFMInterfaceCode::ACQUIRE_ACCESS)] =
        &El5FilekeyManagerStub::AcquireAccessInner;
    requestMap_[static_cast<uint32_t>(EFMInterfaceCode::RELEASE_ACCESS)] =
        &El5FilekeyManagerStub::ReleaseAccessInner;
    requestMap_[static_cast<uint32_t>(EFMInterfaceCode::GET_USER_APP_KEY)] =
        &El5FilekeyManagerStub::GetUserAppKeyInner;
    requestMap_[static_cast<uint32_t>(EFMInterfaceCode::CHANGE_USER_APP_KEYS_LOAD_INFO)] =
        &El5FilekeyManagerStub::ChangeUserAppkeysLoadInfoInner;
    requestMap_[static_cast<uint32_t>(EFMInterfaceCode::SET_FILE_PATH_POLICY)] =
        &El5FilekeyManagerStub::SetFilePathPolicyInner;
    requestMap_[static_cast<uint32_t>(EFMInterfaceCode::REGISTER_CALLBACK)] =
        &El5FilekeyManagerStub::RegisterCallbackInner;
    requestMap_[static_cast<uint32_t>(EFMInterfaceCode::GENERATE_GROUPID_KEY)] =
        &El5FilekeyManagerStub::GenerateGroupIDKeyInner;
    requestMap_[static_cast<uint32_t>(EFMInterfaceCode::DELETE_GROUPID_KEY)] =
        &El5FilekeyManagerStub::DeleteGroupIDKeyInner;
    requestMap_[static_cast<uint32_t>(EFMInterfaceCode::QUERY_APP_KEY_STATE)] =
        &El5FilekeyManagerStub::QueryAppKeyStateInner;
}

int32_t El5FilekeyManagerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (data.ReadInterfaceToken() != El5FilekeyManagerInterface::GetDescriptor()) {
        LOG_ERROR("Get unexpected descriptor");
        return EFM_ERR_IPC_TOKEN_INVALID;
    }

    auto itFunc = requestMap_.find(code);
    if (itFunc != requestMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            (this->*requestFunc)(data, reply);
            return NO_ERROR;
        }
    }

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

void El5FilekeyManagerStub::AcquireAccessInner(MessageParcel &data, MessageParcel &reply)
{
    DataLockType type = static_cast<DataLockType>(data.ReadInt32());
    reply.WriteInt32(this->AcquireAccess(type));
}

void El5FilekeyManagerStub::ReleaseAccessInner(MessageParcel &data, MessageParcel &reply)
{
    DataLockType type = static_cast<DataLockType>(data.ReadInt32());
    reply.WriteInt32(this->ReleaseAccess(type));
}

void El5FilekeyManagerStub::GenerateAppKeyInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t uid = data.ReadUint32();
    std::string bundleName = data.ReadString();
    std::string keyId;
    reply.WriteInt32(this->GenerateAppKey(uid, bundleName, keyId));
    reply.WriteString(keyId);
}

void El5FilekeyManagerStub::DeleteAppKeyInner(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    reply.WriteInt32(this->DeleteAppKey(bundleName, userId));
}

void El5FilekeyManagerStub::GetUserAppKeyInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = data.ReadInt32();
    bool getAllFlag = data.ReadBool();
    std::vector<std::pair<int32_t, std::string>> keyInfos;
    reply.WriteInt32(this->GetUserAppKey(userId, getAllFlag, keyInfos));
    MarshallingKeyInfos(reply, keyInfos);
}

void El5FilekeyManagerStub::ChangeUserAppkeysLoadInfoInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = data.ReadInt32();
    std::vector<std::pair<std::string, bool>> loadInfos;
    int32_t ret = UnmarshallingLoadInfos(data, loadInfos);
    if (ret == EFM_SUCCESS) {
        ret = this->ChangeUserAppkeysLoadInfo(userId, loadInfos);
    }
    reply.WriteInt32(ret);
}

void El5FilekeyManagerStub::SetFilePathPolicyInner(MessageParcel &data, MessageParcel &reply)
{
    reply.WriteInt32(this->SetFilePathPolicy());
}

void El5FilekeyManagerStub::RegisterCallbackInner(MessageParcel &data, MessageParcel &reply)
{
    auto callback = iface_cast<El5FilekeyCallbackInterface>(data.ReadRemoteObject());
    if ((callback == nullptr) || (!callback->AsObject())) {
        LOG_ERROR("Read callback failed.");
        reply.WriteInt32(EFM_ERR_IPC_READ_DATA);
        return;
    }
    reply.WriteInt32(this->RegisterCallback(callback));
}

void El5FilekeyManagerStub::GenerateGroupIDKeyInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t uid = data.ReadUint32();
    std::string groupID = data.ReadString();
    std::string keyId;
    reply.WriteInt32(this->GenerateGroupIDKey(uid, groupID, keyId));
    reply.WriteString(keyId);
}

void El5FilekeyManagerStub::DeleteGroupIDKeyInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t uid = data.ReadUint32();
    std::string groupID = data.ReadString();
    reply.WriteInt32(this->DeleteGroupIDKey(uid, groupID));
}

void El5FilekeyManagerStub::QueryAppKeyStateInner(MessageParcel &data, MessageParcel &reply)
{
    DataLockType type = static_cast<DataLockType>(data.ReadInt32());
    reply.WriteInt32(this->QueryAppKeyState(type));
}

void El5FilekeyManagerStub::MarshallingKeyInfos(MessageParcel &reply,
    std::vector<std::pair<int32_t, std::string>>& keyInfos)
{
    reply.WriteUint32(keyInfos.size());
    for (std::pair<int32_t, std::string> &keyInfo : keyInfos) {
        reply.WriteInt32(keyInfo.first);
        reply.WriteString(keyInfo.second);
    }
}

int32_t El5FilekeyManagerStub::UnmarshallingLoadInfos(MessageParcel &data,
    std::vector<std::pair<std::string, bool>> &loadInfos)
{
    uint32_t loadInfosSize = data.ReadUint32();
    if (loadInfosSize > MAX_KEY_SIZE) {
        LOG_ERROR("Parse loadInfos failed, results oversize %{public}d.", loadInfosSize);
        return EFM_ERR_IPC_READ_DATA;
    }
    for (uint32_t i = 0; i < loadInfosSize; ++i) {
        std::string keyId = data.ReadString();
        bool loadState = data.ReadBool();
        loadInfos.emplace_back(std::make_pair(keyId, loadState));
    }
    return EFM_SUCCESS;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
