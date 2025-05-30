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

#include "form_manager_access_proxy.h"
#include "accesstoken_common_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t ERROR = -1;
}

int32_t FormManagerAccessProxy::RegisterAddObserver(
    const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERROR;
    }
    if (!data.WriteString(bundleName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write bundleName failed.");
        return ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write callerToken failed.");
        return ERROR;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remote service is null.");
        return ERROR;
    }
    int32_t error = remote->SendRequest(
        static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_ADD_OBSERVER), data, reply, option);
    if (error != ERR_NONE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "RegisterAddObserver failed, error: %{public}d", error);
        return ERROR;
    }
    return reply.ReadInt32();
}

int32_t FormManagerAccessProxy::RegisterRemoveObserver(
    const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERROR;
    }
    if (!data.WriteString(bundleName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write bundleName failed.");
        return ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Write callerToken failed.");
        return ERROR;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remote service is null.");
        return ERROR;
    }
    int32_t error = remote->SendRequest(
        static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_REMOVE_OBSERVER), data, reply, option);
    if (error != ERR_NONE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "UnregisterAddObserver failed, error: %d", error);
        return error;
    }
    return reply.ReadInt32();
}

bool FormManagerAccessProxy::HasFormVisible(const uint32_t tokenId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return false;
    }
    if (!data.WriteUint32(tokenId)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write tokenId.");
        return false;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remote service is null.");
        return false;
    }
    int32_t error = remote->SendRequest(
        static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_HAS_FORM_VISIBLE_WITH_TOKENID), data, reply, option);
    if (error != ERR_NONE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get form visibility failed, error: %{public}d", error);
        return false;
    }
    return reply.ReadBool();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
