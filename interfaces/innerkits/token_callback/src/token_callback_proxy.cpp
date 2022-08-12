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

#include "token_callback_proxy.h"

#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenCallbackProxy"
};
static const int32_t LIST_SIZE_MAX = 1024;
}

TokenCallbackProxy::TokenCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<ITokenCallback>(impl) {
}

TokenCallbackProxy::~TokenCallbackProxy()
{}

void TokenCallbackProxy::GrantResultsCallback(
    const std::vector<std::string> &permissions, const std::vector<int> &grantResults)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(ITokenCallback::GetDescriptor())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get unexpect descriptor");
        return;
    }

    uint32_t listSize = permissions.size();
    uint32_t resultSize = grantResults.size();
    if ((listSize > LIST_SIZE_MAX) || (resultSize != listSize)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "listSize %{public}d or resultSize %{public}d is invalid", listSize, resultSize);
        return;
    }
    if (!data.WriteUint32(listSize)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write listSize");
        return;
    }
    for (uint32_t i = 0; i < listSize; i++) {
        if (!data.WriteString(permissions[i])) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permList[%{public}d], %{public}s", i, permissions[i].c_str());
            return;
        }
    }

    if (!data.WriteUint32(resultSize)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write resultSize");
        return;
    }
    for (uint32_t i = 0; i < resultSize; i++) {
        if (!data.WriteInt32(grantResults[i])) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write permList[%{public}d], %{public}d", i, grantResults[i]);
            return;
        }
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remote service null.");
        return;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(ITokenCallback::GRANT_RESULT_CALLBACK), data, reply, option);
    if (requestResult != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "send request fail, result: %{public}d", requestResult);
        return;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "SendRequest success");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
