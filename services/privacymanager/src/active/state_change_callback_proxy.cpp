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

#include "state_change_callback_proxy.h"

#include "accesstoken_log.h"
#include "perm_active_response_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "StateChangeCallbackProxy"
};
}

StateChangeCallbackProxy::StateChangeCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IStateChangeCallback>(impl) {
}

StateChangeCallbackProxy::~StateChangeCallbackProxy()
{}

void StateChangeCallbackProxy::StateChangeNotify(AccessTokenID tokenId, bool isShowing)
{
    MessageParcel data;
    data.WriteInterfaceToken(IStateChangeCallback::GetDescriptor());

    if (!data.WriteUint32(tokenId)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to Write tokenId");
        return;
    }

    if (!data.WriteBool(isShowing)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to Write isShowing");
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remote service null.");
        return;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(IStateChangeCallback::STATE_CHANGE_CALLBACK), data, reply, option);
    if (requestResult != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "send request fail, result: %{public}d", requestResult);
        return;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "SendRequest success");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
