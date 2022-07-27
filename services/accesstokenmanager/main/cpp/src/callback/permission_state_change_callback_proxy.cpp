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

#include "permission_state_change_callback_proxy.h"

#include "access_token.h"
#include "accesstoken_log.h"
#include "permission_state_change_info_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "PermissionStateChangeCallbackProxy"
};
}

PermissionStateChangeCallbackProxy::PermissionStateChangeCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IPermissionStateCallback>(impl) {
}

PermissionStateChangeCallbackProxy::~PermissionStateChangeCallbackProxy()
{}

void PermissionStateChangeCallbackProxy::PermStateChangeCallback(PermStateChangeInfo& info)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPermissionStateCallback::GetDescriptor());

    PermissionStateChangeInfoParcel resultParcel;
    resultParcel.changeInfo = info;
    if (!data.WriteParcelable(&resultParcel)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteParcelable(result)");
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
        static_cast<uint32_t>(IPermissionStateCallback::PERMISSION_STATE_CHANGE), data, reply, option);
    if (requestResult != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "send request fail, result: %{public}d", requestResult);
        return;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "SendRequest success");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
