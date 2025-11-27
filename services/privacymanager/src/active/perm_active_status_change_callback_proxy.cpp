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

#include "perm_active_status_change_callback_proxy.h"

#include "accesstoken_common_log.h"
#include "active_change_response_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

PermActiveStatusChangeCallbackProxy::PermActiveStatusChangeCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IPermActiveStatusCallback>(impl) {
}

PermActiveStatusChangeCallbackProxy::~PermActiveStatusChangeCallbackProxy()
{}

void PermActiveStatusChangeCallbackProxy::ActiveStatusChangeCallback(ActiveChangeResponse& result)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPermActiveStatusCallback::GetDescriptor());

    ActiveChangeResponseParcel resultParcel;
    resultParcel.changeResponse = result;
    if (!data.WriteParcelable(&resultParcel)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to WriteParcelable");
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Remote service null.");
        return;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(PrivacyActiveChangeInterfaceCode::PERM_ACTIVE_STATUS_CHANGE), data, reply, option);
    if (requestResult != NO_ERROR) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Send request fail, result: %{public}d", requestResult);
        return;
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
