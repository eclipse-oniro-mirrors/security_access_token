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

#include "perm_disable_policy_cbk_proxy.h"

#include "accesstoken_common_log.h"
#include "perm_disable_policy_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

PermDisablePolicyCbkProxy::PermDisablePolicyCbkProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<IPermDisablePolicyCallback>(impl) {
}

PermDisablePolicyCbkProxy::~PermDisablePolicyCbkProxy()
{}

void PermDisablePolicyCbkProxy::PermDisablePolicyCallback(const PermDisablePolicyInfo& info)
{
    MessageParcel data;
    data.WriteInterfaceToken(IPermDisablePolicyCallback::GetDescriptor());

    PermDisablePolicyParcel parcel;
    parcel.info = info;
    if (!data.WriteParcelable(&parcel)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to WriteParcelable!");
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
        static_cast<uint32_t>(PrivacyDisableChangeInterfaceCode::PERM_DISABLE_POLICY_CHANGE), data, reply, option);
    if (requestResult != NO_ERROR) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Send request fail, result: %{public}d", requestResult);
        return;
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
