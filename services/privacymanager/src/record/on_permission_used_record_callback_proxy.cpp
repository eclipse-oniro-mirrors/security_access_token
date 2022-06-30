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

#include "on_permission_used_record_callback_proxy.h"

#include "accesstoken_log.h"
#include "permission_used_result_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "OnPermissionUsedRecordCallbackProxy"
};
}

OnPermissionUsedRecordCallbackProxy::OnPermissionUsedRecordCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<OnPermissionUsedRecordCallback>(impl) {
}

OnPermissionUsedRecordCallbackProxy::~OnPermissionUsedRecordCallbackProxy()
{}

void OnPermissionUsedRecordCallbackProxy::OnQueried(ErrCode code, PermissionUsedResult& result)
{
    MessageParcel data;
    data.WriteInterfaceToken(OnPermissionUsedRecordCallback::GetDescriptor());
    if (!data.WriteInt32(code)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to WriteParcelable(code)");
        return;
    }

    PermissionUsedResultParcel resultParcel;
    resultParcel.result = result;
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
        static_cast<uint32_t>(OnPermissionUsedRecordCallback::ON_QUERIED), data, reply, option);
    if (requestResult != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "send request fail, result: %{public}d", requestResult);
        return;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "SendRequest success");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
