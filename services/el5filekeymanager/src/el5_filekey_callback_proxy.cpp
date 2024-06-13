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

#include "el5_filekey_callback_proxy.h"
#include "el5_filekey_manager_error.h"
#include "el5_filekey_manager_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
El5FilekeyCallbackProxy::El5FilekeyCallbackProxy(const sptr<IRemoteObject>& impl)
    : IRemoteProxy<El5FilekeyCallbackInterface>(impl) {
}

El5FilekeyCallbackProxy::~El5FilekeyCallbackProxy()
{
}

void El5FilekeyCallbackProxy::OnRegenerateAppKey(std::vector<AppKeyInfo> &infos)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(El5FilekeyCallbackInterface::GetDescriptor())) {
        LOG_ERROR("Failed to write WriteInterfaceToken.");
        return;
    }
    if (!data.WriteUint32(infos.size())) {
        LOG_ERROR("Failed to WriteUint32(%{public}d).", static_cast<uint32_t>(infos.size()));
        return;
    }
    for (AppKeyInfo info : infos) {
        if (!data.WriteParcelable(&info)) {
            LOG_ERROR("Failed to write AppKeyInfo.");
            return;
        }
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERROR("Remote service is null.");
        return;
    }

    int32_t result = remote->SendRequest(
        static_cast<int32_t>(El5FilekeyCallbackInterface::Code::ON_REGENERATE_APP_KEY), data, reply, option);
    if (result != NO_ERROR) {
        LOG_ERROR("SendRequest failed, result: %{public}d.", result);
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
