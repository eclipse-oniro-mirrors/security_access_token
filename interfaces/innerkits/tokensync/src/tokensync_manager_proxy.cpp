/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "tokensync_manager_proxy.h"

#include "accesstoken_log.h"

#include "parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace TokenSync {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenSyncManagerProxy"};
}

TokenSyncManagerProxy::TokenSyncManagerProxy(const sptr<IRemoteObject>& impl) : IRemoteProxy<ITokenSyncManager>(impl)
{}

TokenSyncManagerProxy::~TokenSyncManagerProxy()
{}

int TokenSyncManagerProxy::VerifyPermission(
    const std::string& bundleName, const std::string& permissionName, int userId)
{
    MessageParcel data;
    data.WriteInterfaceToken(ITokenSyncManager::GetDescriptor());
    if (!data.WriteString(bundleName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: Failed to write bundleName", __func__);
        return -1;
    }
    if (!data.WriteString(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: Failed to write permissionName", __func__);
        return -1;
    }
    if (!data.WriteInt32(userId)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: Failed to write userId", __func__);
        return -1;
    }

    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: remote service null.", __func__);
        return -1;
    }
    int32_t requestResult = remote->SendRequest(
        static_cast<uint32_t>(ITokenSyncManager::InterfaceCode::VERIFY_PERMISSION), data, reply, option);
    if (requestResult != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s send request fail, result: %{public}d", __func__, requestResult);
        return -1;
    }

    int32_t result = reply.ReadInt32();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s get result from server data = %{public}d", __func__, result);
    return result;
}
} // namespace TokenSync
} // namespace Security
} // namespace OHOS
