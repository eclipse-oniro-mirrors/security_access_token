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

#include "power_manager_proxy.h"
#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool PowerMgrProxy::IsScreenOn()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE(PRI_DOMAIN, PRI_TAG, "WriteInterfaceToken failed");
        return false;
    }
    bool needPrintLog = true;
    if (!data.WriteBool(needPrintLog)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "WriteBool failed");
        return false;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Remote service is null.");
        return false;
    }
    int32_t error = remote->SendRequest(static_cast<uint32_t>(IPowerMgr::Message::IS_SCREEN_ON), data, reply, option);
    if (error != ERR_NONE) {
        LOGE(PRI_DOMAIN, PRI_TAG, "IsScreenOn failed, error: %{public}d", error);
        return false;
    }
    return reply.ReadBool();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
