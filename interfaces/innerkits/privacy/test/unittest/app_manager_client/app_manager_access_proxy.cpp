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

#include "app_manager_access_proxy.h"
#include "accesstoken_common_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t ERROR = -1;
constexpr int32_t CYCLE_LIMIT = 1000;
}

int32_t AppManagerAccessProxy::GetForegroundApplications(std::vector<AppStateData>& list)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE(PRI_DOMAIN, PRI_TAG, "WriteInterfaceToken failed");
        return ERROR;
    }
    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(IAppMgr::Message::GET_FOREGROUND_APPLICATIONS), data, reply, option);
    if (error != ERR_NONE) {
        LOGE(PRI_DOMAIN, PRI_TAG, "GetForegroundApplications failed, error: %{public}d", error);
        return error;
    }
    uint32_t infoSize = reply.ReadUint32();
    if (infoSize > CYCLE_LIMIT) {
        LOGE(PRI_DOMAIN, PRI_TAG, "InfoSize is too large");
        return ERROR;
    }
    for (uint32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<AppStateData> info(reply.ReadParcelable<AppStateData>());
        if (info != nullptr) {
            list.emplace_back(*info);
        }
    }
    return reply.ReadInt32();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
