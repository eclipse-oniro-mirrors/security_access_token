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

#include "ams_manager_access_proxy.h"
#include "accesstoken_common_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t ERROR = -1;
}
int32_t AmsManagerAccessProxy::KillProcessesByAccessTokenId(const uint32_t accessTokenId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInterfaceToken failed.");
        return ERROR;
    }

    if (!data.WriteInt32(accessTokenId)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteInt32 failed.");
        return ERROR;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remote service is null.");
        return ERROR;
    }
    int32_t error = remote->SendRequest(
        static_cast<uint32_t>(IAmsMgr::Message::FORCE_KILL_APPLICATION_BY_ACCESS_TOKEN_ID), data, reply, option);
    if (error != ERR_NONE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "KillProcessesByAccessTokenId failed, error: %{public}d", error);
        return ERROR;
    }
    return reply.ReadInt32();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
