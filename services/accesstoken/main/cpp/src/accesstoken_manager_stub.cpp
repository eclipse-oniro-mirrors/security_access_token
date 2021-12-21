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

#include "accesstoken_manager_stub.h"

#include "accesstoken.h"
#include "accesstoken_log.h"

#include "ipc_skeleton.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenManagerStub"
};
}

int32_t AccessTokenManagerStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, code: %{public}d", __func__, code);
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IAccessTokenManager::GetDescriptor()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return RET_FAILED;
    }
    switch (code) {
        case static_cast<uint32_t>(IAccessTokenManager::InterfaceCode::VERIFY_ACCESSTOKEN):
            VerifyAccessTokenInner(data, reply);
            break;
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return NO_ERROR;
}

void AccessTokenManagerStub::VerifyAccessTokenInner(MessageParcel& data, MessageParcel& reply)
{
    AccessTokenID tokenID = data.ReadUint32();
    std::string permissionName = data.ReadString();
    int result = this->VerifyAccesstoken(tokenID, permissionName);
    reply.WriteInt32(result);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS