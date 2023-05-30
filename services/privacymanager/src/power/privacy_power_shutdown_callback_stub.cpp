/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "privacy_power_shutdown_callback_stub.h"

#include "accesstoken_log.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyPowerShutDownCallbackStub"
};
static const int32_t ERROR = -1;
}

int32_t PrivacyPowerShutDownCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IShutdownCallback::GetDescriptor()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return ERROR;
    }
    switch (code) {
        case static_cast<uint32_t>(IShutdownCallback::POWER_SHUTDOWN_CHANGED):
            ShutdownCallback();
            break;
        
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return NO_ERROR;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
