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

#include "perm_active_status_change_callback_stub.h"

#include "accesstoken_log.h"
#include "perm_active_response_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PermActiveStatusChangeCallbackStub"
};
}

int32_t PermActiveStatusChangeCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry, code: 0x%{public}x", code);
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IPermActiveStatusCallback::GetDescriptor()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return RET_FAILED;
    }

    int32_t msgCode =  static_cast<int32_t>(code);
    if (msgCode == IPermActiveStatusCallback::PERM_ACTIVE_STATUS_CHANGE) {
        sptr<ActiveChangeResponseParcel> resultSptr = data.ReadParcelable<ActiveChangeResponseParcel>();
        if (resultSptr == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable fail");
            return RET_FAILED;
        }

        ActiveStatusChangeCallback(resultSptr->changeResponse);
    } else {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
