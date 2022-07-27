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

#include "permission_state_change_callback_stub.h"

#include "access_token.h"
#include "accesstoken_log.h"
#include "permission_state_change_info_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "PermissionStateChangeCallbackStub"
};
}

int32_t PermissionStateChangeCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry, code: 0x%{public}x", code);
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IPermissionStateCallback::GetDescriptor()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return RET_FAILED;
    }

    int32_t msgCode =  static_cast<int32_t>(code);
    if (msgCode == IPermissionStateCallback::PERMISSION_STATE_CHANGE) {
        PermStateChangeInfo result;
        sptr<PermissionStateChangeInfoParcel> resultSptr = data.ReadParcelable<PermissionStateChangeInfoParcel>();
        if (resultSptr == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable fail");
            return RET_FAILED;
        }

        PermStateChangeCallback(resultSptr->changeInfo);
    } else {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
