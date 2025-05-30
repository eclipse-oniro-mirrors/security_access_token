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

#include "state_change_callback_stub.h"

#include "accesstoken_common_log.h"
#include "privacy_error.h"
#include "perm_active_response_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

int32_t StateChangeCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "Entry, code: 0x%{public}x", code);
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != IStateChangeCallback::GetDescriptor()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return ERROR_IPC_REQUEST_FAIL;
    }

    int32_t msgCode = static_cast<int32_t>(code);
    if (msgCode == IStateChangeCallback::STATE_CHANGE_CALLBACK) {
        AccessTokenID tokenId = data.ReadUint32();
        bool isShowing = data.ReadBool();

        StateChangeNotify(tokenId, isShowing);
    } else {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
