/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "on_permission_used_record_callback_stub.h"

#include "accesstoken_log.h"
#include "constant.h"
#include "permission_used_result_parcel.h"
#include "constant.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "OnPermissionUsedRecordCallbackStub"
};
}

int32_t OnPermissionUsedRecordCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called, code: 0x%{public}x", __func__, code);
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != OnPermissionUsedRecordCallback::GetDescriptor()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return Constant::FAILURE;
    }

    int32_t msgCode =  static_cast<int32_t>(code);
    if (msgCode == OnPermissionUsedRecordCallback::ON_QUERIED) {
        ErrCode errCode = data.ReadInt32();
        PermissionUsedResult result;
        if (errCode != NO_ERROR) {
            OnQueried(errCode, result);
            return Constant::FAILURE;
        }
        sptr<PermissionUsedResultParcel> resultSptr = data.ReadParcelable<PermissionUsedResultParcel>();
        if (resultSptr == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "ReadParcelable fail");
            return Constant::FAILURE;
        }
        ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s errCode: %{public}d", __func__, errCode);
        OnQueried(errCode, resultSptr->result);
    } else {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return NO_ERROR;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
