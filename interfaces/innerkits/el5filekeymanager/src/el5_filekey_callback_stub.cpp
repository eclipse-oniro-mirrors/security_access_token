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

#include "el5_filekey_callback_stub.h"
#include "el5_filekey_manager_error.h"
#include "el5_filekey_manager_log.h"
#include "parcel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
El5FilekeyCallbackStub::El5FilekeyCallbackStub()
{
}

El5FilekeyCallbackStub::~El5FilekeyCallbackStub()
{
}

int32_t El5FilekeyCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    if (data.ReadInterfaceToken() != El5FilekeyCallbackInterface::GetDescriptor()) {
        LOG_ERROR("get unexpected descriptor");
        return EFM_ERR_IPC_TOKEN_INVALID;
    }
    if (code == static_cast<uint32_t>(El5FilekeyCallbackInterface::Code::ON_REGENERATE_APP_KEY)) {
        std::vector<AppKeyInfo> infos;
        uint32_t infosSize = data.ReadUint32();
        if (infosSize > MAX_RECORD_SIZE) {
            LOG_ERROR("Parse infos failed, results oversize %{public}d.", infosSize);
            return EFM_ERR_IPC_READ_DATA;
        }
        for (uint32_t i = 0; i < infosSize; ++i) {
            sptr<AppKeyInfo> info = data.ReadParcelable<AppKeyInfo>();
            if (info == nullptr) {
                LOG_ERROR("Parse AppKetInfo failed.");
                return EFM_ERR_IPC_READ_DATA;
            }
            infos.emplace_back(*info);
        }
        OnRegenerateAppKey(infos);
        return NO_ERROR;
    } else {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
