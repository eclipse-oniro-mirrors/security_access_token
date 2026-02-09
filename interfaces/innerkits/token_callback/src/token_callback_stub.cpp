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

#include "token_callback_stub.h"

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "string_ex.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const int32_t LIST_SIZE_MAX = 200;
static const int32_t FAILED = -1;
}

static std::string to_utf8(std::u16string str16)
{
    return std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {}.to_bytes(str16);
}

int32_t TokenCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Entry, code: 0x%{public}x", code);
    std::u16string descriptor = data.ReadInterfaceToken();
    if (descriptor != ITokenCallback::GetDescriptor()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get unexpect descriptor: %{public}s", Str16ToStr8(descriptor).c_str());
        return ERROR_IPC_REQUEST_FAIL;
    }

    int32_t msgCode =  static_cast<int32_t>(code);
    if (msgCode == ITokenCallback::GRANT_RESULT_CALLBACK) {
        uint32_t permListSize;
        if (!data.ReadUint32(permListSize)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to read permListSize.");
            return FAILED;
        }
        if (permListSize > LIST_SIZE_MAX) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Read permListSize fail %{public}u", permListSize);
            return FAILED;
        }
        std::vector<std::string> permList;
        for (uint32_t i = 0; i < permListSize; i++) {
            std::u16string u16Perm;
            if (!data.ReadString16(u16Perm)) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Failed to read permission at index %{public}u.", i);
                return FAILED;
            }
            std::string perm = to_utf8(u16Perm);
            permList.emplace_back(perm);
        }

        uint32_t statusListSize;
        if (!data.ReadUint32(statusListSize)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to read statusListSize.");
            return FAILED;
        }
        if (statusListSize != permListSize) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Read statusListSize fail %{public}u", statusListSize);
            return FAILED;
        }
        std::vector<int32_t> grantResults;
        for (uint32_t i = 0; i < permListSize; i++) {
            int32_t res;
            if (!data.ReadInt32(res)) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Failed to read grant result at index %{public}u.", i);
                return FAILED;
            }
            grantResults.emplace_back(res);
        }
        GrantResultsCallback(permList, grantResults);
    } else if (msgCode == ITokenCallback::WINDOW_DESTORY_CALLBACK) {
        WindowShownCallback();
    } else {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return 0;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS