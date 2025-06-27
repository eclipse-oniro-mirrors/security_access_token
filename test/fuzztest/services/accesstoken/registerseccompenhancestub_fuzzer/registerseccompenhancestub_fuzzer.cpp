/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "registerseccompenhancestub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#include "accesstoken_callbacks.h"
#include "accesstoken_manager_service.h"
#undef private
#include "errors.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "hap_token_info.h"
#include "iaccess_token_manager.h"
#include "on_permission_used_record_callback_stub.h"
#include "permission_used_request.h"
#include "permission_used_request_parcel.h"
#include "securec.h"
#include "token_sync_kit_interface.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
class TokenSyncCallbackImpl : public TokenSyncKitInterface {
public:
    ~TokenSyncCallbackImpl() = default;
    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) const override
    {
        return 0;
    };

    int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) const override
    {
        return 0;
    };

    int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) const override
    {
        return 0;
    };
};
}

    bool RegisterSecCompEnhanceStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        sptr<TokenSyncCallback> callback =
            sptr<TokenSyncCallback>(new (std::nothrow) TokenSyncCallback(std::make_shared<TokenSyncCallbackImpl>()));

        SecCompEnhanceData secData;
        secData.callback = callback->AsObject();
        secData.pid = provider.ConsumeIntegral<int32_t>();
        secData.token = provider.ConsumeIntegral<AccessTokenID>();
        secData.challenge = provider.ConsumeIntegral<uint64_t>();
        secData.sessionId = provider.ConsumeIntegral<uint32_t>();
        secData.seqNum = provider.ConsumeIntegral<uint32_t>();
        if (size < AES_KEY_STORAGE_LEN) {
            return false;
        }
        if (memcpy_s(secData.key, AES_KEY_STORAGE_LEN, data, AES_KEY_STORAGE_LEN) != EOK) {
            return false;
        }

        SecCompEnhanceDataParcel enhance;
        enhance.enhanceData = secData;

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteParcelable(&enhance)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_REGISTER_SEC_COMP_ENHANCE);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);

        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::RegisterSecCompEnhanceStubFuzzTest(data, size);
    return 0;
}
