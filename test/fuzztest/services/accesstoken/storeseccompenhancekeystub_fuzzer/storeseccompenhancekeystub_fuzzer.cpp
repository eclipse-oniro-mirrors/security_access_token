/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "storeseccompenhancekeystub_fuzzer.h"

#include <vector>

#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_service_context_helper.h"
#include "iaccess_token_manager.h"
#include "mock_permission.h"
#include "sec_comp_enhance_key_parcel.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::AccessToken;

namespace {
bool SetSecCompToken()
{
    AccessTokenID token = INVALID_TOKENID;
    {
        MockToken mock({}, false);
        token = AccessTokenKit::GetNativeTokenId("security_component_service");
    }
    return (token != INVALID_TOKENID) && (SetSelfTokenID(token) == 0);
}
}

namespace OHOS {
bool StoreSecCompEnhanceKeyStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0) || !SetSecCompToken()) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    MessageParcel sendData;
    sendData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (provider.ConsumeBool()) {
        SecCompEnhanceKeyParcel parcel;
        parcel.enhanceKey.epoch = provider.ConsumeIntegral<uint64_t>();
        parcel.enhanceKey.key.size = provider.ConsumeIntegralInRange<uint32_t>(1, MAX_HMAC_SIZE);
        std::vector<uint8_t> keyData = provider.ConsumeBytes<uint8_t>(parcel.enhanceKey.key.size);
        if (!keyData.empty()) {
            (void)memcpy_s(parcel.enhanceKey.key.data, MAX_HMAC_SIZE, keyData.data(), keyData.size());
        }
        (void)sendData.WriteParcelable(&parcel);
    } else {
        (void)sendData.WriteUint64(provider.ConsumeIntegral<uint64_t>());
        (void)sendData.WriteUint32(provider.ConsumeIntegral<uint32_t>());
    }

    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_STORE_SEC_COMP_ENHANCE_KEY);
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, sendData, reply, option);
    return true;
}

void Initialize()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Initialize();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::StoreSecCompEnhanceKeyStubFuzzTest(data, size);
    return 0;
}
