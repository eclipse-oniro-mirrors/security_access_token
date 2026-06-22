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

#include "storeseccompenhancekey_fuzzer.h"

#include <vector>

#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mock_permission.h"
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
bool StoreSecCompEnhanceKeyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0) || !SetSecCompToken()) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    SecCompEnhanceKey enhanceKey;
    enhanceKey.epoch = provider.ConsumeIntegral<uint64_t>();
    enhanceKey.key.size = provider.ConsumeBool()
        ? provider.ConsumeIntegralInRange<uint32_t>(1, MAX_HMAC_SIZE)
        : provider.ConsumeIntegral<uint32_t>();
    std::vector<uint8_t> keyData = provider.ConsumeBytes<uint8_t>(MAX_HMAC_SIZE);
    if (!keyData.empty()) {
        (void)memcpy_s(enhanceKey.key.data, MAX_HMAC_SIZE, keyData.data(), keyData.size());
    }
    return AccessTokenKit::StoreSecCompEnhanceKey(enhanceKey) == RET_SUCCESS;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::StoreSecCompEnhanceKeyFuzzTest(data, size);
    return 0;
}
