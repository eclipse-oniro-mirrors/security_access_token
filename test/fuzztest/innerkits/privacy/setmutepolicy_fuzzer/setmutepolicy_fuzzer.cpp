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

#include "setmutepolicy_fuzzer.h"

#include <iostream>
#include <thread>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#undef private
#include "privacy_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
static const uint32_t ACTIVE_CHANGE_CHANGE_TYPE_MAX = 4;
static const uint32_t CALLER_TYPE_MAX = 2;

namespace OHOS {
    bool SetMutePolicyFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        return PrivacyKit::SetMutePolicy(provider.ConsumeIntegralInRange<uint32_t>(0, ACTIVE_CHANGE_CHANGE_TYPE_MAX),
            provider.ConsumeIntegralInRange<uint32_t>(0, CALLER_TYPE_MAX),
            provider.ConsumeBool(), provider.ConsumeIntegral<AccessTokenID>()) == 0;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetMutePolicyFuzzTest(data, size);
    return 0;
}
