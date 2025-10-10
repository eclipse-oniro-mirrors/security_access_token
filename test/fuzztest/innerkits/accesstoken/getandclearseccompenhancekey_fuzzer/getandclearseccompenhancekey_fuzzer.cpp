/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "getandclearseccompenhancekey_fuzzer.h"

#include <iostream>
#include <thread>
#include <string>
#include <vector>

#undef private
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool GetAndClearSecCompEnhanceKeyFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        uint32_t sizeIn = provider.ConsumeIntegral<int32_t>();
        if (sizeIn > 1024) { // 1024 is the largest size
            return true;
        }
        uint8_t* key = new (std::nothrow) uint8_t [sizeIn];
        if (key == nullptr) {
            return false;
        }
        uint32_t sizeOut;
        return AccessTokenKit::GetAndClearSecCompEnhanceKey(sizeIn, key, &sizeOut) == 0;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetAndClearSecCompEnhanceKeyFuzzTest(data, size);
    return 0;
}
