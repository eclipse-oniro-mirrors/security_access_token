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

#include "isallowedusingpermission_fuzzer.h"

#include <iostream>
#include <thread>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#undef private
#include "privacy_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool IsAllowedUsingPermissionFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        return PrivacyKit::IsAllowedUsingPermission(provider.ConsumeIntegral<AccessTokenID>(),
            provider.ConsumeRandomLengthString(), provider.ConsumeIntegral<int32_t>());
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::IsAllowedUsingPermissionFuzzTest(data, size);
    return 0;
}
