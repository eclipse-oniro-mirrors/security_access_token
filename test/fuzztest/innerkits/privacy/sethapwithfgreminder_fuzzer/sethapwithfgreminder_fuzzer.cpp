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

#include "sethapwithfgreminder_fuzzer.h"

#include "fuzzer/FuzzedDataProvider.h"
#include "privacy_kit.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
bool SetHapWithFGReminderFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    return PrivacyKit::SetHapWithFGReminder(provider.ConsumeIntegral<AccessTokenID>(), provider.ConsumeBool()) == 0;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    (void)OHOS::SetHapWithFGReminderFuzzTest(data, size);
    return 0;
}
