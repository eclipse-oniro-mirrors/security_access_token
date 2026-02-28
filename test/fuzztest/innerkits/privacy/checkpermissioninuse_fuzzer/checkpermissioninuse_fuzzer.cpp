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

#include "checkpermissioninuse_fuzzer.h"

#include <iostream>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#undef private
#include "privacy_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool CheckPermissionInUseFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);

        // Generate permission name with realistic constraints
        size_t permNameLen = provider.ConsumeIntegralInRange<size_t>(0, 300);
        std::string permissionName = provider.ConsumeRandomLengthString(permNameLen);

        // Call the API - it should handle all edge cases gracefully
        bool isUsing = false;
        int32_t ret = PrivacyKit::CheckPermissionInUse(permissionName, isUsing);

        // The function should handle: empty strings, very long strings,
        // invalid permission names, special characters, etc.
        // We don't assert on the result, just ensure it doesn't crash
        (void)ret;
        (void)isUsing;

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::CheckPermissionInUseFuzzTest(data, size);
    return 0;
}
