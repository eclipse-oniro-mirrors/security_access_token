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

#include "getpermissionusedrecords_fuzzer.h"

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
    bool GetPermissionUsedRecordsFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        PermissionUsedRequest request = {
            .tokenId = provider.ConsumeIntegral<AccessTokenID>(),
            .isRemote = provider.ConsumeBool(),
            .deviceId = provider.ConsumeRandomLengthString(),
            .bundleName = provider.ConsumeRandomLengthString(),
            .permissionList = {provider.ConsumeRandomLengthString()},
            .beginTimeMillis = provider.ConsumeIntegral<int64_t>(),
            .endTimeMillis = provider.ConsumeIntegral<int64_t>(),
            .flag = static_cast<PermissionUsageFlag>(provider.ConsumeIntegralInRange<uint32_t>(
                0, static_cast<uint32_t>(PermissionUsageFlag::FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_UNLOCKED)))
        };

        PermissionUsedResult res;
        return PrivacyKit::GetPermissionUsedRecords(request, res) == 0;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetPermissionUsedRecordsFuzzTest(data, size);
    return 0;
}
