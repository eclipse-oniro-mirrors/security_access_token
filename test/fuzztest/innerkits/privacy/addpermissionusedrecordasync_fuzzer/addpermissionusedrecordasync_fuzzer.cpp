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

#include "addpermissionusedrecordasync_fuzzer.h"

#include <iostream>
#include <thread>
#include <string>
#include <vector>

#include "accesstoken_fuzzdata.h"
#undef private
#include "privacy_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool AddPermissionUsedRecordAsyncFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenFuzzData fuzzData(data, size);

        AddPermParamInfo info;
        info.tokenId = static_cast<AccessTokenID>(fuzzData.GetData<uint32_t>());
        info.permissionName = fuzzData.GenerateStochasticString();
        info.successCount = fuzzData.GetData<int32_t>();
        info.failCount = fuzzData.GetData<int32_t>();
        info.type = fuzzData.GenerateStochasticEnmu<PermissionUsedType>(PERM_USED_TYPE_BUTT);

        return PrivacyKit::AddPermissionUsedRecord(info, true) == 0;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AddPermissionUsedRecordAsyncFuzzTest(data, size);
    return 0;
}
