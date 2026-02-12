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

#include "querystatusbytokenid_fuzzer.h"

#include <vector>

#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
bool QueryStatusByTokenIDFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);

    // Generate tokenID list with random size (0 to 1025 to test boundary)
    size_t tokenListSize = provider.ConsumeIntegralInRange<size_t>(0, 1025);
    std::vector<AccessTokenID> tokenIDList;
    tokenIDList.reserve(tokenListSize);

    for (size_t i = 0; i < tokenListSize; i++) {
        tokenIDList.push_back(ConsumeTokenId(provider));
    }

    // Call the API
    std::vector<PermissionStatus> permissionInfoList;
    AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::QueryStatusByTokenIDFuzzTest(data, size);
    return 0;
}
