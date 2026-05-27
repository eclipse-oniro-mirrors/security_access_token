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

#include "deleteidentity_fuzzer.h"

#include <string>
#include <vector>
#include <thread>

#undef private
#include "access_token.h"
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace {
// Extend range beyond valid enum to cover invalid-type rejection paths:
//   ReservedType::NONE = 0, ReservedType::RESERVED_IDENTITY = 1, ReservedType::RESERVED_DATA = 2
const int32_t RESERVED_TYPE_MIN = 0;
const int32_t RESERVED_TYPE_MAX = 4;
} // namespace

namespace OHOS {
    bool DeleteIdentityFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);

        // tokenID: mix tokenID=0 (bundle-only cleanup path), random, and real existing IDs
        AccessTokenID tokenId;
        int32_t tokenIdMode = provider.ConsumeIntegralInRange<int32_t>(0, 2);
        if (tokenIdMode == 0) {
            tokenId = 0; // triggers TryCleanBundleInfo path in the service
        } else {
            tokenId = ConsumeTokenId(provider);
        }

        // bundleName: mix empty, well-formed, and random strings
        std::string bundleName;
        int32_t nameMode = provider.ConsumeIntegralInRange<int32_t>(0, 2);
        if (nameMode == 0) {
            bundleName = ""; // triggers ERR_PARAM_INVALID for empty name
        } else if (nameMode == 1) {
            bundleName = "deleteidentity.fuzztest.bundle";
        } else {
            bundleName = provider.ConsumeRandomLengthString();
        }

        // type: cover all valid values and sentinel/out-of-range values to exercise
        // both valid-type dispatch and invalid-type rejection in the service
        int32_t rawType = provider.ConsumeIntegralInRange<int32_t>(RESERVED_TYPE_MIN, RESERVED_TYPE_MAX);
        ReservedType type = static_cast<ReservedType>(rawType);

        AccessTokenKit::DeleteIdentity(tokenId, bundleName, type);
        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DeleteIdentityFuzzTest(data, size);
    return 0;
}
