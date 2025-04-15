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

#include "verifyaccesstokenwithlist_fuzzer.h"

#include <string>
#include <vector>
#include <thread>
#include "accesstoken_fuzzdata.h"
#undef private
#include "accesstoken_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
const int32_t MAX_PERMISSION_SIZE = 1100;

namespace OHOS {
    bool VerifyAccessTokenWithListFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenFuzzData fuzzData(data, size);

        int permSize = fuzzData.GetData<int>() % MAX_PERMISSION_SIZE;
        std::vector<std::string> permissionList;
        std::vector<int32_t> permStateList;
        for (int i = 0; i < permSize; i++) {
            permissionList.emplace_back(fuzzData.GenerateStochasticString());
        }

        int32_t result = AccessTokenKit::VerifyAccessToken(
            fuzzData.GetData<AccessTokenID>(), permissionList, permStateList, false);

        return result == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::VerifyAccessTokenWithListFuzzTest(data, size);
    return 0;
}
