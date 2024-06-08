/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "deleteremotetoken_fuzzer.h"

#include <string>
#include <vector>
#include <thread>
#include "accesstoken_fuzzdata.h"
#undef private
#include "accesstoken_kit.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool DeleteRemoteTokenFuzzTest(const uint8_t* data, size_t size)
    {
#ifdef TOKEN_SYNC_ENABLE
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenFuzzData fuzzData(data, size);
        int32_t result = AccessTokenKit::DeleteRemoteToken(
            fuzzData.GenerateRandomString(), fuzzData.GetData<AccessTokenID>());
        return result == RET_SUCCESS;
#else
        return true;
#endif
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DeleteRemoteTokenFuzzTest(data, size);
    return 0;
}

