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

#include "grantpermission_fuzzer.h"

#include <string>
#include <vector>
#include <thread>

#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"

const static int32_t FLAG_SIZE = 16;

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool GrantPermissionFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        AccessTokenID tokenId = ConsumeTokenId(provider);
        std::string permission = ConsumePermissionName(provider);
        return AccessTokenKit::GrantPermission(tokenId, permission,
            1 << (provider.ConsumeIntegral<uint32_t>() % FLAG_SIZE)) == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GrantPermissionFuzzTest(data, size);
    return 0;
}
