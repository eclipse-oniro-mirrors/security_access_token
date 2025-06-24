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

#include "getpermissionsstatus_fuzzer.h"

#include <cstdint>
#include <string>
#include <vector>
#include <thread>

#undef private
#include "access_token.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {

    bool GetPermissionsStatusFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        std::vector<PermissionListState> permList;
        return AccessTokenKit::GetPermissionsStatus(provider.ConsumeIntegral<AccessTokenID>(), permList) == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetPermissionsStatusFuzzTest(data, size);
    return 0;
}
