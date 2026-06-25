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

#include "clearusergrantedpermstatebybundle_fuzzer.h"

#include <string>
#include <vector>
#include <thread>

#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    AccessTokenID GetShellTokenForFuzz()
    {
        AccessTokenID shellToken = AccessTokenKit::GetNativeTokenId("hdcd");
        AccessTokenID selfToken = static_cast<AccessTokenID>(GetSelfTokenID());
        if ((shellToken == INVALID_TOKENID) && (AccessTokenKit::GetTokenTypeFlag(selfToken) == TOKEN_SHELL)) {
            shellToken = selfToken;
        }
        return shellToken;
    }

    bool ClearUserGrantedPermStateByBundleFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        AccessTokenID shellToken = GetShellTokenForFuzz();
        if (shellToken == INVALID_TOKENID) {
            return false;
        }
        uint64_t selfTokenId = GetSelfTokenID();
        if (SetSelfTokenID(shellToken) != RET_SUCCESS) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        std::string bundleName = provider.ConsumeRandomLengthString();
        bool ret = AccessTokenKit::ClearUserGrantedPermStateByBundle(bundleName) == RET_SUCCESS;
        (void)SetSelfTokenID(selfTokenId);
        return ret;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ClearUserGrantedPermStateByBundleFuzzTest(data, size);
    return 0;
}
