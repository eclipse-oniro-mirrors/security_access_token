/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "deleteremotedevicetokens_fuzzer.h"

#include <string>
#include <vector>
#include <thread>

#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mock_permission.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace {
bool SetTokenSyncToken()
{
    AccessTokenID token = INVALID_TOKENID;
    {
        MockToken mock({}, false);
        token = AccessTokenKit::GetNativeTokenId("token_sync_service");
    }
    if (token == INVALID_TOKENID) {
        return false;
    }
    return SetSelfTokenID(token) == 0;
}
}

namespace OHOS {
    bool DeleteRemoteDeviceTokensFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        if (!SetTokenSyncToken()) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        return AccessTokenKit::DeleteRemoteDeviceTokens(provider.ConsumeRandomLengthString()) == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DeleteRemoteDeviceTokensFuzzTest(data, size);
    return 0;
}
