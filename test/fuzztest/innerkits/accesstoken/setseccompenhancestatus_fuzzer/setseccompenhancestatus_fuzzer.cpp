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

#include "setseccompenhancestatus_fuzzer.h"

#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mock_permission.h"
#include "token_setproc.h"

using namespace OHOS::Security::AccessToken;

namespace {
AccessTokenID g_secCompTokenId = INVALID_TOKENID;

bool SetSecCompToken()
{
    if (g_secCompTokenId == INVALID_TOKENID) {
        MockToken mock({}, false);
        g_secCompTokenId = AccessTokenKit::GetNativeTokenId("security_component_service");
    }
    return (g_secCompTokenId != INVALID_TOKENID) && (SetSelfTokenID(g_secCompTokenId) == 0);
}
}

namespace OHOS {
bool SetSecCompEnhanceStatusFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0) || !SetSecCompToken()) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    return AccessTokenKit::SetSecCompEnhanceStatus(provider.ConsumeBool()) == RET_SUCCESS;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::SetSecCompEnhanceStatusFuzzTest(data, size);
    return 0;
}
