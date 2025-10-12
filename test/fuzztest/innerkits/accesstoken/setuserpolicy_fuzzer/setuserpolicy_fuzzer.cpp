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

#include "setuserpolicy_fuzzer.h"

#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "access_token.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
bool SetUserPolicyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);

    int32_t userId = provider.ConsumeIntegral<int32_t>();
    const std::vector<int32_t> userList = { userId };
    PermissionPolicy policy;
    policy.permList.emplace_back(provider.ConsumeRandomLengthString());
    policy.grantList.emplace_back(provider.ConsumeBool());
    std::vector<PermissionPolicy> permPolicyList = { policy };
    AccessTokenKit::SetUserPolicy(userList, permPolicyList);
    AccessTokenKit::ClearUserPolicy(userList);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetUserPolicyFuzzTest(data, size);
    return 0;
}
