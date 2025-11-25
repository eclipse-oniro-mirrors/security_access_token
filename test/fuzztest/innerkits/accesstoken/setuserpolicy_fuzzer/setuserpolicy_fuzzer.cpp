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

#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
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
    std::string permission = ConsumePermissionName(provider);

    std::vector<std::string> permList = { permission };
    UserPermissionPolicy policy;
    policy.permissionName = permission;
    UserPolicy userPolicy;
    userPolicy.userId = provider.ConsumeIntegral<int32_t>();
    userPolicy.isRestricted = provider.ConsumeBool();
    policy.userPolicyList.emplace_back(userPolicy);
    std::vector<UserPermissionPolicy> permPolicyList = { policy };
    AccessTokenKit::SetUserPolicy(permPolicyList);
    AccessTokenKit::ClearUserPolicy(permList);

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
