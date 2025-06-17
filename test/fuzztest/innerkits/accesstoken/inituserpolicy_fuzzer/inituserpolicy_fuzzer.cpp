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

#include "inituserpolicy_fuzzer.h"

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "access_token.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
bool InitUserPolicyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    AccessTokenFuzzData fuzzData(data, size);

    std::string permissionName(fuzzData.GenerateStochasticString());
    const std::vector<std::string> permList = {permissionName};
    UserState state;
    state.userId = fuzzData.GetData<int32_t>();
    state.isActive = fuzzData.GenerateStochasticBool();
    std::vector<UserState> userList = {state};
    AccessTokenKit::InitUserPolicy(userList, permList);
    AccessTokenKit::UpdateUserPolicy(userList);
    AccessTokenKit::ClearUserPolicy();

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::InitUserPolicyFuzzTest(data, size);
    return 0;
}
