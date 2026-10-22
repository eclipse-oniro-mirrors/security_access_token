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

#include "checkautomationcontrolaccess_fuzzer.h"
#include <vector>
#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mock_permission.h"
using namespace std;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
bool CHECKAUTOMATIONCONTROLACCESSFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) { return false; }
    FuzzedDataProvider provider(data, size);
    uint32_t controllerTokenId = provider.ConsumeIntegral<uint32_t>();
    MockToken mock({"ohos.permission.GET_SENSITIVE_PERMISSIONS"}, true, true);
    std::vector<AccessTokenID> targetList;
    uint32_t count = provider.ConsumeIntegralInRange<uint32_t>(1, 4);
    for (uint32_t i = 0; i < count; i++) {
        targetList.push_back(provider.ConsumeIntegral<uint32_t>());
    }
    std::vector<AutomationControlAccessDecision> decisions;
    AccessTokenKit::CheckAutomationControlAccess(controllerTokenId, targetList, decisions);
    return true;
}
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::CHECKAUTOMATIONCONTROLACCESSFuzzTest(data, size);
    return 0;
}
