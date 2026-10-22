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

#include "setautomationcontrolstatus_fuzzer.h"

#include <vector>
#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mock_permission.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
bool SETAUTOMATIONCONTROLSTATUSFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzedDataProvider provider(data, size);
    uint32_t controllerTokenId = provider.ConsumeIntegral<uint32_t>();
    MockToken mock({"ohos.permission.GRANT_SENSITIVE_PERMISSIONS"}, true, true);
    std::vector<AutomationControlTargetParam> targetList;
    uint32_t targetCount = provider.ConsumeIntegralInRange<uint32_t>(1, 4);
    for (uint32_t i = 0; i < targetCount; i++) {
        AutomationControlTargetParam param;
        param.targetTokenID = provider.ConsumeIntegral<uint32_t>();
        param.status = provider.ConsumeIntegralInRange<int32_t>(0, 1);
        targetList.push_back(param);
    }
    std::vector<AutomationControlSetResult> results;
    AccessTokenKit::SetAutomationControlStatus(controllerTokenId, targetList, results);
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::SETAUTOMATIONCONTROLSTATUSFuzzTest(data, size);
    return 0;
}
