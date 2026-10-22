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

#include "automationcontrollifecycle_fuzzer.h"

#include <string>
#include <vector>

#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "automation_control_types.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mock_permission.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
bool AutomationControlLifecycleFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzedDataProvider provider(data, size);
    // controller: HAP + system app, carries GRANT/GET for Set/Get/Check and
    // MANAGE_HAP_TOKENID for AllocHapToken/DeleteToken (granted in kernel by MockToken).
    MockToken controller({"ohos.permission.GRANT_SENSITIVE_PERMISSIONS",
                          "ohos.permission.GET_SENSITIVE_PERMISSIONS",
                          "ohos.permission.MANAGE_HAP_TOKENID"}, true, true);
    AccessTokenID controllerId = controller.GetTokenId();

    // 1. add token: minimal valid params pass AllocHapToken validation every iteration.
    HapInfoParams info = {
        .userID = 0,
        .bundleName = "ac_fuzz_" + std::to_string(provider.ConsumeIntegral<uint32_t>()),
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
        .apiVersion = 12
    };
    HapPolicyParams policy = {.apl = APL_NORMAL, .domain = "domain"};
    AccessTokenIDEx targetEx = AccessTokenKit::AllocHapToken(info, policy);
    AccessTokenID target = targetEx.tokenIdExStruct.tokenID;
    if (target == INVALID_TOKENID) {
        return false;
    }

    // 2. set: fuzz status; optionally mix in a random (non-HAP) token to exercise
    // the per-element INVALID_TOKEN_ID path alongside the SUCCESS path.
    std::vector<AutomationControlTargetParam> targetList;
    AutomationControlTargetParam param;
    param.targetTokenID = target;
    param.status = provider.ConsumeBool() ? AUTOMATION_CONTROL_ENABLED : AUTOMATION_CONTROL_DISABLED;
    targetList.emplace_back(param);
    if (provider.ConsumeBool()) {
        AutomationControlTargetParam fuzzParam;
        fuzzParam.targetTokenID = provider.ConsumeIntegral<uint32_t>();
        fuzzParam.status = provider.ConsumeBool() ? AUTOMATION_CONTROL_ENABLED : AUTOMATION_CONTROL_DISABLED;
        targetList.emplace_back(fuzzParam);
    }
    std::vector<AutomationControlSetResult> results;
    AccessTokenKit::SetAutomationControlStatus(controllerId, targetList, results);

    // 3. get targets (query controller after Set).
    std::vector<AutomationControlTargetResult> queryResults;
    AccessTokenKit::GetAutomationControlTargets(controllerId, queryResults);

    // 4. get controllers (reverse query by target).
    std::vector<AutomationControlControllerInfo> ctrlResults;
    AccessTokenKit::GetAutomationControlControllers(target, ctrlResults);

    // 5. check (decision: GRANTED/DENIED when record exists, else POPUP_NEEDED).
    std::vector<AccessTokenID> checkList{target};
    std::vector<AutomationControlAccessDecision> decisions;
    AccessTokenKit::CheckAutomationControlAccess(controllerId, checkList, decisions);

    // 6. delete token: triggers ClearByTokenId (service uninstall cleanup path).
    AccessTokenKit::DeleteToken(target);
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::AutomationControlLifecycleFuzzTest(data, size);
    return 0;
}
