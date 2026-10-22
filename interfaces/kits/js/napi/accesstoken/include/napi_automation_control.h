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
#ifndef NAPI_AUTOMATION_CONTROL_H
#define NAPI_AUTOMATION_CONTROL_H

#include "napi_context_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

struct AutomationControlAsyncContext : public AtManagerAsyncWorkData {
    explicit AutomationControlAsyncContext(napi_env env) : AtManagerAsyncWorkData(env) {}

    AccessTokenID tokenId = 0;
    AccessTokenID targetTokenId = 0;
    int32_t errorCode = 0;
    std::string extErrorMsg = "";
    std::vector<unsigned int> targetTokenIds;
    std::vector<int> statusList;
    std::vector<int> outputResults;
    std::vector<std::string> outputBundleNames;
};

class NapiAutomationControl final {
public:
    static napi_value SetAutomationControlStatus(napi_env env, napi_callback_info info);
    static napi_value GetAutomationControlTargets(napi_env env, napi_callback_info info);
    static napi_value GetAutomationControlControllers(napi_env env, napi_callback_info info);

#ifdef ENABLE_AUTOMATION_CONTROL
    static void SetAutomationControlStatusExecute(napi_env env, void *data);
    static void SetAutomationControlStatusComplete(napi_env env, napi_status status, void *data);
    static void GetAutomationControlTargetsExecute(napi_env env, void *data);
    static void GetAutomationControlTargetsComplete(napi_env env, napi_status status, void *data);
    static void GetAutomationControlControllersExecute(napi_env env, void *data);
    static void GetAutomationControlControllersComplete(napi_env env, napi_status status, void *data);

private:
    static bool ParseInputSetAutomationControlStatus(const napi_env env, const napi_callback_info info,
        AutomationControlAsyncContext& asyncContext);
    static bool ParseInputGetAutomationControl(const napi_env env, const napi_callback_info info,
        AutomationControlAsyncContext& asyncContext, bool isByController);
    static void ReturnPromiseResult(napi_env env, const AutomationControlAsyncContext& context, napi_value result);
#endif
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // NAPI_AUTOMATION_CONTROL_H
