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

#include "napi_automation_control.h"

#include "accesstoken_common_log.h"
#include "accesstoken_kit.h"
#include "automation_control_types.h"
#include "napi_common.h"
#include "napi_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

#ifdef ENABLE_AUTOMATION_CONTROL
void NapiAutomationControl::ReturnPromiseResult(napi_env env, const AutomationControlAsyncContext& context,
    napi_value result)
{
    if (context.errorCode != RET_SUCCESS) {
        int32_t jsCode = GetJsErrorCode(context.errorCode);
        napi_value businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode, context.extErrorMsg));
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, context.deferred, businessError));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, context.deferred, result));
    }
}

static bool ParseAutomationControlTargetElement(napi_env env, napi_value element,
    AutomationControlAsyncContext& asyncContext)
{
    std::string errMsg;
    napi_value targetVal = nullptr;
    napi_get_named_property(env, element, "targetTokenID", &targetVal);
    uint32_t tid = 0;
    if (!ParseUint32(env, targetVal, tid)) {
        errMsg = GetParamErrorMsg("targetTokenID", "number");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    asyncContext.targetTokenIds.emplace_back(tid);
    napi_value statusVal = nullptr;
    napi_get_named_property(env, element, "status", &statusVal);
    int32_t status = 0;
    if (!ParseInt32(env, statusVal, status)) {
        errMsg = GetParamErrorMsg("status", "number");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    asyncContext.statusList.emplace_back(status);
    return true;
}

bool NapiAutomationControl::ParseInputSetAutomationControlStatus(const napi_env env, const napi_callback_info info,
    AutomationControlAsyncContext& asyncContext)
{
    size_t argc = MAX_PARAMS_THREE;
    napi_value argv[MAX_PARAMS_THREE] = { nullptr };
    napi_value thisVar = nullptr;
    void* data = nullptr;
    std::string errMsg;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
    if (argc < MAX_PARAMS_TWO) {
        NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env,
            JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }
    if (!ParseUint32(env, argv[0], asyncContext.tokenId)) {
        errMsg = GetParamErrorMsg("controllerTokenID", "number");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    bool isArray = false;
    NAPI_CALL_BASE(env, napi_is_array(env, argv[1], &isArray), false);
    if (!isArray) {
        errMsg = GetParamErrorMsg("targetList", "Array");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    uint32_t arrayLen = 0;
    napi_get_array_length(env, argv[1], &arrayLen);
    for (uint32_t i = 0; i < arrayLen; i++) {
        napi_value element = nullptr;
        napi_get_element(env, argv[1], i, &element);
        if (!ParseAutomationControlTargetElement(env, element, asyncContext)) {
            return false;
        }
    }
    asyncContext.env = env;
    return true;
}

bool NapiAutomationControl::ParseInputGetAutomationControl(const napi_env env, const napi_callback_info info,
    AutomationControlAsyncContext& asyncContext, bool isByController)
{
    size_t argc = MAX_PARAMS_ONE;
    napi_value argv[MAX_PARAMS_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    void* data = nullptr;
    std::string errMsg;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
    if (argc < MAX_PARAMS_ONE) {
        NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env,
            JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }
    if (isByController) {
        if (!ParseUint32(env, argv[0], asyncContext.tokenId)) {
            errMsg = GetParamErrorMsg("controllerTokenID", "number");
            NAPI_CALL_BASE(env,
                napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
            return false;
        }
    } else {
        if (!ParseUint32(env, argv[0], asyncContext.targetTokenId)) {
            errMsg = GetParamErrorMsg("targetTokenID", "number");
            NAPI_CALL_BASE(env,
                napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
            return false;
        }
    }
    asyncContext.env = env;
    return true;
}

void NapiAutomationControl::SetAutomationControlStatusExecute(napi_env env, void *data)
{
    auto* ctx = reinterpret_cast<AutomationControlAsyncContext*>(data);
    if (ctx == nullptr) {
        return;
    }
    std::vector<AutomationControlTargetParam> targetList;
    for (size_t i = 0; i < ctx->targetTokenIds.size(); i++) {
        AutomationControlTargetParam p;
        p.targetTokenID = ctx->targetTokenIds[i];
        p.status = (i < ctx->statusList.size()) ? ctx->statusList[i] : 0;
        targetList.emplace_back(p);
    }
    std::vector<AutomationControlSetResult> results;
    ctx->errorCode = AccessTokenKit::SetAutomationControlStatus(ctx->tokenId, targetList, results);
    ctx->outputResults.clear();
    for (auto r : results) {
        ctx->outputResults.emplace_back(static_cast<int>(r));
    }
}

void NapiAutomationControl::SetAutomationControlStatusComplete(napi_env env, napi_status status, void *data)
{
    auto* ctx = reinterpret_cast<AutomationControlAsyncContext*>(data);
    if (ctx == nullptr) {
        return;
    }
    std::unique_ptr<AutomationControlAsyncContext> callbackPtr {ctx};
    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result));
    for (size_t i = 0; i < ctx->outputResults.size(); i++) {
        napi_value element = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, ctx->outputResults[i], &element));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, i, element));
    }
    ReturnPromiseResult(env, *ctx, result);
}

void NapiAutomationControl::GetAutomationControlTargetsExecute(napi_env env, void *data)
{
    auto* ctx = reinterpret_cast<AutomationControlAsyncContext*>(data);
    if (ctx == nullptr) {
        return;
    }
    std::vector<AutomationControlTargetResult> results;
    ctx->errorCode = AccessTokenKit::GetAutomationControlTargets(ctx->tokenId, results);
    ctx->targetTokenIds.clear();
    ctx->statusList.clear();
    ctx->outputBundleNames.clear();
    for (const auto& r : results) {
        ctx->targetTokenIds.emplace_back(r.targetTokenID);
        ctx->statusList.emplace_back(r.status);
        ctx->outputBundleNames.emplace_back(r.bundleName);
    }
}

void NapiAutomationControl::GetAutomationControlTargetsComplete(napi_env env, napi_status status, void *data)
{
    auto* ctx = reinterpret_cast<AutomationControlAsyncContext*>(data);
    if (ctx == nullptr) {
        return;
    }
    std::unique_ptr<AutomationControlAsyncContext> callbackPtr {ctx};
    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result));
    for (size_t i = 0; i < ctx->targetTokenIds.size(); i++) {
        napi_value element = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &element));
        napi_value tid = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, ctx->targetTokenIds[i], &tid));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, element, "targetTokenID", tid));
        napi_value st = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, ctx->statusList[i], &st));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, element, "status", st));
        napi_value bn = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, ctx->outputBundleNames[i].c_str(),
            NAPI_AUTO_LENGTH, &bn));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, element, "bundleName", bn));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, i, element));
    }
    ReturnPromiseResult(env, *ctx, result);
}

void NapiAutomationControl::GetAutomationControlControllersExecute(napi_env env, void *data)
{
    auto* ctx = reinterpret_cast<AutomationControlAsyncContext*>(data);
    if (ctx == nullptr) {
        return;
    }
    std::vector<AutomationControlControllerInfo> results;
    ctx->errorCode = AccessTokenKit::GetAutomationControlControllers(ctx->targetTokenId, results);
    ctx->targetTokenIds.clear();
    ctx->outputBundleNames.clear();
    for (const auto& r : results) {
        ctx->targetTokenIds.emplace_back(r.controllerTokenID);
        ctx->outputBundleNames.emplace_back(r.bundleName);
    }
}

void NapiAutomationControl::GetAutomationControlControllersComplete(napi_env env, napi_status status, void *data)
{
    auto* ctx = reinterpret_cast<AutomationControlAsyncContext*>(data);
    if (ctx == nullptr) {
        return;
    }
    std::unique_ptr<AutomationControlAsyncContext> callbackPtr {ctx};
    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result));
    for (size_t i = 0; i < ctx->targetTokenIds.size(); i++) {
        napi_value element = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &element));
        napi_value cid = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, ctx->targetTokenIds[i], &cid));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, element, "controllerTokenID", cid));
        napi_value bn = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, ctx->outputBundleNames[i].c_str(),
            NAPI_AUTO_LENGTH, &bn));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, element, "bundleName", bn));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, i, element));
    }
    ReturnPromiseResult(env, *ctx, result);
}
#endif

napi_value NapiAutomationControl::SetAutomationControlStatus(napi_env env, napi_callback_info info)
{
#ifndef ENABLE_AUTOMATION_CONTROL
    NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env,
        JsErrorCode::JS_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT,
        GetErrorMessage(JsErrorCode::JS_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT))));
    return nullptr;
#else
    auto* ctx = new (std::nothrow) AutomationControlAsyncContext(env);
    if (ctx == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AutomationControlAsyncContext> context {ctx};
    if (!ParseInputSetAutomationControlStatus(env, info, *ctx)) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &(ctx->deferred), &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetAutomationControlStatus", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, SetAutomationControlStatusExecute, SetAutomationControlStatusComplete,
        reinterpret_cast<void*>(ctx), &(ctx->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, ctx->work, napi_qos_default));
    context.release();
    return result;
#endif
}

napi_value NapiAutomationControl::GetAutomationControlTargets(napi_env env, napi_callback_info info)
{
#ifndef ENABLE_AUTOMATION_CONTROL
    NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env,
        JsErrorCode::JS_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT,
        GetErrorMessage(JsErrorCode::JS_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT))));
    return nullptr;
#else
    auto* ctx = new (std::nothrow) AutomationControlAsyncContext(env);
    if (ctx == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AutomationControlAsyncContext> context {ctx};
    if (!ParseInputGetAutomationControl(env, info, *ctx, true)) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &(ctx->deferred), &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAutomationControlTargets", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, GetAutomationControlTargetsExecute, GetAutomationControlTargetsComplete,
        reinterpret_cast<void*>(ctx), &(ctx->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, ctx->work, napi_qos_default));
    context.release();
    return result;
#endif
}

napi_value NapiAutomationControl::GetAutomationControlControllers(napi_env env, napi_callback_info info)
{
#ifndef ENABLE_AUTOMATION_CONTROL
    NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env,
        JsErrorCode::JS_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT,
        GetErrorMessage(JsErrorCode::JS_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT))));
    return nullptr;
#else
    auto* ctx = new (std::nothrow) AutomationControlAsyncContext(env);
    if (ctx == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AutomationControlAsyncContext> context {ctx};
    if (!ParseInputGetAutomationControl(env, info, *ctx, false)) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &(ctx->deferred), &result));
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetAutomationControlControllers", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, GetAutomationControlControllersExecute, GetAutomationControlControllersComplete,
        reinterpret_cast<void*>(ctx), &(ctx->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, ctx->work, napi_qos_default));
    context.release();
    return result;
#endif
}

}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
