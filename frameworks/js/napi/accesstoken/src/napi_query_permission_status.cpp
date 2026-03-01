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

#include "napi_query_permission_status.h"

#include "access_token.h"
#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "data_validator.h"
#include "napi_common.h"
#include "napi_error.h"
#include "napi_hisysevent_adapter.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

static void ReturnPromiseResult(napi_env env, QueryPermissionStatusAsyncContext& context, napi_value result)
{
    if (context.result.errorCode != RET_SUCCESS) {
        int32_t jsCode = GetJsErrorCode(context.result.errorCode);
        napi_value businessError = GenerateBusinessError(env, jsCode,
            GetErrorMessage(jsCode, context.result.errorMsg));
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, context.deferred, businessError));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, context.deferred, result));
    }
    context.deferred = nullptr;
}

napi_value NapiQueryPermissionStatus::QueryStatusByPermission(napi_env env, napi_callback_info info)
{
    auto* asyncContext = new (std::nothrow) QueryPermissionStatusAsyncContext(env);
    if (asyncContext == nullptr) {
        return nullptr;
    }

    std::unique_ptr<QueryPermissionStatusAsyncContext> context {asyncContext};

    size_t argc = MAX_PARAMS_ONE;
    napi_value argv[MAX_PARAMS_ONE] = { nullptr };
    napi_value thatVar = nullptr;
    void* data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thatVar, &data), nullptr);

    if (argc < MAX_PARAMS_ONE) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return nullptr;
    }

    asyncContext->env = env;
    asyncContext->isQueryByPermission = true;

    if (!ParseStringArray(env, argv[0], asyncContext->permissionList)) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("permissionList", "Array<Permissions>")));
        return nullptr;
    }

    napi_value result = nullptr;
    napi_create_promise(env, &(asyncContext->deferred), &result);

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "QueryStatusByPermission", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, QueryPermissionStatusExecute,
        QueryPermissionStatusComplete, asyncContext, &(asyncContext->work));

    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);

    context.release();
    return result;
}

napi_value NapiQueryPermissionStatus::QueryStatusByTokenID(napi_env env, napi_callback_info info)
{
    auto* asyncContext = new (std::nothrow) QueryPermissionStatusAsyncContext(env);
    if (asyncContext == nullptr) {
        return nullptr;
    }

    std::unique_ptr<QueryPermissionStatusAsyncContext> context {asyncContext};

    size_t argc = MAX_PARAMS_ONE;
    napi_value argv[MAX_PARAMS_ONE] = { nullptr };
    napi_value thatVar = nullptr;
    void* data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thatVar, &data), nullptr);

    if (argc < MAX_PARAMS_ONE) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return nullptr;
    }

    asyncContext->env = env;
    asyncContext->isQueryByPermission = false;

    if (!ParseAccessTokenIDArray(env, argv[0], asyncContext->tokenIDList)) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("tokenIDList", "Array<number>")));
        return nullptr;
    }

    napi_value result = nullptr;
    napi_create_promise(env, &(asyncContext->deferred), &result);

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "QueryStatusByTokenID", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env, nullptr, resource, QueryPermissionStatusExecute,
        QueryPermissionStatusComplete, asyncContext, &(asyncContext->work));

    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);

    context.release();
    return result;
}

void NapiQueryPermissionStatus::QueryPermissionStatusExecute(napi_env env, void* data)
{
    QueryPermissionStatusAsyncContext* asyncContext = reinterpret_cast<QueryPermissionStatusAsyncContext*>(data);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "QueryPermissionStatusExecute enter, asyncContext is null.");
        return;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "QueryPermissionStatusExecute enter, isQueryByPermission: %{public}d.",
        asyncContext->isQueryByPermission);

    if (asyncContext->isQueryByPermission) {
        asyncContext->SetErrorCode(AccessTokenKit::QueryStatusByPermission(
            asyncContext->permissionList, asyncContext->permissionInfoList, true));
    } else {
        asyncContext->SetErrorCode(AccessTokenKit::QueryStatusByTokenID(
            asyncContext->tokenIDList, asyncContext->permissionInfoList));
    }
}

void NapiQueryPermissionStatus::QueryPermissionStatusComplete(napi_env env, napi_status status, void* data)
{
    QueryPermissionStatusAsyncContext* asyncContext = reinterpret_cast<QueryPermissionStatusAsyncContext*>(data);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "QueryPermissionStatusComplete enter, asyncContext is null.");
        return;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "QueryPermissionStatusComplete enter, isQueryByPermission: %{public}d, "
        "permissionInfoList size: %{public}zu.", asyncContext->isQueryByPermission,
        asyncContext->permissionInfoList.size());
    std::unique_ptr<QueryPermissionStatusAsyncContext> callbackPtr {asyncContext};

    napi_value result;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result));

    for (size_t i = 0; i < asyncContext->permissionInfoList.size(); ++i) {
        const auto& permStatus = asyncContext->permissionInfoList[i];

        napi_value obj = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &obj));

        napi_value tokenIDValue = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, permStatus.tokenID, &tokenIDValue));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, "tokenID", tokenIDValue));

        napi_value permissionNameValue = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, permStatus.permissionName.c_str(),
            NAPI_AUTO_LENGTH, &permissionNameValue));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, "permissionName", permissionNameValue));

        napi_value grantStatusValue = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, permStatus.grantStatus, &grantStatusValue));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, "grantStatus", grantStatusValue));

        napi_value grantFlagsValue = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, permStatus.grantFlag, &grantFlagsValue));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, obj, "grantFlags", grantFlagsValue));

        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, i, obj));
    }

    ReturnPromiseResult(env, *asyncContext, result);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
