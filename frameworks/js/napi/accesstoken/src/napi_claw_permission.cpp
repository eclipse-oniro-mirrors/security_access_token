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

#include "napi_claw_permission.h"

#include <memory>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_kit.h"
#include "napi_common.h"
#include "napi_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr size_t CLI_DIALOG_PARAM_COUNT = 2;
constexpr size_t SKILL_DIALOG_PARAM_COUNT = 2;
constexpr size_t SYSTEM_PARAM_COUNT = 3;
constexpr size_t CHALLENGE_PARAM_COUNT = 3;
constexpr size_t THIRD_PARAM_INDEX = 2;
constexpr size_t MAX_AGENT_ID_LENGTH = MAX_CLAW_AGENT_ID_LEN;

void ThrowParamError(napi_env env, const std::string& param, const std::string& type)
{
    napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, GetParamErrorMsg(param, type)));
}

bool GetNamedString(napi_env env, napi_value obj, const char* name, std::string& value)
{
    napi_value property = nullptr;
    if (!IsNeedParseProperty(env, obj, name, property)) {
        return false;
    }
    return ParseString(env, property, value);
}

bool ParseAgentID(napi_env env, napi_value value, std::string& agentID)
{
    return ParseString(env, value, agentID) && agentID.length() <= MAX_AGENT_ID_LENGTH;
}

bool ParseCliInfo(napi_env env, napi_value value, CliInfo& info)
{
    if (!CheckType(env, value, napi_object)) {
        return false;
    }
    return GetNamedString(env, value, "cliName", info.cliName) &&
        GetNamedString(env, value, "subCliName", info.subCliName);
}

bool ParseSkillInfo(napi_env env, napi_value value, SkillInfo& info)
{
    if (!CheckType(env, value, napi_object)) {
        return false;
    }
    return GetNamedString(env, value, "skillName", info.skillName) &&
        GetNamedString(env, value, "bundleName", info.bundleName) &&
        GetNamedString(env, value, "moduleName", info.moduleName);
}

bool GetNamedStringArray(napi_env env, napi_value obj, const char* name, std::vector<std::string>& values)
{
    napi_value property = nullptr;
    if (!IsNeedParseProperty(env, obj, name, property)) {
        return false;
    }
    return ParseStringArray(env, property, values);
}

bool GetNamedBoolArray(napi_env env, napi_value obj, const char* name, std::vector<bool>& values)
{
    napi_value property = nullptr;
    if (!IsNeedParseProperty(env, obj, name, property) || !IsArray(env, property)) {
        return false;
    }
    uint32_t length = 0;
    NAPI_CALL_BASE(env, napi_get_array_length(env, property, &length), false);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value element = nullptr;
        bool value = false;
        NAPI_CALL_BASE(env, napi_get_element(env, property, i, &element), false);
        if (!ParseBool(env, element, value)) {
            return false;
        }
        values.emplace_back(value);
    }
    return true;
}

bool ParseCliAuthInfo(napi_env env, napi_value value, CliAuthInfo& info)
{
    napi_value cliValue = nullptr;
    if (!CheckType(env, value, napi_object) || !IsNeedParseProperty(env, value, "cliInfo", cliValue)) {
        return false;
    }
    return ParseCliInfo(env, cliValue, info.cliInfo) &&
        GetNamedStringArray(env, value, "permissionNames", info.permissionNames) &&
        GetNamedBoolArray(env, value, "authorizationResults", info.authorizationResults);
}

bool ParseSkillAuthInfo(napi_env env, napi_value value, SkillAuthInfo& info)
{
    napi_value skillValue = nullptr;
    if (!CheckType(env, value, napi_object) || !IsNeedParseProperty(env, value, "skillInfo", skillValue)) {
        return false;
    }
    return ParseSkillInfo(env, skillValue, info.skillInfo) &&
        GetNamedStringArray(env, value, "permissionNames", info.permissionNames) &&
        GetNamedBoolArray(env, value, "authorizationResults", info.authorizationResults);
}

template<typename T, typename Parser>
bool ParseObjectArray(napi_env env, napi_value value, std::vector<T>& result, Parser parser)
{
    if (!IsArray(env, value)) {
        return false;
    }
    uint32_t length = 0;
    NAPI_CALL_BASE(env, napi_get_array_length(env, value, &length), false);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value element = nullptr;
        NAPI_CALL_BASE(env, napi_get_element(env, value, i, &element), false);
        T info;
        if (!parser(env, element, info)) {
            return false;
        }
        result.emplace_back(info);
    }
    return true;
}

napi_value CreateStringArray(napi_env env, const std::vector<std::string>& values)
{
    napi_value array = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, values.size(), &array));
    for (size_t i = 0; i < values.size(); ++i) {
        napi_value value = nullptr;
        NAPI_CALL(env, napi_create_string_utf8(env, values[i].c_str(), NAPI_AUTO_LENGTH, &value));
        NAPI_CALL(env, napi_set_element(env, array, i, value));
    }
    return array;
}

napi_value CreateStatusArray(napi_env env, const std::vector<PermissionDecisionStatus>& values)
{
    napi_value array = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, values.size(), &array));
    for (size_t i = 0; i < values.size(); ++i) {
        napi_value value = nullptr;
        NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(values[i]), &value));
        NAPI_CALL(env, napi_set_element(env, array, i, value));
    }
    return array;
}

template<typename T, typename Converter>
napi_value CreateObjectArray(napi_env env, const std::vector<T>& values, Converter converter)
{
    napi_value array = nullptr;
    NAPI_CALL(env, napi_create_array_with_length(env, values.size(), &array));
    for (size_t i = 0; i < values.size(); ++i) {
        NAPI_CALL(env, napi_set_element(env, array, i, converter(env, values[i])));
    }
    return array;
}

bool SetNamedString(napi_env env, napi_value obj, const char* name, const std::string& value)
{
    napi_value property = nullptr;
    NAPI_CALL_BASE(env, napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &property), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, obj, name, property), false);
    return true;
}

bool SetNamedInt(napi_env env, napi_value obj, const char* name, int32_t value)
{
    napi_value property = nullptr;
    NAPI_CALL_BASE(env, napi_create_int32(env, value, &property), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, obj, name, property), false);
    return true;
}

bool SetNamedBool(napi_env env, napi_value obj, const char* name, bool value)
{
    napi_value property = nullptr;
    NAPI_CALL_BASE(env, napi_get_boolean(env, value, &property), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, obj, name, property), false);
    return true;
}

bool SetNamedRef(napi_env env, napi_value obj, const char* name, napi_value value)
{
    NAPI_CALL_BASE(env, napi_set_named_property(env, obj, name, value), false);
    return true;
}

napi_value CreatePermissionDialogDetail(napi_env env, const PermissionDialogDetail& detail)
{
    napi_value obj = nullptr;
    NAPI_CALL(env, napi_create_object(env, &obj));
    SetNamedBool(env, obj, "needPermissionDialog", detail.needPermissionDialog);
    SetNamedRef(env, obj, "permissionNameList", CreateStringArray(env, detail.permissionNameList));
    SetNamedRef(env, obj, "statusList", CreateStatusArray(env, detail.statusList));
    SetNamedString(env, obj, "authResult", detail.authResult);
    return obj;
}

napi_value CreatePermissionDialogResult(napi_env env, const PermissionDialogResult& result)
{
    napi_value obj = nullptr;
    NAPI_CALL(env, napi_create_object(env, &obj));
    SetNamedRef(env, obj, "detailList", CreateObjectArray(env, result.detailList, CreatePermissionDialogDetail));
    return obj;
}

napi_value CreateCliPermissionDetail(napi_env env, const CliPermissionDetail& detail)
{
    napi_value obj = nullptr;
    NAPI_CALL(env, napi_create_object(env, &obj));
    SetNamedString(env, obj, "requiredCliPermission", detail.requiredCliPermission);
    SetNamedInt(env, obj, "cliPermissionStatus", static_cast<int32_t>(detail.cliPermissionStatus));
    SetNamedRef(env, obj, "usedPermissions", CreateStringArray(env, detail.usedPermissions));
    return obj;
}

napi_value CreateCliCommandPermissionResult(napi_env env, const CliCommandPermissionResult& result)
{
    napi_value obj = nullptr;
    NAPI_CALL(env, napi_create_object(env, &obj));
    SetNamedRef(env, obj, "requiredCliPermissions",
        CreateObjectArray(env, result.requiredCliPermissions, CreateCliPermissionDetail));
    return obj;
}

napi_value CreateCliPermissionsResult(napi_env env, const CliPermissionsResult& result)
{
    napi_value obj = nullptr;
    NAPI_CALL(env, napi_create_object(env, &obj));
    SetNamedRef(env, obj, "permList", CreateObjectArray(env, result.permList, CreateCliCommandPermissionResult));
    return obj;
}

napi_value CreateSkillCommandPermissionResult(napi_env env, const SkillCommandPermissionResult& result)
{
    napi_value obj = nullptr;
    NAPI_CALL(env, napi_create_object(env, &obj));
    SetNamedRef(env, obj, "usedPermissions", CreateStringArray(env, result.usedPermissions));
    SetNamedRef(env, obj, "statusList", CreateStatusArray(env, result.statusList));
    return obj;
}

napi_value CreateSkillPermissionsResult(napi_env env, const SkillPermissionsResult& result)
{
    napi_value obj = nullptr;
    NAPI_CALL(env, napi_create_object(env, &obj));
    SetNamedRef(env, obj, "permList", CreateObjectArray(env, result.permList, CreateSkillCommandPermissionResult));
    return obj;
}

napi_value CreateToolAuthResult(napi_env env, const ToolAuthResult& result)
{
    napi_value obj = nullptr;
    NAPI_CALL(env, napi_create_object(env, &obj));
    SetNamedRef(env, obj, "authResults", CreateStringArray(env, result.authResults));
    return obj;
}

void ReturnPromiseResult(napi_env env, ClawPermissionAsyncContext& context, napi_value result)
{
    if (context.errorCode != RET_SUCCESS) {
        int32_t jsCode = GetJsErrorCode(context.errorCode);
        napi_value businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode, context.errorMsg));
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, context.deferred, businessError));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, context.deferred, result));
    }
    context.deferred = nullptr;
}

napi_value CreatePromiseWork(napi_env env, ClawPermissionAsyncContext* asyncContext, const char* resourceName)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, resourceName, NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, NapiClawPermission::Execute,
        NapiClawPermission::Complete, asyncContext, &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));
    return result;
}
} // namespace

napi_value NapiClawPermission::GetCliPermissionRequestInfo(napi_env env, napi_callback_info info)
{
    auto* asyncContext = new (std::nothrow) ClawPermissionAsyncContext(env);
    if (asyncContext == nullptr) {
        return nullptr;
    }
    std::unique_ptr<ClawPermissionAsyncContext> context {asyncContext};

    size_t argc = CLI_DIALOG_PARAM_COUNT;
    napi_value argv[CLI_DIALOG_PARAM_COUNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < CLI_DIALOG_PARAM_COUNT) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return nullptr;
    }
    if (!ParseAgentID(env, argv[0], asyncContext->agentID)) {
        ThrowParamError(env, "agentID", "string(<=48 chars)");
        return nullptr;
    }
    if (!ParseObjectArray(env, argv[1], asyncContext->cliInfoList, ParseCliInfo)) {
        ThrowParamError(env, "cliList", "Array<CliInfo>");
        return nullptr;
    }
    asyncContext->apiType = ClawPermissionApiType::GET_CLI_PERMISSION_DIALOG_INFO;
    napi_value result = CreatePromiseWork(env, asyncContext, "GetCliPermissionRequestInfo");
    context.release();
    return result;
}

napi_value NapiClawPermission::GetSkillPermissionRequestInfo(napi_env env, napi_callback_info info)
{
    auto* asyncContext = new (std::nothrow) ClawPermissionAsyncContext(env);
    if (asyncContext == nullptr) {
        return nullptr;
    }
    std::unique_ptr<ClawPermissionAsyncContext> context {asyncContext};

    size_t argc = SKILL_DIALOG_PARAM_COUNT;
    napi_value argv[SKILL_DIALOG_PARAM_COUNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < SKILL_DIALOG_PARAM_COUNT) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return nullptr;
    }
    if (!ParseAgentID(env, argv[0], asyncContext->agentID)) {
        ThrowParamError(env, "agentID", "string(<=48 chars)");
        return nullptr;
    }
    if (!ParseObjectArray(env, argv[1], asyncContext->skillInfoList, ParseSkillInfo)) {
        ThrowParamError(env, "skillList", "Array<SkillInfo>");
        return nullptr;
    }
    asyncContext->apiType = ClawPermissionApiType::GET_SKILL_PERMISSION_DIALOG_INFO;
    napi_value result = CreatePromiseWork(env, asyncContext, "GetSkillPermissionRequestInfo");
    context.release();
    return result;
}

napi_value NapiClawPermission::GetCliPermissions(napi_env env, napi_callback_info info)
{
    auto* asyncContext = new (std::nothrow) ClawPermissionAsyncContext(env);
    if (asyncContext == nullptr) {
        return nullptr;
    }
    std::unique_ptr<ClawPermissionAsyncContext> context {asyncContext};

    size_t argc = SYSTEM_PARAM_COUNT;
    napi_value argv[SYSTEM_PARAM_COUNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < SYSTEM_PARAM_COUNT) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return nullptr;
    }
    if (!ParseUint32(env, argv[0], asyncContext->hostTokenID)) {
        ThrowParamError(env, "hostTokenID", "number");
        return nullptr;
    }
    if (!ParseAgentID(env, argv[1], asyncContext->agentID)) {
        ThrowParamError(env, "agentID", "string(<=48 chars)");
        return nullptr;
    }
    if (!ParseObjectArray(env, argv[THIRD_PARAM_INDEX], asyncContext->cliInfoList, ParseCliInfo)) {
        ThrowParamError(env, "cliInfoList", "Array<CliInfo>");
        return nullptr;
    }
    asyncContext->apiType = ClawPermissionApiType::GET_CLI_PERMISSIONS;
    napi_value result = CreatePromiseWork(env, asyncContext, "GetCliPermissions");
    context.release();
    return result;
}

napi_value NapiClawPermission::GetSkillPermissions(napi_env env, napi_callback_info info)
{
    auto* asyncContext = new (std::nothrow) ClawPermissionAsyncContext(env);
    if (asyncContext == nullptr) {
        return nullptr;
    }
    std::unique_ptr<ClawPermissionAsyncContext> context {asyncContext};

    size_t argc = SYSTEM_PARAM_COUNT;
    napi_value argv[SYSTEM_PARAM_COUNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < SYSTEM_PARAM_COUNT) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return nullptr;
    }
    if (!ParseUint32(env, argv[0], asyncContext->hostTokenID)) {
        ThrowParamError(env, "hostTokenID", "number");
        return nullptr;
    }
    if (!ParseAgentID(env, argv[1], asyncContext->agentID)) {
        ThrowParamError(env, "agentID", "string(<=48 chars)");
        return nullptr;
    }
    if (!ParseObjectArray(env, argv[THIRD_PARAM_INDEX], asyncContext->skillInfoList, ParseSkillInfo)) {
        ThrowParamError(env, "skillInfoList", "Array<SkillInfo>");
        return nullptr;
    }
    asyncContext->apiType = ClawPermissionApiType::GET_SKILL_PERMISSIONS;
    napi_value result = CreatePromiseWork(env, asyncContext, "GetSkillPermissions");
    context.release();
    return result;
}

napi_value NapiClawPermission::GenerateCliAuthResult(napi_env env, napi_callback_info info)
{
    auto* asyncContext = new (std::nothrow) ClawPermissionAsyncContext(env);
    if (asyncContext == nullptr) {
        return nullptr;
    }
    std::unique_ptr<ClawPermissionAsyncContext> context {asyncContext};
    size_t argc = CHALLENGE_PARAM_COUNT;
    napi_value argv[CHALLENGE_PARAM_COUNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < CHALLENGE_PARAM_COUNT) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return nullptr;
    }
    if (!ParseUint32(env, argv[0], asyncContext->hostTokenID)) {
        ThrowParamError(env, "hostTokenID", "number");
        return nullptr;
    }
    if (!ParseAgentID(env, argv[1], asyncContext->agentID)) {
        ThrowParamError(env, "agentID", "string(<=48 chars)");
        return nullptr;
    }
    if (!ParseObjectArray(env, argv[THIRD_PARAM_INDEX], asyncContext->cliAuthInfoList, ParseCliAuthInfo)) {
        ThrowParamError(env, "authInfoList", "Array<CliAuthInfo>");
        return nullptr;
    }
    asyncContext->apiType = ClawPermissionApiType::GENERATE_CLI_AUTH_RESULT;
    napi_value result = CreatePromiseWork(env, asyncContext, "GenerateCliAuthResult");
    context.release();
    return result;
}

napi_value NapiClawPermission::GenerateSkillAuthResult(napi_env env, napi_callback_info info)
{
    auto* asyncContext = new (std::nothrow) ClawPermissionAsyncContext(env);
    if (asyncContext == nullptr) {
        return nullptr;
    }
    std::unique_ptr<ClawPermissionAsyncContext> context {asyncContext};
    size_t argc = CHALLENGE_PARAM_COUNT;
    napi_value argv[CHALLENGE_PARAM_COUNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < CHALLENGE_PARAM_COUNT) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return nullptr;
    }
    if (!ParseUint32(env, argv[0], asyncContext->hostTokenID)) {
        ThrowParamError(env, "hostTokenID", "number");
        return nullptr;
    }
    if (!ParseAgentID(env, argv[1], asyncContext->agentID)) {
        ThrowParamError(env, "agentID", "string(<=48 chars)");
        return nullptr;
    }
    if (!ParseObjectArray(env, argv[THIRD_PARAM_INDEX], asyncContext->skillAuthInfoList, ParseSkillAuthInfo)) {
        ThrowParamError(env, "authInfoList", "Array<SkillAuthInfo>");
        return nullptr;
    }
    asyncContext->apiType = ClawPermissionApiType::GENERATE_SKILL_AUTH_RESULT;
    napi_value result = CreatePromiseWork(env, asyncContext, "GenerateSkillAuthResult");
    context.release();
    return result;
}

void NapiClawPermission::Execute(napi_env env, void* data)
{
    ClawPermissionAsyncContext* asyncContext = reinterpret_cast<ClawPermissionAsyncContext*>(data);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return;
    }

    switch (asyncContext->apiType) {
        case ClawPermissionApiType::GET_CLI_PERMISSION_DIALOG_INFO:
            asyncContext->errorCode = AccessTokenKit::GetCliPermissionRequestInfo(
                asyncContext->agentID, asyncContext->cliInfoList, asyncContext->dialogResult);
            break;
        case ClawPermissionApiType::GET_SKILL_PERMISSION_DIALOG_INFO:
            asyncContext->errorCode = AccessTokenKit::GetSkillPermissionRequestInfo(
                asyncContext->agentID, asyncContext->skillInfoList, asyncContext->dialogResult);
            break;
        case ClawPermissionApiType::GET_CLI_PERMISSIONS:
            asyncContext->errorCode = AccessTokenKit::GetCliPermissions(asyncContext->hostTokenID,
                asyncContext->agentID, asyncContext->cliInfoList, asyncContext->cliPermissionsResult);
            break;
        case ClawPermissionApiType::GET_SKILL_PERMISSIONS:
            asyncContext->errorCode = AccessTokenKit::GetSkillPermissions(asyncContext->hostTokenID,
                asyncContext->agentID, asyncContext->skillInfoList, asyncContext->skillPermissionsResult);
            break;
        case ClawPermissionApiType::GENERATE_CLI_AUTH_RESULT:
            asyncContext->errorCode = AccessTokenKit::GenerateCliAuthResult(asyncContext->hostTokenID,
                asyncContext->agentID, asyncContext->cliAuthInfoList, asyncContext->toolAuthResult);
            break;
        case ClawPermissionApiType::GENERATE_SKILL_AUTH_RESULT:
            asyncContext->errorCode = AccessTokenKit::GenerateSkillAuthResult(asyncContext->hostTokenID,
                asyncContext->agentID, asyncContext->skillAuthInfoList, asyncContext->toolAuthResult);
            break;
        default:
            asyncContext->errorCode = RET_FAILED;
            break;
    }
}

void NapiClawPermission::Complete(napi_env env, napi_status status, void* data)
{
    ClawPermissionAsyncContext* asyncContext = reinterpret_cast<ClawPermissionAsyncContext*>(data);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return;
    }
    std::unique_ptr<ClawPermissionAsyncContext> context {asyncContext};

    napi_value result = nullptr;
    switch (asyncContext->apiType) {
        case ClawPermissionApiType::GET_CLI_PERMISSION_DIALOG_INFO:
        case ClawPermissionApiType::GET_SKILL_PERMISSION_DIALOG_INFO:
            result = CreatePermissionDialogResult(env, asyncContext->dialogResult);
            break;
        case ClawPermissionApiType::GET_CLI_PERMISSIONS:
            result = CreateCliPermissionsResult(env, asyncContext->cliPermissionsResult);
            break;
        case ClawPermissionApiType::GET_SKILL_PERMISSIONS:
            result = CreateSkillPermissionsResult(env, asyncContext->skillPermissionsResult);
            break;
        case ClawPermissionApiType::GENERATE_CLI_AUTH_RESULT:
        case ClawPermissionApiType::GENERATE_SKILL_AUTH_RESULT:
            result = CreateToolAuthResult(env, asyncContext->toolAuthResult);
            break;
        default:
            NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result));
            break;
    }
    ReturnPromiseResult(env, *asyncContext, result);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
