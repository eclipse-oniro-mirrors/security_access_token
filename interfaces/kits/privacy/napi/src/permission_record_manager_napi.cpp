/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "permission_record_manager_napi.h"
#include <vector>
#include "privacy_kit.h"
#include "accesstoken_log.h"
#include "napi_context_common.h"
#include "napi_common.h"
#include "napi_error.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "privacy_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::mutex g_lockForPermActiveChangeSubscribers;
std::vector<RegisterPermActiveChangeContext*> g_permActiveChangeSubscribers;
static constexpr size_t MAX_CALLBACK_SIZE = 200;
static constexpr int32_t ADD_PERMISSION_RECORD_MAX_PARAMS = 5;
static constexpr int32_t GET_PERMISSION_RECORD_MAX_PARAMS = 2;
static constexpr int32_t ON_OFF_MAX_PARAMS = 3;
static constexpr int32_t START_STOP_MAX_PARAMS = 3;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PermissionRecordManagerNapi"};
} // namespace

static int32_t GetJsErrorCode(uint32_t errCode)
{
    int32_t jsCode = JS_OK;
    switch (errCode) {
        case ERR_PARAM_INVALID:
            jsCode = JS_ERROR_PARAM_INVALID;
            break;
        case ERR_SERVICE_ABNORMAL:
        case ERR_READ_PARCEL_FAILED:
        case ERR_WRITE_PARCEL_FAILED:
        case ERR_IPC_PARCEL_FAILED:
        case ERR_MALLOC_FAILED:
            jsCode = JS_ERROR_SERVICE_NOT_RUNNING;
            break;
        case ERR_TOKENID_NOT_EXIST:
            jsCode = JS_ERROR_TOKENID_NOT_EXIST;
            break;
        case ERR_PERMISSION_NOT_EXIST:
            jsCode = JS_ERROR_PERMISSION_NOT_EXIST;
            break;
        case ERR_CALLBACK_ALREADY_EXIST:
        case ERR_CALLBACK_NOT_EXIST:
        case ERR_PERMISSION_ALREADY_START_USING:
        case ERR_PERMISSION_NOT_START_USING:
            jsCode = JS_ERROR_NOT_USE_TOGETHER;
            break;
        case ERR_CALLBACKS_EXCEED_LIMITATION:
            jsCode = JS_ERROR_REGISTERS_EXCEED_LIMITATION;
            break;
        case ERR_PERMISSION_DENIED:
            jsCode = JS_ERROR_PERMISSION_DENIED;
            break;
        default:
            break;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetJsErrorCode nativeCode(%{public}d) jsCode(%{public}d).", errCode, jsCode);
    return jsCode;
}

static void ParamResolveErrorThrow(const napi_env& env, const std::string& param, const std::string& type)
{
    std::string errMsg = GetParamErrorMsg(param, type);
    NAPI_CALL_RETURN_VOID(env, napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_ILLEGAL, errMsg)));
}

static bool ParseRequestResolveSomeParam(
    const napi_env& env, const napi_value& value, PermissionUsedRequest& request, napi_value& property)
{
    property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "isRemote", &property), false) ;
    if (!ParseBool(env, property, request.isRemote)) {
        ParamResolveErrorThrow(env, "request:isRemote", "boolean");
        return false;
    }

    property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "deviceId", &property), false);
    if (!ParseString(env, property, request.deviceId)) {
        ParamResolveErrorThrow(env, "request:deviceId", "string");
        return false;
    }
    return true;
}

static void ReturnPromiseResult(napi_env env, const RecordManagerAsyncContext& context, napi_value result)
{
    if (context.retCode != RET_SUCCESS) {
        int32_t jsCode = GetJsErrorCode(context.retCode);
        napi_value businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode));
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, context.deferred, businessError));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, context.deferred, result));
    }
}

static void ReturnCallbackResult(napi_env env, const RecordManagerAsyncContext& context, napi_value result)
{
    napi_value businessError = GetNapiNull(env);
    if (context.retCode != RET_SUCCESS) {
        int32_t jsCode = GetJsErrorCode(context.retCode);
        businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode));
    }
    napi_value results[ASYNC_CALL_BACK_VALUES_NUM] = { businessError, result };

    napi_value callback = nullptr;
    napi_value thisValue = nullptr;
    napi_value thatValue = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &thisValue));
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 0, &thatValue));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, context.callbackRef, &callback));
    NAPI_CALL_RETURN_VOID(env,
        napi_call_function(env, thisValue, callback, ASYNC_CALL_BACK_VALUES_NUM, results, &thatValue));
}

static bool ParseAddPermissionRecord(
    const napi_env env, const napi_callback_info info, RecordManagerAsyncContext& asyncContext)
{
    size_t argc = ADD_PERMISSION_RECORD_MAX_PARAMS;
    napi_value argv[ADD_PERMISSION_RECORD_MAX_PARAMS] = { nullptr };
    napi_value thisVar = nullptr;
    void* data = nullptr;

    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
    if (argc < ADD_PERMISSION_RECORD_MAX_PARAMS - 1) {
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }

    asyncContext.env = env;
    // 0: the first parameter of argv
    if (!ParseUint32(env, argv[0], asyncContext.tokenId)) {
        ParamResolveErrorThrow(env, "tokenID", "number");
        return false;
    }

    // 1: the second parameter of argv
    if (!ParseString(env, argv[1], asyncContext.permissionName)) {
        ParamResolveErrorThrow(env, "permissionName", "string");
        return false;
    }

    // 2: the third parameter of argv
    if (!ParseInt32(env, argv[2], asyncContext.successCount)) {
        ParamResolveErrorThrow(env, "successCount", "number");
        return false;
    }

    // 3: the fourth parameter of argv
    if (!ParseInt32(env, argv[3], asyncContext.failCount)) {
        ParamResolveErrorThrow(env, "failCount", "number");
        return false;
    }
    if (argc == ADD_PERMISSION_RECORD_MAX_PARAMS) {
        // 4: : the fifth parameter of argv
        if (!ParseCallback(env, argv[4], asyncContext.callbackRef)) {
            ParamResolveErrorThrow(env, "callback", "AsyncCallback");
            return false;
        }
    }
    return true;
}

static bool ParseStartAndStopUsingPermission(
    const napi_env env, const napi_callback_info info, RecordManagerAsyncContext& asyncContext)
{
    size_t argc = START_STOP_MAX_PARAMS;
    napi_value argv[START_STOP_MAX_PARAMS] = { nullptr };
    napi_value thisVar = nullptr;
    void* data = nullptr;

    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
    if (argc < START_STOP_MAX_PARAMS - 1) {
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }

    asyncContext.env = env;
    // 0: the first parameter of argv
    if (!ParseUint32(env, argv[0], asyncContext.tokenId)) {
        ParamResolveErrorThrow(env, "tokenId", "number");
        return false;
    }

    // 1: the second parameter of argv
    if (!ParseString(env, argv[1], asyncContext.permissionName)) {
        ParamResolveErrorThrow(env, "permissionName", "string");
        return false;
    }
    if (argc == START_STOP_MAX_PARAMS) {
        // 2: the third parameter of argv
        if (!ParseCallback(env, argv[2], asyncContext.callbackRef)) {
            ParamResolveErrorThrow(env, "callback", "AsyncCallback");
            return false;
        }
    }
    return true;
}

static void ConvertDetailUsedRecord(napi_env env, napi_value value, const UsedRecordDetail& detailRecord)
{
    napi_value nStatus;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, detailRecord.status, &nStatus));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "status", nStatus));

    napi_value nTimestamp;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, detailRecord.timestamp, &nTimestamp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "timestamp", nTimestamp));

    napi_value nAccessDuration;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, detailRecord.accessDuration, &nAccessDuration));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "accessDuration", nAccessDuration));
}

static void ConvertPermissionUsedRecord(napi_env env, napi_value value, const PermissionUsedRecord& permissionRecord)
{
    napi_value nPermissionName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env,
        permissionRecord.permissionName.c_str(), NAPI_AUTO_LENGTH, &nPermissionName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "permissionName", nPermissionName));

    napi_value nAccessCount;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, permissionRecord.accessCount, &nAccessCount));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "accessCount", nAccessCount));

    napi_value nRejectCount;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, permissionRecord.rejectCount, &nRejectCount));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "rejectCount", nRejectCount));

    napi_value nLastAccessTime;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, permissionRecord.lastAccessTime, &nLastAccessTime));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "lastAccessTime", nLastAccessTime));

    napi_value nLastRejectTime;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, permissionRecord.lastRejectTime, &nLastRejectTime));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "lastRejectTime", nLastRejectTime));

    napi_value nLastAccessDuration;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, permissionRecord.lastAccessDuration, &nLastAccessDuration));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "lastAccessDuration", nLastAccessDuration));

    size_t index = 0;
    napi_value objAccessRecords;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &objAccessRecords));
    for (const auto& accRecord : permissionRecord.accessRecords) {
        napi_value objAccessRecord;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objAccessRecord));
        ConvertDetailUsedRecord(env, objAccessRecord, accRecord);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, objAccessRecords, index, objAccessRecord));
        index++;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "accessRecords", objAccessRecords));

    index = 0;
    napi_value objRejectRecords;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &objRejectRecords));
    for (const auto& rejRecord : permissionRecord.rejectRecords) {
        napi_value objRejectRecord;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objRejectRecord));
        ConvertDetailUsedRecord(env, objRejectRecord, rejRecord);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, objRejectRecords, index, objRejectRecord));
        index++;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "rejectRecords", objRejectRecords));
}

static void ConvertBundleUsedRecord(napi_env env, napi_value value, const BundleUsedRecord& bundleRecord)
{
    napi_value nTokenId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, bundleRecord.tokenId, &nTokenId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "tokenId", nTokenId));

    napi_value nIsRemote;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, bundleRecord.isRemote, &nIsRemote));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "isRemote", nIsRemote));

    napi_value nDeviceId;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env,
        bundleRecord.deviceId.c_str(), NAPI_AUTO_LENGTH, &nDeviceId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "deviceId", nDeviceId));

    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env,
        bundleRecord.bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "bundleName", nBundleName));
    size_t index = 0;
    napi_value objPermissionRecords;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &objPermissionRecords));
    for (const auto& permRecord : bundleRecord.permissionRecords) {
        napi_value objPermissionRecord;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objPermissionRecord));
        ConvertPermissionUsedRecord(env, objPermissionRecord, permRecord);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, objPermissionRecords, index, objPermissionRecord));
        index++;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "permissionRecords", objPermissionRecords));
}

static void ProcessRecordResult(napi_env env, napi_value value, const PermissionUsedResult& result)
{
    napi_value nBeginTimestamp;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, result.beginTimeMillis, &nBeginTimestamp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "beginTime", nBeginTimestamp));

    napi_value nEndTimestamp;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, result.endTimeMillis, &nEndTimestamp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "endTime", nEndTimestamp));

    size_t index = 0;
    napi_value objBundleRecords;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &objBundleRecords));
    for (const auto& bundleRecord : result.bundleRecords) {
        napi_value objBundleRecord;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objBundleRecord));
        ConvertBundleUsedRecord(env, objBundleRecord, bundleRecord);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, objBundleRecords, index, objBundleRecord));
        index++;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "bundleRecords", objBundleRecords));
}

static bool ParseRequest(const napi_env& env, const napi_value& value, PermissionUsedRequest& request)
{
    if (!CheckType(env, value, napi_object)) {
        return false;
    }
    napi_value property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "tokenId", &property), false);
    if (!ParseUint32(env, property, request.tokenId)) {
        ParamResolveErrorThrow(env, "request:tokenId", "number");
        return false;
    }

    if (!ParseRequestResolveSomeParam(env, value, request, property)) {
        return false;
    }

    property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "bundleName", &property), false);
    if (!ParseString(env, property, request.bundleName)) {
        ParamResolveErrorThrow(env, "request:bundleName", "string");
        return false;
    }

    property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "beginTime", &property), false);
    if (!ParseInt64(env, property, request.beginTimeMillis)) {
        ParamResolveErrorThrow(env, "request:beginTime", "number");
        return false;
    }

    property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "endTime", &property), false);
    if (!ParseInt64(env, property, request.endTimeMillis)) {
        ParamResolveErrorThrow(env, "request:endTime", "number");
        return false;
    }

    property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "permissionNames", &property), false);
    if (!ParseStringArray(env, property, request.permissionList)) {
        ParamResolveErrorThrow(env, "request:permissionNames", "Array<string>");
        return false;
    }

    property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "flag", &property), false);
    int32_t flag;
    if (!ParseInt32(env, property, flag)) {
        ParamResolveErrorThrow(env, "request:flag", "number");
        return false;
    }
    request.flag = static_cast<PermissionUsageFlagEnum>(flag);

    return true;
}

static bool ParseGetPermissionUsedRecords(
    const napi_env env, const napi_callback_info info, RecordManagerAsyncContext& asyncContext)
{
    size_t argc = GET_PERMISSION_RECORD_MAX_PARAMS;
    napi_value argv[GET_PERMISSION_RECORD_MAX_PARAMS] = { nullptr };
    napi_value thisVar = nullptr;
    void* data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
    if (argc < GET_PERMISSION_RECORD_MAX_PARAMS - 1) {
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }

    asyncContext.env = env;

    // 0: the first parameter of argv
    if (!ParseRequest(env, argv[0], asyncContext.request)) {
        return false;
    }

    if (argc == GET_PERMISSION_RECORD_MAX_PARAMS) {
        // 1: the second parameter of argv
        if (!ParseCallback(env, argv[1], asyncContext.callbackRef)) {
            ParamResolveErrorThrow(env, "callback", "AsyncCallback");
            return false;
        }
    }
    return true;
}

static void AddPermissionUsedRecordExecute(napi_env env, void* data)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "AddPermissionUsedRecord execute.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    asyncContext->retCode = PrivacyKit::AddPermissionUsedRecord(asyncContext->tokenId,
        asyncContext->permissionName, asyncContext->successCount, asyncContext->failCount);
}

static void AddPermissionUsedRecordComplete(napi_env env, napi_status status, void* data)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "AddPermissionUsedRecord complete.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    std::unique_ptr<RecordManagerAsyncContext> callbackPtr {asyncContext};
    napi_value result = GetNapiNull(env);
    if (asyncContext->deferred != nullptr) {
        ReturnPromiseResult(env, *asyncContext, result);
    } else {
        ReturnCallbackResult(env, *asyncContext, result);
    }
}

napi_value AddPermissionUsedRecord(napi_env env, napi_callback_info cbinfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "AddPermissionUsedRecord begin.");

    auto *asyncContext = new (std::nothrow) RecordManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    std::unique_ptr<RecordManagerAsyncContext> callbackPtr {asyncContext};
    if (!ParseAddPermissionRecord(env, cbinfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "AddPermissionUsedRecord", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        AddPermissionUsedRecordExecute,
        AddPermissionUsedRecordComplete,
        reinterpret_cast<void *>(asyncContext),
        &(asyncContext->asyncWork)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->asyncWork));
    callbackPtr.release();
    return result;
}

static void StartUsingPermissionExecute(napi_env env, void* data)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "StartUsingPermission execute.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    asyncContext->retCode = PrivacyKit::StartUsingPermission(asyncContext->tokenId,
        asyncContext->permissionName);
}

static void StartUsingPermissionComplete(napi_env env, napi_status status, void* data)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "StartUsingPermission complete.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    std::unique_ptr<RecordManagerAsyncContext> callbackPtr{asyncContext};
    napi_value result = GetNapiNull(env);
    if (asyncContext->deferred != nullptr) {
        ReturnPromiseResult(env, *asyncContext, result);
    } else {
        ReturnCallbackResult(env, *asyncContext, result);
    }
}

napi_value StartUsingPermission(napi_env env, napi_callback_info cbinfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "StartUsingPermission begin.");
    auto *asyncContext = new (std::nothrow) RecordManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    std::unique_ptr<RecordManagerAsyncContext> callbackPtr {asyncContext};
    if (!ParseStartAndStopUsingPermission(env, cbinfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "StartUsingPermission", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        StartUsingPermissionExecute,
        StartUsingPermissionComplete,
        reinterpret_cast<void *>(asyncContext),
        &(asyncContext->asyncWork)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->asyncWork));
    callbackPtr.release();
    return result;
}

static void StopUsingPermissionExecute(napi_env env, void* data)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "StopUsingPermission execute.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    asyncContext->retCode = PrivacyKit::StopUsingPermission(asyncContext->tokenId,
        asyncContext->permissionName);
}

static void StopUsingPermissionComplete(napi_env env, napi_status status, void* data)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "StopUsingPermission complete.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    std::unique_ptr<RecordManagerAsyncContext> callbackPtr{asyncContext};
    napi_value result = GetNapiNull(env);

    if (asyncContext->deferred != nullptr) {
        ReturnPromiseResult(env, *asyncContext, result);
    } else {
        ReturnCallbackResult(env, *asyncContext, result);
    }
}

napi_value StopUsingPermission(napi_env env, napi_callback_info cbinfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "StopUsingPermission begin.");

    auto *asyncContext = new (std::nothrow) RecordManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    std::unique_ptr<RecordManagerAsyncContext> callbackPtr {asyncContext};
    if (!ParseStartAndStopUsingPermission(env, cbinfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "StopUsingPermission", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        StopUsingPermissionExecute,
        StopUsingPermissionComplete,
        reinterpret_cast<void *>(asyncContext),
        &(asyncContext->asyncWork)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->asyncWork));
    callbackPtr.release();
    return result;
}

static void GetPermissionUsedRecordsExecute(napi_env env, void* data)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetPermissionUsedRecords execute.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    asyncContext->retCode = PrivacyKit::GetPermissionUsedRecords(asyncContext->request, asyncContext->result);
}

static void GetPermissionUsedRecordsComplete(napi_env env, napi_status status, void* data)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetPermissionUsedRecords complete.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    std::unique_ptr<RecordManagerAsyncContext> callbackPtr{asyncContext};
    napi_value result = GetNapiNull(env);
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result));
    ProcessRecordResult(env, result, asyncContext->result);
    if (asyncContext->deferred != nullptr) {
        ReturnPromiseResult(env, *asyncContext, result);
    } else {
        ReturnCallbackResult(env, *asyncContext, result);
    }
}

napi_value GetPermissionUsedRecords(napi_env env, napi_callback_info cbinfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetPermissionUsedRecords begin.");
    auto *asyncContext = new (std::nothrow) RecordManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    std::unique_ptr<RecordManagerAsyncContext> callbackPtr {asyncContext};
    if (!ParseGetPermissionUsedRecords(env, cbinfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetPermissionUsedRecords", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        GetPermissionUsedRecordsExecute,
        GetPermissionUsedRecordsComplete,
        reinterpret_cast<void *>(asyncContext),
        &(asyncContext->asyncWork)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->asyncWork));
    callbackPtr.release();
    return result;
}

static bool ParseInputToRegister(const napi_env env, const napi_callback_info cbInfo,
    RegisterPermActiveChangeContext& registerPermActiveChangeContext)
{
    size_t argc = ON_OFF_MAX_PARAMS;
    napi_value argv[ON_OFF_MAX_PARAMS] = {nullptr};
    napi_value thisVar = nullptr;
    napi_ref callback = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr), false);
    if (argc < ON_OFF_MAX_PARAMS) {
        NAPI_CALL_BASE(
            env, napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }

    std::string type;
    // 0: the first parameter of argv
    if (!ParseString(env, argv[0], type)) {
        ParamResolveErrorThrow(env, "type", "string");
        return false;
    }
    std::vector<std::string> permList;
    // 1: the second parameter of argv
    if (!ParseStringArray(env, argv[1], permList)) {
        ParamResolveErrorThrow(env, "permList", "Array<string>");
        return false;
    }
    std::sort(permList.begin(), permList.end());
    // 2: the third parameter of argv
    if (!ParseCallback(env, argv[2], callback)) {
        ParamResolveErrorThrow(env, "callback", "AsyncCallback");
        return false;
    }
    registerPermActiveChangeContext.env = env;
    registerPermActiveChangeContext.callbackRef = callback;
    registerPermActiveChangeContext.type = type;
    registerPermActiveChangeContext.subscriber = std::make_shared<PermActiveStatusPtr>(permList);
    registerPermActiveChangeContext.subscriber->SetEnv(env);
    registerPermActiveChangeContext.subscriber->SetCallbackRef(callback);
    return true;
}

static bool ParseInputToUnregister(const napi_env env, const napi_callback_info cbInfo,
    UnregisterPermActiveChangeContext& unregisterPermActiveChangeContext)
{
    size_t argc = ON_OFF_MAX_PARAMS;
    napi_value argv[ON_OFF_MAX_PARAMS] = {nullptr};
    napi_value thisVar = nullptr;
    napi_ref callback = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr), false);
    if (argc < ON_OFF_MAX_PARAMS - 1) {
        NAPI_CALL_BASE(
            env, napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }

    std::string type;
    // 0: the first parameter of argv
    if (!ParseString(env, argv[0], type)) {
        ParamResolveErrorThrow(env, "permList", "Array<string>");
        return false;
    }
    // 1: the second parameter of argv
    std::vector<std::string> permList;
    if (!ParseStringArray(env, argv[1], permList)) {
        ParamResolveErrorThrow(env, "permList", "Array<string>");
        return false;
    }
    std::sort(permList.begin(), permList.end());
    if (argc == ON_OFF_MAX_PARAMS) {
        // 2: the first parameter of argv
        if (!ParseCallback(env, argv[2], callback)) {
            ParamResolveErrorThrow(env, "callback", "AsyncCallback");
            return false;
        }
    }
    unregisterPermActiveChangeContext.env = env;
    unregisterPermActiveChangeContext.callbackRef = callback;
    unregisterPermActiveChangeContext.type = type;
    unregisterPermActiveChangeContext.permList = permList;
    return true;
}

static bool IsExistRegister(const PermActiveChangeContext* permActiveChangeContext)
{
    std::vector<std::string> targetPermList;
    permActiveChangeContext->subscriber->GetPermList(targetPermList);
    std::lock_guard<std::mutex> lock(g_lockForPermActiveChangeSubscribers);
    for (const auto& item : g_permActiveChangeSubscribers) {
        std::vector<std::string> permList;
        item->subscriber->GetPermList(permList);
        if (permList == targetPermList) {
            return true;
        }
    }
    return false;
}

static void DeleteRegisterInVector(PermActiveChangeContext* permActiveChangeContext)
{
    std::vector<std::string> targetPermList;
    permActiveChangeContext->subscriber->GetPermList(targetPermList);
    std::lock_guard<std::mutex> lock(g_lockForPermActiveChangeSubscribers);
    auto item = g_permActiveChangeSubscribers.begin();
    while (item != g_permActiveChangeSubscribers.end()) {
        std::vector<std::string> permList;
        (*item)->subscriber->GetPermList(permList);
        if (permList == targetPermList) {
            delete *item;
            *item = nullptr;
            g_permActiveChangeSubscribers.erase(item);
            return;
        } else {
            ++item;
        }
    }
}

static bool FindAndGetSubscriber(UnregisterPermActiveChangeContext* unregisterPermActiveChangeContext)
{
    std::vector<std::string> targetPermList = unregisterPermActiveChangeContext->permList;
    std::lock_guard<std::mutex> lock(g_lockForPermActiveChangeSubscribers);
    for (const auto& item : g_permActiveChangeSubscribers) {
        std::vector<std::string> permList;
        item->subscriber->GetPermList(permList);
        if (permList == targetPermList) {
            // targetCallback != nullptr, unregister the subscriber with same permList and callback
            unregisterPermActiveChangeContext->subscriber = item->subscriber;
            return true;
        }
    }
    return false;
}

napi_value RegisterPermActiveChangeCallback(napi_env env, napi_callback_info cbInfo)
{
    RegisterPermActiveChangeContext* registerPermActiveChangeContext =
        new (std::nothrow) RegisterPermActiveChangeContext();
    if (registerPermActiveChangeContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "insufficient memory for subscribeCBInfo!");
        return nullptr;
    }
    std::unique_ptr<RegisterPermActiveChangeContext> callbackPtr {registerPermActiveChangeContext};
    if (!ParseInputToRegister(env, cbInfo, *registerPermActiveChangeContext)) {
        return nullptr;
    }
    if (IsExistRegister(registerPermActiveChangeContext)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Subscribe failed. The current subscriber has been existed");
        std::string errMsg = GetErrorMessage(JsErrorCode::JS_ERROR_PARAM_INVALID);
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_INVALID, errMsg)));
        return nullptr;
    }
    int32_t result = PrivacyKit::RegisterPermActiveStatusCallback(registerPermActiveChangeContext->subscriber);
    if (result != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "RegisterPermActiveStatusCallback failed");
        int32_t jsCode = GetJsErrorCode(result);
        std::string errMsg = GetErrorMessage(jsCode);
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, jsCode, errMsg)));
        return nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(g_lockForPermActiveChangeSubscribers);
        if (g_permActiveChangeSubscribers.size() >= MAX_CALLBACK_SIZE) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "subscribers size has reached max value");
            return nullptr;
        }
        g_permActiveChangeSubscribers.emplace_back(registerPermActiveChangeContext);
    }
    callbackPtr.release();
    return nullptr;
}

napi_value UnregisterPermActiveChangeCallback(napi_env env, napi_callback_info cbInfo)
{
    UnregisterPermActiveChangeContext* unregisterPermActiveChangeContext =
        new (std::nothrow) UnregisterPermActiveChangeContext();
    if (unregisterPermActiveChangeContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "insufficient memory for subscribeCBInfo!");
        return nullptr;
    }
    std::unique_ptr<UnregisterPermActiveChangeContext> callbackPtr {unregisterPermActiveChangeContext};
    if (!ParseInputToUnregister(env, cbInfo, *unregisterPermActiveChangeContext)) {
        return nullptr;
    }
    if (!FindAndGetSubscriber(unregisterPermActiveChangeContext)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Unsubscribe failed. The current subscriber does not exist");
        std::string errMsg = GetErrorMessage(JsErrorCode::JS_ERROR_PARAM_INVALID);
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_INVALID, errMsg)));
        return nullptr;
    }
    int32_t result = PrivacyKit::UnRegisterPermActiveStatusCallback(unregisterPermActiveChangeContext->subscriber);
    if (result == RET_SUCCESS) {
        DeleteRegisterInVector(unregisterPermActiveChangeContext);
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UnregisterPermActiveChangeCompleted failed");
        int32_t jsCode = GetJsErrorCode(result);
        std::string errMsg = GetErrorMessage(jsCode);
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, jsCode, errMsg)));
    }
    return nullptr;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS