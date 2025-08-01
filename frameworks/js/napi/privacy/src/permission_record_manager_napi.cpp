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
#include <cinttypes>
#include <vector>
#include "privacy_kit.h"
#include "accesstoken_common_log.h"
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
static constexpr int32_t ADD_PERMISSION_RECORD_MIN_PARAMS = 4;
static constexpr int32_t GET_PERMISSION_RECORD_MAX_PARAMS = 2;
static constexpr int32_t ON_OFF_MAX_PARAMS = 3;
static constexpr int32_t START_STOP_MAX_PARAMS = 4;
static constexpr int32_t START_STOP_MIN_PARAMS = 2;
static constexpr int32_t GET_PERMISSION_USED_TYPE_MAX_PARAMS = 2;
static constexpr int32_t GET_PERMISSION_USED_TYPE_ONE_PARAMS = 1;
static constexpr int32_t FIRST_PARAM = 0;
static constexpr int32_t SECOND_PARAM = 1;
static constexpr int32_t THIRD_PARAM = 2;
static constexpr int32_t FOURTH_PARAM = 3;
static constexpr int32_t FIFTH_PARAM = 4;
static constexpr int32_t SET_PERMISSION_USED_TOGGLE_STATUS_PARAMS = 1;


static int32_t GetJsErrorCode(int32_t errCode)
{
    int32_t jsCode;
    switch (errCode) {
        case RET_SUCCESS:
            jsCode = JS_OK;
            break;
        case ERR_PERMISSION_DENIED:
            jsCode = JS_ERROR_PERMISSION_DENIED;
            break;
        case ERR_NOT_SYSTEM_APP:
            jsCode = JS_ERROR_NOT_SYSTEM_APP;
            break;
        case ERR_PARAM_INVALID:
            jsCode = JS_ERROR_PARAM_INVALID;
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
        case ERR_IDENTITY_CHECK_FAILED:
            jsCode = JS_ERROR_PERMISSION_OPERATION_NOT_ALLOWED;
            break;
        case ERR_SERVICE_ABNORMAL:
        case ERROR_IPC_REQUEST_FAIL:
        case ERR_READ_PARCEL_FAILED:
        case ERR_WRITE_PARCEL_FAILED:
            jsCode = JS_ERROR_SERVICE_NOT_RUNNING;
            break;
        case ERR_MALLOC_FAILED:
            jsCode = JS_ERROR_OUT_OF_MEMORY;
            break;
        default:
            jsCode = JS_ERROR_INNER;
            break;
    }
    LOGD(PRI_DOMAIN, PRI_TAG, "GetJsErrorCode nativeCode(%{public}d) jsCode(%{public}d).", errCode, jsCode);
    return jsCode;
}

static void ParamResolveErrorThrow(const napi_env& env, const std::string& param, const std::string& type)
{
    std::string errMsg = GetParamErrorMsg(param, type);
    NAPI_CALL_RETURN_VOID(env, napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_ILLEGAL, errMsg)));
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

static bool ParseAddPermissionFifthParam(const napi_env env, const napi_value& value,
    RecordManagerAsyncContext& asyncContext)
{
    napi_valuetype typeValue = napi_undefined;
    napi_typeof(env, value, &typeValue);

    if (typeValue == napi_object) {
        // options
        napi_value property = nullptr;
        uint32_t type = 0;
        /* if AddPermissionUsedRecordOptions exsit valid property, asyncContext.type use input param
         * if not, asyncContext.type use default NORMAL_TYPE
         */
        if (IsNeedParseProperty(env, value, "usedType", property)) {
            if (!ParseUint32(env, property, type)) {
                ParamResolveErrorThrow(env, "AddPermissionUsedRecordOptions:usedType", "number");
                return false;
            }

            asyncContext.type = static_cast<PermissionUsedType>(type);
        }
    } else if (typeValue == napi_function) {
        // callback
        if (!IsUndefinedOrNull(env, value) && !ParseCallback(env, value, asyncContext.callbackRef)) {
            ParamResolveErrorThrow(env, "callback", "AsyncCallback");
            return false;
        }
    } else {
        ParamResolveErrorThrow(env, "fifth param", "options or AsyncCallback");
        return false;
    }

    return true;
}

static bool ParseAddPermissionRecord(
    const napi_env env, const napi_callback_info info, RecordManagerAsyncContext& asyncContext)
{
    size_t argc = ADD_PERMISSION_RECORD_MAX_PARAMS;
    napi_value argv[ADD_PERMISSION_RECORD_MAX_PARAMS] = { nullptr };
    napi_value thisVar = nullptr;
    void* data = nullptr;

    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
    if (argc < ADD_PERMISSION_RECORD_MIN_PARAMS) {
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }

    asyncContext.env = env;
    // 0: the first parameter of argv
    if (!ParseUint32(env, argv[FIRST_PARAM], asyncContext.tokenId)) {
        ParamResolveErrorThrow(env, "tokenID", "number");
        return false;
    }

    // 1: the second parameter of argv
    if (!ParseString(env, argv[SECOND_PARAM], asyncContext.permissionName)) {
        ParamResolveErrorThrow(env, "permissionName", "Permissions");
        return false;
    }

    // 2: the third parameter of argv
    if (!ParseInt32(env, argv[THIRD_PARAM], asyncContext.successCount)) {
        ParamResolveErrorThrow(env, "successCount", "number");
        return false;
    }

    // 3: the fourth parameter of argv
    if (!ParseInt32(env, argv[FOURTH_PARAM], asyncContext.failCount)) {
        ParamResolveErrorThrow(env, "failCount", "number");
        return false;
    }

    // 4: the fifth parameter of argv, may be napi_object or napi_function
    if (argc == ADD_PERMISSION_RECORD_MAX_PARAMS) {
        if (!ParseAddPermissionFifthParam(env, argv[FIFTH_PARAM], asyncContext)) {
            return false;
        }
    }

    return true;
}

static bool ParsePermissionUsedRecordToggleStatus(
    const napi_env& env, const napi_callback_info& info, RecordManagerAsyncContext& asyncContext)
{
    size_t argc = SET_PERMISSION_USED_TOGGLE_STATUS_PARAMS;
    napi_value argv[SET_PERMISSION_USED_TOGGLE_STATUS_PARAMS] = { nullptr };
    napi_value thisVar = nullptr;
    void* data = nullptr;

    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
    if (argc != SET_PERMISSION_USED_TOGGLE_STATUS_PARAMS) {
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_ILLEGAL, "Parameter error.")), false);
        return false;
    }

    asyncContext.env = env;
    // 0: the first parameter of argv
    if (!ParseBool(env, argv[FIRST_PARAM], asyncContext.status)) {
        ParamResolveErrorThrow(env, "status", "boolean");
        return false;
    }

    return true;
}

static bool ParseStartAndStopThirdParam(const napi_env env, const napi_value& value,
    RecordManagerAsyncContext& asyncContext)
{
    napi_valuetype typeValue = napi_undefined;
    if (napi_typeof(env, value, &typeValue) != napi_ok) {
        return false;
    }

    if (typeValue == napi_number) {
        // pid
        if (!ParseInt32(env, value, asyncContext.pid)) {
            ParamResolveErrorThrow(env, "pid", "number");
            return false;
        }
    } else if (typeValue == napi_function) {
        // callback
        if (!IsUndefinedOrNull(env, value) && !ParseCallback(env, value, asyncContext.callbackRef)) {
            ParamResolveErrorThrow(env, "callback", "AsyncCallback");
            return false;
        }
    } else {
        ParamResolveErrorThrow(env, "third param", "pid or AsyncCallback");
        return false;
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
    if (argc < START_STOP_MIN_PARAMS) {
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }

    asyncContext.env = env;
    // 0: the first parameter of argv is tokenId
    if (!ParseUint32(env, argv[FIRST_PARAM], asyncContext.tokenId)) {
        ParamResolveErrorThrow(env, "tokenID", "number");
        return false;
    }

    // 1: the second parameter of argv is permissionName
    if (!ParseString(env, argv[SECOND_PARAM], asyncContext.permissionName)) {
        ParamResolveErrorThrow(env, "permissionName", "Permissions");
        return false;
    }

    if (argc == START_STOP_MAX_PARAMS - 1) {
        // 2: the third paramter of argv, may be callback or pid
        if (!ParseStartAndStopThirdParam(env, argv[THIRD_PARAM], asyncContext)) {
            return false;
        }
    } else if (argc == START_STOP_MAX_PARAMS) {
        // 2: the third paramter of argv is pid
        if (!ParseInt32(env, argv[THIRD_PARAM], asyncContext.pid)) {
            ParamResolveErrorThrow(env, "pid", "number");
            return false;
        }

        // 3: the fourth paramter of argv is usedType
        uint32_t usedType = 0;
        if (!ParseUint32(env, argv[FOURTH_PARAM], usedType)) {
            ParamResolveErrorThrow(env, "usedType", "number");
            return false;
        }

        asyncContext.type = static_cast<PermissionUsedType>(usedType);
    }
    return true;
}

static void ConvertDetailUsedRecord(napi_env env, napi_value value, const UsedRecordDetail& detailRecord)
{
    napi_value nStatus;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, detailRecord.status, &nStatus));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "status", nStatus));

    napi_value nLockScreenStatus;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, detailRecord.lockScreenStatus, &nLockScreenStatus));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "lockScreenStatus", nLockScreenStatus));

    napi_value nTimestamp;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, detailRecord.timestamp, &nTimestamp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "timestamp", nTimestamp));

    napi_value nAccessDuration;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, detailRecord.accessDuration, &nAccessDuration));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "accessDuration", nAccessDuration));

    napi_value nCount;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, detailRecord.count, &nCount));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "count", nCount));

    napi_value nUsedType;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, detailRecord.type, &nUsedType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "usedType", nUsedType));
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
    napi_value property = nullptr;
    if (IsNeedParseProperty(env, value, "tokenId", property) && !ParseUint32(env, property, request.tokenId)) {
        ParamResolveErrorThrow(env, "request:tokenId", "number");
        return false;
    }

    if (IsNeedParseProperty(env, value, "isRemote", property) && !ParseBool(env, property, request.isRemote)) {
        ParamResolveErrorThrow(env, "request:isRemote", "boolean");
        return false;
    }

    if (IsNeedParseProperty(env, value, "deviceId", property) && !ParseString(env, property, request.deviceId)) {
        ParamResolveErrorThrow(env, "request:deviceId", "string");
        return false;
    }

    if (IsNeedParseProperty(env, value, "bundleName", property) && !ParseString(env, property, request.bundleName)) {
        ParamResolveErrorThrow(env, "request:bundleName", "string");
        return false;
    }

    if (IsNeedParseProperty(env, value, "beginTime", property) && !ParseInt64(env, property, request.beginTimeMillis)) {
        ParamResolveErrorThrow(env, "request:beginTime", "number");
        return false;
    }

    if (IsNeedParseProperty(env, value, "endTime", property) && !ParseInt64(env, property, request.endTimeMillis)) {
        ParamResolveErrorThrow(env, "request:endTime", "number");
        return false;
    }

    if (IsNeedParseProperty(env, value, "permissionNames", property) &&
        !ParseStringArray(env, property, request.permissionList)) {
        ParamResolveErrorThrow(env, "request:permissionNames", "Array<Permissions>");
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
    if (!CheckType(env, argv[0], napi_object)) {
        ParamResolveErrorThrow(env, "request", "PermissionUsedRequest");
        return false;
    }
    if (!ParseRequest(env, argv[0], asyncContext.request)) {
        return false;
    }

    if (argc == GET_PERMISSION_RECORD_MAX_PARAMS) {
        // 1: the second parameter of argv
        if (!IsUndefinedOrNull(env, argv[1]) && !ParseCallback(env, argv[1], asyncContext.callbackRef)) {
            ParamResolveErrorThrow(env, "callback", "AsyncCallback");
            return false;
        }
    }
    return true;
}

static void AddPermissionUsedRecordExecute(napi_env env, void* data)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "AddPermissionUsedRecord execute.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    AddPermParamInfo info;
    info.tokenId = asyncContext->tokenId;
    info.permissionName = asyncContext->permissionName;
    info.successCount = asyncContext->successCount;
    info.failCount = asyncContext->failCount;
    info.type = asyncContext->type;
    asyncContext->retCode = PrivacyKit::AddPermissionUsedRecord(info);
}

static void AddPermissionUsedRecordComplete(napi_env env, napi_status status, void* data)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "AddPermissionUsedRecord complete.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
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
    LOGD(PRI_DOMAIN, PRI_TAG, "AddPermissionUsedRecord begin.");

    auto *asyncContext = new (std::nothrow) RecordManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "New struct fail.");
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
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->asyncWork, napi_qos_default));
    callbackPtr.release();
    return result;
}

static void SetPermissionUsedRecordToggleStatusExecute(napi_env env, void* data)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "SetPermissionUsedRecordToggleStatus execute.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    int32_t userID = 0;
    asyncContext->retCode = PrivacyKit::SetPermissionUsedRecordToggleStatus(userID, asyncContext->status);
}

static void SetPermissionUsedRecordToggleStatusComplete(napi_env env, napi_status status, void* data)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "SetPermissionUsedRecordToggleStatus complete.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    std::unique_ptr<RecordManagerAsyncContext> callbackPtr {asyncContext};

    napi_value result = GetNapiNull(env);
    if (asyncContext->deferred != nullptr) {
        ReturnPromiseResult(env, *asyncContext, result);
    }
}

napi_value SetPermissionUsedRecordToggleStatus(napi_env env, napi_callback_info cbinfo)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "SetPermissionUsedRecordToggleStatus begin.");

    auto *asyncContext = new (std::nothrow) RecordManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "New struct fail.");
        return nullptr;
    }

    std::unique_ptr<RecordManagerAsyncContext> callbackPtr {asyncContext};
    if (!ParsePermissionUsedRecordToggleStatus(env, cbinfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetPermissionUsedRecordToggleStatus", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        SetPermissionUsedRecordToggleStatusExecute,
        SetPermissionUsedRecordToggleStatusComplete,
        reinterpret_cast<void *>(asyncContext),
        &(asyncContext->asyncWork)));

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->asyncWork, napi_qos_default));
    callbackPtr.release();
    return result;
}

static void GetPermissionUsedRecordToggleStatusExecute(napi_env env, void* data)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "GetPermissionUsedRecordToggleStatus execute.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    int32_t userID = 0;
    asyncContext->retCode = PrivacyKit::GetPermissionUsedRecordToggleStatus(userID, asyncContext->status);
}

static void GetPermissionUsedRecordToggleStatusComplete(napi_env env, napi_status status, void* data)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "GetPermissionUsedRecordToggleStatus complete.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    std::unique_ptr<RecordManagerAsyncContext> callbackPtr {asyncContext};

    napi_value result = GetNapiNull(env);
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncContext->status, &result));
    if (asyncContext->deferred != nullptr) {
        ReturnPromiseResult(env, *asyncContext, result);
    }
}

napi_value GetPermissionUsedRecordToggleStatus(napi_env env, napi_callback_info cbinfo)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "GetPermissionUsedRecordToggleStatus begin.");

    auto *asyncContext = new (std::nothrow) RecordManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "New struct fail.");
        return nullptr;
    }

    std::unique_ptr<RecordManagerAsyncContext> callbackPtr {asyncContext};

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetPermissionUsedRecordToggleStatus", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        GetPermissionUsedRecordToggleStatusExecute,
        GetPermissionUsedRecordToggleStatusComplete,
        reinterpret_cast<void *>(asyncContext),
        &(asyncContext->asyncWork)));

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->asyncWork, napi_qos_default));
    callbackPtr.release();
    return result;
}

static void StartUsingPermissionExecute(napi_env env, void* data)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "StartUsingPermission execute.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    asyncContext->retCode = PrivacyKit::StartUsingPermission(asyncContext->tokenId,
        asyncContext->permissionName, asyncContext->pid, asyncContext->type);
}

static void StartUsingPermissionComplete(napi_env env, napi_status status, void* data)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "StartUsingPermission complete.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
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
    LOGD(PRI_DOMAIN, PRI_TAG, "StartUsingPermission begin.");
    auto *asyncContext = new (std::nothrow) RecordManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "New struct fail.");
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
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->asyncWork, napi_qos_default));
    callbackPtr.release();
    return result;
}

static void StopUsingPermissionExecute(napi_env env, void* data)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "StopUsingPermission execute.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    asyncContext->retCode = PrivacyKit::StopUsingPermission(asyncContext->tokenId,
        asyncContext->permissionName, asyncContext->pid);
}

static void StopUsingPermissionComplete(napi_env env, napi_status status, void* data)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "StopUsingPermission complete.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
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
    LOGD(PRI_DOMAIN, PRI_TAG, "StopUsingPermission begin.");

    auto *asyncContext = new (std::nothrow) RecordManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "New struct fail.");
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
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->asyncWork, napi_qos_default));
    callbackPtr.release();
    return result;
}

static void GetPermissionUsedRecordsExecute(napi_env env, void* data)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "GetPermissionUsedRecords execute.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    asyncContext->retCode = PrivacyKit::GetPermissionUsedRecords(asyncContext->request, asyncContext->result);
}

static void GetPermissionUsedRecordsComplete(napi_env env, napi_status status, void* data)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "GetPermissionUsedRecords complete.");
    RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
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
    LOGD(PRI_DOMAIN, PRI_TAG, "GetPermissionUsedRecords begin.");
    auto *asyncContext = new (std::nothrow) RecordManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "New struct fail.");
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
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->asyncWork, napi_qos_default));
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
        ParamResolveErrorThrow(env, "permissionList", "Array<Permissions>");
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
    registerPermActiveChangeContext.threadId_ = std::this_thread::get_id();
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
        ParamResolveErrorThrow(env, "type", "string");
        return false;
    }
    // 1: the second parameter of argv
    std::vector<std::string> permList;
    if (!ParseStringArray(env, argv[1], permList)) {
        ParamResolveErrorThrow(env, "permissionList", "Array<Permissions>");
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
    unregisterPermActiveChangeContext.threadId_ = std::this_thread::get_id();
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
        bool hasPermIntersection = false;
        // Special cases:
        // 1.Have registered full, and then register some
        // 2.Have registered some, then register full
        if (permList.empty() || targetPermList.empty()) {
            hasPermIntersection = true;
        }
        for (const auto& PermItem : targetPermList) {
            if (hasPermIntersection) {
                break;
            }
            auto iter = std::find(permList.begin(), permList.end(), PermItem);
            if (iter != permList.end()) {
                hasPermIntersection = true;
            }
        }
        if (hasPermIntersection && CompareCallbackRef(permActiveChangeContext->env,
            item->callbackRef, permActiveChangeContext->callbackRef, item->threadId_)) {
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
        if ((permList == targetPermList) && CompareCallbackRef(permActiveChangeContext->env, (*item)->callbackRef,
            permActiveChangeContext->callbackRef, (*item)->threadId_)) {
            delete *item;
            *item = nullptr;
            g_permActiveChangeSubscribers.erase(item);
            return;
        } else {
            ++item;
        }
    }
}

static bool FindAndGetSubscriber(UnregisterPermActiveChangeContext* unregisterPermActiveChangeContext,
    std::vector<RegisterPermActiveChangeContext*>& batchPermActiveChangeSubscribers)
{
    std::vector<std::string> targetPermList = unregisterPermActiveChangeContext->permList;
    std::lock_guard<std::mutex> lock(g_lockForPermActiveChangeSubscribers);
    bool callbackEqual;
    napi_ref callbackRef = unregisterPermActiveChangeContext->callbackRef;
    for (const auto& item : g_permActiveChangeSubscribers) {
        std::vector<std::string> permList;
        item->subscriber->GetPermList(permList);
        // targetCallback == nullptr, Unsubscribe from all callbacks under the same permList
        // targetCallback != nullptr, unregister the subscriber with same permList and callback
        if (callbackRef == nullptr) {
            // batch delete currentThread callback
            callbackEqual = IsCurrentThread(item->threadId_);
        } else {
            callbackEqual = CompareCallbackRef(
                unregisterPermActiveChangeContext->env, item->callbackRef, callbackRef, item->threadId_);
        }

        if ((permList == targetPermList) && callbackEqual) {
            batchPermActiveChangeSubscribers.emplace_back(item);
            if (callbackRef != nullptr) {
                return true;
            }
        }
    }
    if (!batchPermActiveChangeSubscribers.empty()) {
        return true;
    }
    return false;
}

napi_value RegisterPermActiveChangeCallback(napi_env env, napi_callback_info cbInfo)
{
    RegisterPermActiveChangeContext* registerPermActiveChangeContext =
        new (std::nothrow) RegisterPermActiveChangeContext();
    if (registerPermActiveChangeContext == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Insufficient memory for registerPermActiveChangeContext!");
        return nullptr;
    }
    std::unique_ptr<RegisterPermActiveChangeContext> callbackPtr {registerPermActiveChangeContext};
    if (!ParseInputToRegister(env, cbInfo, *registerPermActiveChangeContext)) {
        return nullptr;
    }
    if (IsExistRegister(registerPermActiveChangeContext)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Subscribe failed. The current subscriber has been existed");
        std::string errMsg = GetErrorMessage(JsErrorCode::JS_ERROR_PARAM_INVALID);
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_INVALID, errMsg)));
        return nullptr;
    }
    int32_t result = PrivacyKit::RegisterPermActiveStatusCallback(registerPermActiveChangeContext->subscriber);
    if (result != RET_SUCCESS) {
        LOGE(PRI_DOMAIN, PRI_TAG, "RegisterPermActiveStatusCallback failed");
        int32_t jsCode = GetJsErrorCode(result);
        std::string errMsg = GetErrorMessage(jsCode);
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, jsCode, errMsg)));
        return nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(g_lockForPermActiveChangeSubscribers);
        if (g_permActiveChangeSubscribers.size() >= MAX_CALLBACK_SIZE) {
            LOGE(PRI_DOMAIN, PRI_TAG, "Subscribers size has reached max value");
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
        LOGE(PRI_DOMAIN, PRI_TAG, "Insufficient memory for unregisterPermActiveChangeContext!");
        return nullptr;
    }
    std::unique_ptr<UnregisterPermActiveChangeContext> callbackPtr {unregisterPermActiveChangeContext};
    if (!ParseInputToUnregister(env, cbInfo, *unregisterPermActiveChangeContext)) {
        return nullptr;
    }
    std::vector<RegisterPermActiveChangeContext*> batchPermActiveChangeSubscribers;
    if (!FindAndGetSubscriber(unregisterPermActiveChangeContext, batchPermActiveChangeSubscribers)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Unsubscribe failed. The current subscriber does not exist");
        std::string errMsg = GetErrorMessage(JsErrorCode::JS_ERROR_PARAM_INVALID);
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_INVALID, errMsg)));
        return nullptr;
    }
    for (const auto& item : batchPermActiveChangeSubscribers) {
        int32_t result = PrivacyKit::UnRegisterPermActiveStatusCallback(item->subscriber);
        if (result == RET_SUCCESS) {
            DeleteRegisterInVector(item);
        } else {
            LOGE(PRI_DOMAIN, PRI_TAG, "UnregisterPermActiveChangeCompleted failed");
            int32_t jsCode = GetJsErrorCode(result);
            std::string errMsg = GetErrorMessage(jsCode);
            NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, jsCode, errMsg)));
        }
    }
    return nullptr;
}

static bool ParseGetPermissionUsedType(const napi_env env, const napi_callback_info cbInfo,
    PermissionUsedTypeAsyncContext& context)
{
    size_t argc = GET_PERMISSION_USED_TYPE_MAX_PARAMS;
    napi_value argv[GET_PERMISSION_USED_TYPE_MAX_PARAMS] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr), false);

    AccessTokenID tokenId = 0;
    std::string permissionName;

    if (argc == GET_PERMISSION_USED_TYPE_ONE_PARAMS) {
        // one param: only tokenId
        if (!ParseUint32(env, argv[0], tokenId)) {
            ParamResolveErrorThrow(env, "tokenID", "number");
            return false;
        }
    } else if (argc == GET_PERMISSION_USED_TYPE_MAX_PARAMS) {
        // two params: tokenId + permissionName or null + permissionName
        if (!IsUndefinedOrNull(env, argv[0])) {
            // if first param is null, ignore it, otherwise that is tokenId: number
            if (!ParseUint32(env, argv[0], tokenId)) {
                ParamResolveErrorThrow(env, "tokenID", "number");
                return false;
            }
        }

        if (!ParseString(env, argv[1], permissionName)) {
            ParamResolveErrorThrow(env, "permissionName", "Permissions");
            return false;
        }
    }

    // if there is no input param, that means return all tokenId and permissionName
    context.env = env;
    context.tokenId = tokenId;
    context.permissionName = permissionName;
    return true;
}

static void GetPermissionUsedTypeInfosExecute(napi_env env, void* data)
{
    LOGD(PRI_DOMAIN, PRI_TAG, "GetPermissionUsedTypeInfos execute.");

    PermissionUsedTypeAsyncContext* asyncContext = reinterpret_cast<PermissionUsedTypeAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    asyncContext->retCode = PrivacyKit::GetPermissionUsedTypeInfos(asyncContext->tokenId, asyncContext->permissionName,
        asyncContext->results);
}

static void ConvertPermissionUsedTypeInfo(const napi_env& env, napi_value& value, const PermissionUsedTypeInfo& info)
{
    napi_value tokenIdValue;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, info.tokenId, &tokenIdValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "tokenId", tokenIdValue));

    napi_value permissionNameValue;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, info.permissionName.c_str(),
        NAPI_AUTO_LENGTH, &permissionNameValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "permissionName", permissionNameValue));

    napi_value permissionUsedTypeValue;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, info.type, &permissionUsedTypeValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "usedType", permissionUsedTypeValue));
}

static void ProcessPermissionUsedTypeInfoResult(const napi_env& env, napi_value& value,
    const std::vector<PermissionUsedTypeInfo>& results)
{
    LOGI(PRI_DOMAIN, PRI_TAG, "Size is %{public}zu", results.size());
    size_t index = 0;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &value));
    for (const auto& result : results) {
        napi_value permissionUsedTypeValue;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &permissionUsedTypeValue));
        ConvertPermissionUsedTypeInfo(env, permissionUsedTypeValue, result);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, value, index, permissionUsedTypeValue));
        index++;
    }
}

static void GetPermissionUsedTypeInfosComplete(napi_env env, napi_status status, void* data)
{
    LOGI(PRI_DOMAIN, PRI_TAG, "GetPermissionUsedTypeInfos complete.");

    PermissionUsedTypeAsyncContext* asyncContext = reinterpret_cast<PermissionUsedTypeAsyncContext*>(data);
    std::unique_ptr<PermissionUsedTypeAsyncContext> callbackPtr{asyncContext};

    napi_value result = GetNapiNull(env);
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result));
    ProcessPermissionUsedTypeInfoResult(env, result, asyncContext->results);

    if (asyncContext->retCode != RET_SUCCESS) {
        int32_t jsCode = GetJsErrorCode(asyncContext->retCode);
        napi_value businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode));
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncContext->deferred, businessError));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred, result));
    }
}

napi_value GetPermissionUsedTypeInfos(napi_env env, napi_callback_info cbinfo)
{
    LOGI(PRI_DOMAIN, PRI_TAG, "GetPermissionUsedTypeInfos begin.");

    auto *asyncContext = new (std::nothrow) PermissionUsedTypeAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "New struct fail.");
        return nullptr;
    }

    std::unique_ptr<PermissionUsedTypeAsyncContext> callbackPtr {asyncContext};
    if (!ParseGetPermissionUsedType(env, cbinfo, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetPermissionUsedTypeInfos", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        GetPermissionUsedTypeInfosExecute,
        GetPermissionUsedTypeInfosComplete,
        reinterpret_cast<void *>(asyncContext),
        &(asyncContext->asyncWork)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->asyncWork, napi_qos_default));
    callbackPtr.release();
    return result;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS