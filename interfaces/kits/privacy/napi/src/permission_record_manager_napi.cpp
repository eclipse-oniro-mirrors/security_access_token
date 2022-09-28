/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "napi/native_api.h"
#include "napi/native_node_api.h"

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
static bool ParseAddPermissionRecord(
    const napi_env env, const napi_callback_info info, RecordManagerAsyncContext& asyncContext)
{
    size_t argc = ADD_PERMISSION_RECORD_MAX_PARAMS;
    napi_value argv[ADD_PERMISSION_RECORD_MAX_PARAMS] = { 0 };
    napi_value thisVar = nullptr;
    void* data = nullptr;

    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
    asyncContext.env = env;

    // 0: the first parameter of argv
    if (!ParseUint32(env, argv[0], asyncContext.tokenId)) {
        return false;
    }

    // 1: the second parameter of argv
    if (!ParseString(env, argv[1], asyncContext.permissionName)) {
        return false;
    }

    // 2: the third parameter of argv
    if (!ParseInt32(env, argv[2], asyncContext.successCount)) {
        return false;
    }

    // 3: the fourth parameter of argv
    if (!ParseInt32(env, argv[3], asyncContext.failCount)) {
        return false;
    }
    if (argc == ADD_PERMISSION_RECORD_MAX_PARAMS) {
        // 4: : the fifth parameter of argv
        if (!ParseCallback(env, argv[4], asyncContext.callbackRef)) {
            return false;
        }
    }
    return true;
}

static bool ParseStartAndStopUsingPermission(
    const napi_env env, const napi_callback_info info, RecordManagerAsyncContext& asyncContext)
{
    size_t argc = START_STOP_MAX_PARAMS;
    napi_value argv[START_STOP_MAX_PARAMS] = { 0 };
    napi_value thisVar = nullptr;
    void* data = nullptr;

    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);

    asyncContext.env = env;
    // 0: the first parameter of argv
    if (!ParseUint32(env, argv[0], asyncContext.tokenId)) {
        return false;
    }

    // 1: the second parameter of argv
    if (!ParseString(env, argv[1], asyncContext.permissionName)) {
        return false;
    }
    if (argc == START_STOP_MAX_PARAMS) {
        // 2: the third parameter of argv
        if (!ParseCallback(env, argv[2], asyncContext.callbackRef)) {
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
    napi_valuetype valueType;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_object) {
        return false;
    }
    napi_value property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "tokenId", &property), false);
    if (!ParseUint32(env, property, request.tokenId)) {
        return false;
    }

    property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "isRemote", &property), false) ;
    if (!ParseBool(env, property, request.isRemote)) {
        return false;
    }

    property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "deviceId", &property), false);
    if (!ParseString(env, property, request.deviceId)) {
        return false;
    }

    property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "bundleName", &property), false);
    if (!ParseString(env, property, request.bundleName)) {
        return false;
    }

    property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "beginTime", &property), false);
    if (!ParseInt64(env, property, request.beginTimeMillis)) {
        return false;
    }

    property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "endTime", &property), false);
    if (!ParseInt64(env, property, request.endTimeMillis)) {
        return false;
    }

    property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "permissionNames", &property), false);
    if (!ParseStringArray(env, property, request.permissionList)) {
        return false;
    }

    property = nullptr;
    NAPI_CALL_BASE(env, napi_get_named_property(env, value, "flag", &property), false);
    int32_t flag;
    if (!ParseInt32(env, property, flag)) {
        return false;
    }
    request.flag = static_cast<PermissionUsageFlagEnum>(flag);

    return true;
}

static bool ParseGetPermissionUsedRecords(
    const napi_env env, const napi_callback_info info, RecordManagerAsyncContext& asyncContext)
{
    size_t argc = GET_PERMISSION_RECORD_MAX_PARAMS;
    napi_value argv[GET_PERMISSION_RECORD_MAX_PARAMS] = { 0 };
    napi_value thisVar = nullptr;
    void* data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);

    asyncContext.env = env;

    // 0: the first parameter of argv
    if (!ParseRequest(env, argv[0], asyncContext.request)) {
        return false;
    }

    if (argc == GET_PERMISSION_RECORD_MAX_PARAMS) {
        // 1: the second parameter of argv
        if (!ParseCallback(env, argv[1], asyncContext.callbackRef)) {
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
    napi_value results[ASYNC_CALL_BACK_VALUES_NUM] = {nullptr};

    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->retCode, &results[ASYNC_CALL_BACK_PARAM_DATA]));
    if (asyncContext->deferred != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred,
            results[ASYNC_CALL_BACK_PARAM_DATA]));
    } else {
        napi_value callback = nullptr;
        napi_value callResult = nullptr;
        napi_value undefine = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefine));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 0, &callResult));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefine, callback, ASYNC_CALL_BACK_VALUES_NUM,
            results, &callResult));
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
        napi_throw(enc, );
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

    std::unique_ptr<RecordManagerAsyncContext> callbackPtr {asyncContext};
    napi_value results[ASYNC_CALL_BACK_VALUES_NUM] = {nullptr};

    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->retCode, &results[ASYNC_CALL_BACK_PARAM_DATA]));
    if (asyncContext->deferred != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred,
            results[ASYNC_CALL_BACK_PARAM_DATA]));
    } else {
        napi_value callback = nullptr;
        napi_value callResult = nullptr;
        napi_value undefine = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefine));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 0, &callResult));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefine, callback, ASYNC_CALL_BACK_VALUES_NUM,
            results, &callResult));
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

    std::unique_ptr<RecordManagerAsyncContext> callbackPtr {asyncContext};
    napi_value results[ASYNC_CALL_BACK_VALUES_NUM] = {nullptr};

    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->retCode, &results[ASYNC_CALL_BACK_PARAM_DATA]));
    if (asyncContext->deferred != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred,
            results[ASYNC_CALL_BACK_PARAM_DATA]));
    } else {
        napi_value callback = nullptr;
        napi_value callResult = nullptr;
        napi_value undefine = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefine));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 0, &callResult));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefine, callback, ASYNC_CALL_BACK_VALUES_NUM,
            results, &callResult));
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

    std::unique_ptr<RecordManagerAsyncContext> callbackPtr {asyncContext};
    napi_value results[ASYNC_CALL_BACK_VALUES_NUM] = {nullptr};

    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &results[ASYNC_CALL_BACK_PARAM_DATA]));
    ProcessRecordResult(env, results[ASYNC_CALL_BACK_PARAM_DATA], asyncContext->result);
    if (asyncContext->deferred != nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred,
            results[ASYNC_CALL_BACK_PARAM_DATA]));
    } else {
        napi_value callback = nullptr;
        napi_value callResult = nullptr;
        napi_value undefine = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefine));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 0, &callResult));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefine, callback, ASYNC_CALL_BACK_VALUES_NUM,
            results, &callResult));
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
    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_get_cb_info failed");
        return false;
    }
    std::string type;
    // 0: the first parameter of argv
    if (!ParseString(env, argv[0], type)) {
        return false;
    }
    std::vector<std::string> permList;
    // 1: the second parameter of argv
    if (!ParseStringArray(env, argv[1], permList)) {
        return false;
    }
    std::sort(permList.begin(), permList.end());
    // 2: the third parameter of argv
    if (!ParseCallback(env, argv[2], callback)) {
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
    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_get_cb_info failed");
        return false;
    }
    std::string type;
    // 0: the first parameter of argv
    if (!ParseString(env, argv[0], type)) {
        return false;
    }
    // 1: the second parameter of argv
    std::vector<std::string> permList;
    if (!ParseStringArray(env, argv[1], permList)) {
        return false;
    }
    std::sort(permList.begin(), permList.end());
    if (argc == ON_OFF_MAX_PARAMS) {
        // 2: the first parameter of argv
        if (!ParseCallback(env, argv[2], callback)) {
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
        return nullptr;
    }
    if (PrivacyKit::RegisterPermActiveStatusCallback(registerPermActiveChangeContext->subscriber) != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "RegisterPermActiveStatusCallback failed");
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
        return nullptr;
    }
    if (PrivacyKit::UnRegisterPermActiveStatusCallback(unregisterPermActiveChangeContext->subscriber) == RET_SUCCESS) {
        DeleteRegisterInVector(unregisterPermActiveChangeContext);
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UnregisterPermActiveChangeCompleted failed");
    }
    return nullptr;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS