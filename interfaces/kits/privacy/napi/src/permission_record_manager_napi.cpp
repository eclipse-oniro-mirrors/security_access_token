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
static const size_t MAX_CALLBACK_SIZE = 200;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PermissionRecordManagerNapi"};
} // namespace
static void ParseAddPermissionRecord(
    const napi_env env, const napi_callback_info info, RecordManagerAsyncContext& asyncContext)
{
    size_t argc = ARGS_FIVE;
    napi_value argv[ARGS_FIVE] = { 0 };
    napi_value thisVar = nullptr;
    void* data = nullptr;

    NAPI_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    asyncContext.env = env;
    asyncContext.tokenId = ParseUint32(env, argv[PARAM0]);
    asyncContext.permissionName = ParseString(env, argv[PARAM1]);
    asyncContext.successCount = ParseInt32(env, argv[PARAM2]);
    asyncContext.failCount = ParseInt32(env, argv[PARAM3]);
    if (argc == ARGS_FIVE) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL_RETURN_VOID(env, napi_typeof(env, argv[ARGS_FIVE - 1], &valueType));
        if (valueType == napi_function) {
            NAPI_CALL_RETURN_VOID(env,
                napi_create_reference(env, argv[ARGS_FIVE - 1], 1, &asyncContext.callbackRef));
        }
    }
}

static void ParseStartAndStopUsingPermission(
    const napi_env env, const napi_callback_info info, RecordManagerAsyncContext& asyncContext)
{
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = { 0 };
    napi_value thisVar = nullptr;
    void* data = nullptr;

    NAPI_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));

    asyncContext.env = env;
    asyncContext.tokenId = ParseUint32(env, argv[PARAM0]);
    asyncContext.permissionName = ParseString(env, argv[PARAM1]);
    if (argc == ARGS_THREE) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL_RETURN_VOID(env, napi_typeof(env, argv[ARGS_THREE - 1], &valueType))  ;
        if (valueType == napi_function) {
            NAPI_CALL_RETURN_VOID(env, napi_create_reference(env,
                argv[ARGS_THREE - 1], 1, &asyncContext.callbackRef));
        }
    }
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

static void ParseGetPermissionUsedRecords(
    const napi_env env, const napi_callback_info info, RecordManagerAsyncContext& asyncContext)
{
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = { 0 };
    napi_value thisVar = nullptr;
    void* data = nullptr;
    napi_valuetype valuetype = napi_undefined;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);
    napi_typeof(env, argv[PARAM0], &valuetype);
    if (valuetype != napi_object) {
        return;
    }
    napi_value property = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_named_property(env, argv[PARAM0], "tokenId", &property));
    asyncContext.request.tokenId = ParseUint32(env, property);

    property = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_named_property(env, argv[PARAM0], "isRemote", &property)) ;
    asyncContext.request.isRemote = ParseBool(env, property);

    property = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_named_property(env, argv[PARAM0], "deviceId", &property));
    asyncContext.request.deviceId = ParseString(env, property);

    property = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_named_property(env, argv[PARAM0], "bundleName", &property));
    asyncContext.request.bundleName = ParseString(env, property);

    property = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_named_property(env, argv[PARAM0], "beginTime", &property));
    asyncContext.request.beginTimeMillis = ParseInt64(env, property);

    property = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_named_property(env, argv[PARAM0], "endTime", &property));
    asyncContext.request.endTimeMillis = ParseInt64(env, property);

    property = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_named_property(env, argv[PARAM0], "permissionNames", &property));
    if (!ParseStringArray(env, property, asyncContext.request.permissionList)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ParseStringArray failed");
        return;
    }

    property = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_named_property(env, argv[PARAM0], "flag", &property));
    asyncContext.request.flag = (PermissionUsageFlagEnum)ParseInt32(env, property);

    asyncContext.env = env;
    if (argc == ARGS_TWO) {
        NAPI_CALL_RETURN_VOID(env, napi_typeof(env, argv[ARGS_TWO - 1], &valuetype));
        if (valuetype == napi_function) {
            NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, argv[ARGS_TWO - 1], 1, &asyncContext.callbackRef));
        }
    }
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

    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
        asyncContext->retCode, &results[PARAM1]));
    if (asyncContext->deferred) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred,
            results[PARAM1]));
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
    ParseAddPermissionRecord(env, cbinfo, *asyncContext);

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

    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->retCode,
        &results[PARAM1]));
    if (asyncContext->deferred) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred,
            results[PARAM1]));
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
    ParseStartAndStopUsingPermission(env, cbinfo, *asyncContext);

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

    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->retCode,
        &results[PARAM1]));
    if (asyncContext->deferred) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred,
            results[PARAM1]));
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
    ParseStartAndStopUsingPermission(env, cbinfo, *asyncContext);

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

    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->retCode, &results[0]));
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &results[PARAM1]));
    ProcessRecordResult(env, results[PARAM1], asyncContext->result);
    if (asyncContext->deferred) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred,
            results[PARAM1]));
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
    ParseGetPermissionUsedRecords(env, cbinfo, *asyncContext);

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
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {nullptr};
    napi_value thisVar = nullptr;
    napi_ref callback = nullptr;
    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_get_cb_info failed");
        return false;
    }
    std::string type = ParseString(env, argv[PARAM0]);
    std::vector<std::string> permList;
    if (!ParseStringArray(env, argv[PARAM1], permList)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ParseStringArray failed");
        return false;
    }
    std::sort(permList.begin(), permList.end());
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[PARAM2], &valueType) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get napi type failed");
        return false;
    } // get PRARM[2] callback type
    if (valueType != napi_function) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "value type dismatch");
        return false;
    }
    if (napi_create_reference(env, argv[PARAM2], 1, &callback) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_create_reference failed");
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
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {nullptr};
    napi_value thisVar = nullptr;
    napi_ref callback = nullptr;
    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_get_cb_info failed");
        return false;
    }
    std::string type = ParseString(env, argv[PARAM0]);
    std::vector<std::string> permList;
    if (!ParseStringArray(env, argv[PARAM1], permList)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ParseStringArray failed");
        return false;
    }
    std::sort(permList.begin(), permList.end());
    napi_valuetype valueType = napi_undefined;
    if (argc >= ARGS_THREE) {
        if (napi_typeof(env, argv[PARAM2], &valueType) != napi_ok) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "get napi type failed");
            return false;
        } // get PRARM[2] callback type
        if (valueType != napi_function) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "value type dismatch");
            return false;
        }
        if (napi_create_reference(env, argv[PARAM2], 1, &callback) != napi_ok) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "napi_create_reference failed");
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