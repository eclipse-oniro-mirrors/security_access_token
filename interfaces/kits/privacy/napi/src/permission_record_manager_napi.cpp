/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "privacy_kit.h"
#include "accesstoken_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PermissionRecordManagerNapi"};
} // namespace

namespace {
const int ARGS_TWO = 2;
const int ARGS_THREE = 3;
const int ARGS_FIVE = 5;
const int ASYNC_CALL_BACK_VALUES_NUM = 2;
const int PARAM0 = 0;
const int PARAM1 = 1;
const int PARAM2 = 2;
const int PARAM3 = 3;
};

static bool ParseBool(const napi_env env, const napi_value value)
{
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, value, &valuetype);
    if (valuetype != napi_boolean) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "value type dismatch");
        return 0;
    }
    bool result = 0;
    if (napi_get_value_bool(env, value, &result) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get value bool");
        return 0;
    }
    return result;
}

static int32_t ParseInt32(const napi_env env, const napi_value value)
{
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, value, &valuetype);
    if (valuetype != napi_number) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "value type dismatch");
        return 0;
    }
    int32_t result = 0;
    if (napi_get_value_int32(env, value, &result) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get value int32");
        return 0;
    }
    return result;
}

static int64_t ParseInt64(const napi_env env, const napi_value value)
{
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, value, &valuetype);
    if (valuetype != napi_number) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "value type dismatch");
        return 0;
    }
    int64_t result = 0;
    if (napi_get_value_int64(env, value, &result) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get value int64");
        return 0;
    }
    return result;
}

static uint32_t ParseUint32(const napi_env env, const napi_value value)
{
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, value, &valuetype);
    if (valuetype != napi_number) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "value type dismatch");
        return 0;
    }
    uint32_t result = 0;
    if (napi_get_value_uint32(env, value, &result) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get value uint32");
        return 0;
    }
    return result;
}

static std::string ParseString(const napi_env env, const napi_value value)
{
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, value, &valuetype);
    if (valuetype != napi_string) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "value type dismatch");
        return "";
    }
    std::string str;
    size_t size;

    if (napi_get_value_string_utf8(env, value, nullptr, 0, &size) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get string size");
        return "";
    }

    str.reserve(size + 1);
    str.resize(size);
    if (napi_get_value_string_utf8(env, value, str.data(), size + 1, &size) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "cannot get string value");
        return "";
    }
    return str;
}

static std::vector<std::string> ParseStringArray(const napi_env env, const napi_value value)
{
    std::vector<std::string> res;
    uint32_t length = 0;
    napi_valuetype valuetype = napi_undefined;

    napi_get_array_length(env, value, &length);
    napi_value valueArray;
    for (uint32_t i = 0; i < length; i++) {
        napi_get_element(env, value, i, &valueArray);

        napi_typeof(env, valueArray, &valuetype);
        if (valuetype == napi_string) {
            res.emplace_back(ParseString(env, valueArray));
        }
    }
    return res;
}


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
        napi_typeof(env, argv[ARGS_FIVE - 1], &valueType);
        if (valueType == napi_function) {
            napi_create_reference(env, argv[ARGS_FIVE - 1], 1, &asyncContext.callbackRef); // get probably callback
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

    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    asyncContext.env = env;
    asyncContext.tokenId = ParseUint32(env, argv[PARAM0]);
    asyncContext.permissionName = ParseString(env, argv[PARAM1]);
    if (argc == ARGS_THREE) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[ARGS_THREE - 1], &valueType);
        if (valueType == napi_function) {
            napi_create_reference(env, argv[ARGS_THREE - 1], 1, &asyncContext.callbackRef); // get probably callback
        }
    }
}

static void ConvertDetailUsedRecord(napi_env env, napi_value value, const UsedRecordDetail& detailRecord)
{
    napi_value nStatus;
    napi_create_int32(env, detailRecord.status, &nStatus);
    napi_set_named_property(env, value, "status", nStatus);

    napi_value nTimestamp;
    napi_create_int64(env, detailRecord.timestamp, &nTimestamp);
    napi_set_named_property(env, value, "timestamp", nTimestamp);

    napi_value nAccessDuration;
    napi_create_int64(env, detailRecord.accessDuration, &nAccessDuration);
    napi_set_named_property(env, value, "accessDuration", nAccessDuration);
}

static void ConvertPermissionUsedRecord(napi_env env, napi_value value, const PermissionUsedRecord& permissionRecord)
{
    napi_value nPermissionName;
    napi_create_string_utf8(env, permissionRecord.permissionName.c_str(), NAPI_AUTO_LENGTH, &nPermissionName);
    napi_set_named_property(env, value, "permissionName", nPermissionName);

    napi_value nAccessCount;
    napi_create_int32(env, permissionRecord.accessCount, &nAccessCount);
    napi_set_named_property(env, value, "accessCount", nAccessCount);

    napi_value nRejectCount;
    napi_create_int32(env, permissionRecord.rejectCount, &nRejectCount);
    napi_set_named_property(env, value, "rejectCount", nRejectCount);

    napi_value nLastAccessTime;
    napi_create_int64(env, permissionRecord.lastAccessTime, &nLastAccessTime);
    napi_set_named_property(env, value, "lastAccessTime", nLastAccessTime);

    napi_value nLastRejectTime;
    napi_create_int64(env, permissionRecord.lastRejectTime, &nLastRejectTime);
    napi_set_named_property(env, value, "lastRejectTime", nLastRejectTime);

    napi_value nLastAccessDuration;
    napi_create_int64(env, permissionRecord.lastAccessDuration, &nLastAccessDuration);
    napi_set_named_property(env, value, "lastAccessDuration", nLastAccessDuration);

    size_t index = 0;
    napi_value objAccessRecords;
    napi_create_array(env, &objAccessRecords);
    for (const auto& accRecord : permissionRecord.accessRecords) {
        napi_value objAccessRecord;
        napi_create_object(env, &objAccessRecord);
        ConvertDetailUsedRecord(env, objAccessRecord, accRecord);
        napi_set_element(env, objAccessRecords, index, objAccessRecord);
        index++;
    }
    napi_set_named_property(env, value, "accessRecords", objAccessRecords);

    index = 0;
    napi_value objRejectRecords;
    napi_create_array(env, &objRejectRecords);
    for (const auto& rejRecord : permissionRecord.rejectRecords) {
        napi_value objRejectRecord;
        napi_create_object(env, &objRejectRecord);
        ConvertDetailUsedRecord(env, objRejectRecord, rejRecord);
        napi_set_element(env, objRejectRecords, index, objRejectRecord);
        index++;
    }
    napi_set_named_property(env, value, "rejectRecords", objRejectRecords);
}

static void ConvertBundleUsedRecord(napi_env env, napi_value value, const BundleUsedRecord& bundleRecord)
{
    napi_value nTokenId;
    napi_create_int32(env, bundleRecord.tokenId, &nTokenId);
    napi_set_named_property(env, value, "tokenId", nTokenId);

    napi_value nIsRemote;
    napi_create_int32(env, bundleRecord.isRemote, &nIsRemote);
    napi_set_named_property(env, value, "isRemote", nIsRemote);

    napi_value nDeviceId;
    napi_create_string_utf8(env, bundleRecord.deviceId.c_str(), NAPI_AUTO_LENGTH, &nDeviceId);
    napi_set_named_property(env, value, "deviceId", nDeviceId);

    napi_value nBundleName;
    napi_create_string_utf8(env, bundleRecord.bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName);
    napi_set_named_property(env, value, "bundleName", nBundleName);
    size_t index = 0;
    napi_value objPermissionRecords;
    napi_create_array(env, &objPermissionRecords);
    for (const auto& permRecord : bundleRecord.permissionRecords) {
        napi_value objPermissionRecord;
        napi_create_object(env, &objPermissionRecord);
        ConvertPermissionUsedRecord(env, objPermissionRecord, permRecord);
        napi_set_element(env, objPermissionRecords, index, objPermissionRecord);
        index++;
    }
    napi_set_named_property(env, value, "permissionRecords", objPermissionRecords);
}

static void ProcessRecordResult(napi_env env, napi_value value, const PermissionUsedResult& result)
{
    napi_value nBeginTimestamp;
    napi_create_int64(env, result.beginTimeMillis, &nBeginTimestamp);
    napi_set_named_property(env, value, "beginTime", nBeginTimestamp);

    napi_value nEndTimestamp;
    napi_create_int64(env, result.endTimeMillis, &nEndTimestamp);
    napi_set_named_property(env, value, "endTime", nEndTimestamp);

    size_t index = 0;
    napi_value objBundleRecords;
    napi_create_array(env, &objBundleRecords);
    for (const auto& bundleRecord : result.bundleRecords) {
        napi_value objBundleRecord;
        napi_create_object(env, &objBundleRecord);
        ConvertBundleUsedRecord(env, objBundleRecord, bundleRecord);
        napi_set_element(env, objBundleRecords, index, objBundleRecord);
        index++;
    }
    napi_set_named_property(env, value, "bundleRecords", objBundleRecords);
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
    napi_typeof(env, argv[0], &valuetype);
    if (valuetype != napi_object) {
        return;
    }
    napi_value property = nullptr;
    if (napi_ok != napi_get_named_property(env, argv[0], "tokenId", &property)) {
        return;
    }
    asyncContext.request.tokenId = ParseUint32(env, property);
    if (napi_ok != napi_get_named_property(env, argv[0], "isRemote", &property)) {
        return;
    }
    asyncContext.request.isRemote = ParseBool(env, property);
    if (napi_ok != napi_get_named_property(env, argv[0], "deviceId", &property)) {
        return;
    }
    asyncContext.request.deviceId = ParseString(env, property);
    if (napi_ok != napi_get_named_property(env, argv[0], "bundleName", &property)) {
        return;
    }
    asyncContext.request.bundleName = ParseString(env, property);
    if (napi_ok != napi_get_named_property(env, argv[0], "beginTime", &property)) {
        return;
    }
    asyncContext.request.beginTimeMillis = ParseInt64(env, property);
    if (napi_ok != napi_get_named_property(env, argv[0], "endTime", &property)) {
        return;
    }
    asyncContext.request.endTimeMillis = ParseInt64(env, property);
    if (napi_ok != napi_get_named_property(env, argv[0], "permissionNames", &property)) {
        return;
    }
    asyncContext.request.permissionList = ParseStringArray(env, property);
    if (napi_ok != napi_get_named_property(env, argv[0], "flag", &property)) {
        return;
    }
    asyncContext.request.flag = (PermissionUsageFlagEnum)ParseInt32(env, property);

    asyncContext.env = env;
    if (argc == ARGS_TWO) {
        napi_typeof(env, argv[ARGS_TWO - 1], &valuetype);
        if (valuetype == napi_function) {
            napi_create_reference(env, argv[ARGS_TWO - 1], 1, &asyncContext.callbackRef);
        }
    }
}

napi_value AddPermissionUsedRecord(napi_env env, napi_callback_info cbinfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "AddPermissionUsedRecord begin.");

    auto *asyncContext = new (std::nothrow) RecordManagerAsyncContext();
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }
    ParseAddPermissionRecord(env, cbinfo, *asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        if (napi_create_promise(env, &(asyncContext->deferred), &result) !=napi_ok) {
            return nullptr;
        }
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "AddPermissionUsedRecord", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void* data) {
            RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
            asyncContext->retCode = PrivacyKit::AddPermissionUsedRecord(asyncContext->tokenId,
                asyncContext->permissionName, asyncContext->successCount, asyncContext->failCount);
        },
        [](napi_env env, napi_status status, void *data) {
            RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
            napi_value results[ASYNC_CALL_BACK_VALUES_NUM] = {nullptr};
            napi_create_int32(env, asyncContext->retCode, &results[ASYNC_CALL_BACK_VALUES_NUM - 1]);
            if (asyncContext->deferred) {
                napi_resolve_deferred(env, asyncContext->deferred, results[ASYNC_CALL_BACK_VALUES_NUM - 1]);
            } else {
                napi_value callback = nullptr;
                napi_value callResult = nullptr;
                napi_value undefine = nullptr;
                napi_get_undefined(env, &undefine);
                napi_create_int32(env, 0, &callResult);
                napi_get_reference_value(env, asyncContext->callbackRef, &callback);
                napi_call_function(env, undefine, callback, ASYNC_CALL_BACK_VALUES_NUM, results, &callResult);
                napi_delete_reference(env, asyncContext->callbackRef);
            }
            napi_delete_async_work(env, asyncContext->asyncWork);
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext),
        &(asyncContext->asyncWork));
    napi_queue_async_work(env, asyncContext->asyncWork);
    return result;
}

napi_value StartUsingPermission(napi_env env, napi_callback_info cbinfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "StartUsingPermission begin.");

    auto *asyncContext = new (std::nothrow) RecordManagerAsyncContext();
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }
    ParseStartAndStopUsingPermission(env, cbinfo, *asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        if (napi_create_promise(env, &(asyncContext->deferred), &result) !=napi_ok) {
            return nullptr;
        }
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "StartUsingPermission", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void* data) {
            RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
            asyncContext->retCode = PrivacyKit::StartUsingPermission(asyncContext->tokenId,
                asyncContext->permissionName);
        },
        [](napi_env env, napi_status status, void *data) {
            RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
            napi_value results[ASYNC_CALL_BACK_VALUES_NUM] = {nullptr};
            napi_create_int32(env, asyncContext->retCode, &results[ASYNC_CALL_BACK_VALUES_NUM - 1]);
            if (asyncContext->deferred) {
                napi_resolve_deferred(env, asyncContext->deferred, results[ASYNC_CALL_BACK_VALUES_NUM - 1]);
            } else {
                napi_value callback = nullptr;
                napi_value callResult = nullptr;
                napi_value undefine = nullptr;
                napi_get_undefined(env, &undefine);
                napi_create_int32(env, 0, &callResult);
                napi_get_reference_value(env, asyncContext->callbackRef, &callback);
                napi_call_function(env, undefine, callback, ASYNC_CALL_BACK_VALUES_NUM, results, &callResult);
                napi_delete_reference(env, asyncContext->callbackRef);
            }
            napi_delete_async_work(env, asyncContext->asyncWork);
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext),
        &(asyncContext->asyncWork));
    napi_queue_async_work(env, asyncContext->asyncWork);
    return result;
}

napi_value StopUsingPermission(napi_env env, napi_callback_info cbinfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "StopUsingPermission begin.");

    auto *asyncContext = new (std::nothrow) RecordManagerAsyncContext();
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }
    ParseStartAndStopUsingPermission(env, cbinfo, *asyncContext);

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        if (napi_create_promise(env, &(asyncContext->deferred), &result) !=napi_ok) {
            return nullptr;
        }
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "StopUsingPermission", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void* data) {
            RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
            asyncContext->retCode = PrivacyKit::StopUsingPermission(asyncContext->tokenId,
                asyncContext->permissionName);
        },
        [](napi_env env, napi_status status, void *data) {
            RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
            napi_value results[ASYNC_CALL_BACK_VALUES_NUM] = {nullptr};
            napi_create_int32(env, asyncContext->retCode, &results[ASYNC_CALL_BACK_VALUES_NUM - 1]);
            if (asyncContext->deferred) {
                napi_resolve_deferred(env, asyncContext->deferred, results[ASYNC_CALL_BACK_VALUES_NUM - 1]);
            } else {
                napi_value callback = nullptr;
                napi_value callResult = nullptr;
                napi_value undefine = nullptr;
                napi_get_undefined(env, &undefine);
                napi_create_int32(env, 0, &callResult);
                napi_get_reference_value(env, asyncContext->callbackRef, &callback);
                napi_call_function(env, undefine, callback, ASYNC_CALL_BACK_VALUES_NUM, results, &callResult);
                napi_delete_reference(env, asyncContext->callbackRef);
            }
            napi_delete_async_work(env, asyncContext->asyncWork);
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext),
        &(asyncContext->asyncWork));
    napi_queue_async_work(env, asyncContext->asyncWork);
    return result;
}

napi_value GetPermissionUsedRecords(napi_env env, napi_callback_info cbinfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetPermissionUsedRecords begin.");
    auto *asyncContext = new (std::nothrow) RecordManagerAsyncContext();
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }
    ParseGetPermissionUsedRecords(env, cbinfo, *asyncContext);

        napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        if (napi_create_promise(env, &(asyncContext->deferred), &result) !=napi_ok) {
            return nullptr;
        }
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "GetPermissionUsedRecords", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(env,
        nullptr,
        resource,
        [](napi_env env, void* data) {
            RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
            asyncContext->retCode = PrivacyKit::GetPermissionUsedRecords(asyncContext->request, asyncContext->result);
        },
        [](napi_env env, napi_status status, void *data) {
            RecordManagerAsyncContext* asyncContext = reinterpret_cast<RecordManagerAsyncContext*>(data);
            napi_value results[ASYNC_CALL_BACK_VALUES_NUM] = {nullptr};
            napi_create_int32(env, asyncContext->retCode, &results[0]);
            napi_create_array(env, &results[ASYNC_CALL_BACK_VALUES_NUM - 1]);
            ProcessRecordResult(env, results[ASYNC_CALL_BACK_VALUES_NUM - 1], asyncContext->result);
            if (asyncContext->deferred) {
                napi_resolve_deferred(env, asyncContext->deferred, results[ASYNC_CALL_BACK_VALUES_NUM - 1]);
            } else {
                napi_value callback = nullptr;
                napi_value callResult = nullptr;
                napi_value undefine = nullptr;
                napi_get_undefined(env, &undefine);
                napi_create_int32(env, 0, &callResult);
                napi_get_reference_value(env, asyncContext->callbackRef, &callback);
                napi_call_function(env, undefine, callback, ASYNC_CALL_BACK_VALUES_NUM, results, &callResult);
                napi_delete_reference(env, asyncContext->callbackRef);
            }
            napi_delete_async_work(env, asyncContext->asyncWork);
            delete asyncContext;
        },
        reinterpret_cast<void *>(asyncContext),
        &(asyncContext->asyncWork));
    napi_queue_async_work(env, asyncContext->asyncWork);
    return result;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS