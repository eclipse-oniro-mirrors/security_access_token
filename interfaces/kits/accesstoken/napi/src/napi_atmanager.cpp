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
#include "napi_atmanager.h"

#include <cstdio>
#include <cstring>
#include <map>
#include <pthread.h>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::mutex g_lockForPermStateChangeRegisters;
std::map<AccessTokenKit*, std::vector<RegisterPermStateChangeInfo*>> g_permStateChangeRegisters;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenAbilityAccessCtrl"
};

static bool ConvertPermStateChangeInfo(napi_env env, napi_value value, const PermStateChangeInfo& result)
{
    napi_value element;
    NAPI_CALL_BASE(env, napi_create_int32(env, result.PermStateChangeType, &element), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, value, "change", element), false);
    element = nullptr;
    NAPI_CALL_BASE(env, napi_create_int32(env, result.tokenID, &element), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, value, "tokenID", element), false);
    element = nullptr;
    NAPI_CALL_BASE(env, napi_create_string_utf8(env, result.permissionName.c_str(),
        NAPI_AUTO_LENGTH, &element), false);
    NAPI_CALL_BASE(env, napi_set_named_property(env, value, "permissionName", element), false);
    return true;
};

static bool CompareScopeInfo(const PermStateChangeScope& scopeInfo,
    const std::vector<AccessTokenID>& tokenIDs, const std::vector<std::string>& permList)
{
    std::vector<AccessTokenID> targetTokenIDs = scopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = scopeInfo.permList;
    if (targetTokenIDs.size() != tokenIDs.size() || targetPermList.size() != permList.size()) {
        return false;
    }
    std::sort(targetTokenIDs.begin(), targetTokenIDs.end());
    std::sort(targetPermList.begin(), targetPermList.end());
    if (std::equal(targetTokenIDs.begin(), targetTokenIDs.end(), tokenIDs.begin()) &&
        std::equal(targetPermList.begin(), targetPermList.end(), permList.begin())) {
        return true;
    }
    return false;
};

static void UvQueueWorkPermStateChanged(uv_work_t* work, int status)
{
    if (work == nullptr || work->data == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "work == nullptr || work->data == nullptr");
        return;
    }
    std::unique_ptr<uv_work_t> uvWorkPtr {work};
    RegisterPermStateChangeWorker* registerPermStateChangeData =
        reinterpret_cast<RegisterPermStateChangeWorker*>(work->data);
    std::unique_ptr<RegisterPermStateChangeWorker> workPtr {registerPermStateChangeData};
    napi_value result[ARGS_ONE] = {nullptr};
    NAPI_CALL_RETURN_VOID(registerPermStateChangeData->env,
        napi_create_array(registerPermStateChangeData->env, &result[PARAM0]));
    if (!ConvertPermStateChangeInfo(registerPermStateChangeData->env,
        result[PARAM0], registerPermStateChangeData->result)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertPermStateChangeInfo failed");
        return;
    }
    napi_value undefined = nullptr;
    napi_value callback = nullptr;
    napi_value resultout = nullptr;
    NAPI_CALL_RETURN_VOID(registerPermStateChangeData->env,
        napi_get_undefined(registerPermStateChangeData->env, &undefined));
    NAPI_CALL_RETURN_VOID(registerPermStateChangeData->env,
        napi_get_reference_value(registerPermStateChangeData->env, registerPermStateChangeData->ref, &callback));
    NAPI_CALL_RETURN_VOID(registerPermStateChangeData->env,
        napi_call_function(registerPermStateChangeData->env,
        undefined, callback, ARGS_ONE, &result[PARAM0], &resultout));
    ACCESSTOKEN_LOG_DEBUG(LABEL, "UvQueueWorkPermStateChanged end");
};
} // namespace

RegisterPermStateChangeScopePtr::RegisterPermStateChangeScopePtr(const PermStateChangeScope& subscribeInfo)
    : PermStateChangeCallbackCustomize(subscribeInfo)
{}

RegisterPermStateChangeScopePtr::~RegisterPermStateChangeScopePtr()
{}

void RegisterPermStateChangeScopePtr::PermStateChangeCallback(PermStateChangeInfo& result)
{
    uv_loop_s* loop = nullptr;
    NAPI_CALL_RETURN_VOID(env_, napi_get_uv_event_loop(env_, &loop));
    if (loop == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "loop instance is nullptr");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "insufficient memory for work!");
        return;
    }
    std::unique_ptr<uv_work_t> uvWorkPtr {work};
    RegisterPermStateChangeWorker* registerPermStateChangeWorker =
        new (std::nothrow) RegisterPermStateChangeWorker();
    if (registerPermStateChangeWorker == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "insufficient memory for RegisterPermStateChangeWorker!");
        return;
    }
    std::unique_ptr<RegisterPermStateChangeWorker> workPtr {registerPermStateChangeWorker};
    registerPermStateChangeWorker->env = env_;
    registerPermStateChangeWorker->ref = ref_;
    registerPermStateChangeWorker->result = result;
    ACCESSTOKEN_LOG_DEBUG(LABEL,
        "result PermStateChangeType = %{public}d, tokenID = %{public}d, permissionName = %{public}s",
        result.PermStateChangeType, result.tokenID, result.permissionName.c_str());
    registerPermStateChangeWorker->subscriber = this;
    work->data = reinterpret_cast<void *>(registerPermStateChangeWorker);
    NAPI_CALL_RETURN_VOID(env_,
        uv_queue_work(loop, work, [](uv_work_t* work) {}, UvQueueWorkPermStateChanged));
    uvWorkPtr.release();
    workPtr.release();
}

void RegisterPermStateChangeScopePtr::SetEnv(const napi_env& env)
{
    env_ = env;
}

void RegisterPermStateChangeScopePtr::SetCallbackRef(const napi_ref& ref)
{
    ref_ = ref;
}

PermStateChangeContext::~PermStateChangeContext()
{
    if (callbackRef != nullptr) {
        napi_delete_reference(env, callbackRef);
        callbackRef = nullptr;
    }
}

UnregisterPermStateChangeInfo::~UnregisterPermStateChangeInfo()
{
    if (work != nullptr) {
        napi_delete_async_work(env, work);
        work = nullptr;
    }
}

void NapiAtManager::SetNamedProperty(napi_env env, napi_value dstObj, const int32_t objValue, const char *propName)
{
    napi_value prop = nullptr;
    napi_create_int32(env, objValue, &prop);
    napi_set_named_property(env, dstObj, propName, prop);
}

napi_value NapiAtManager::Init(napi_env env, napi_value exports)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "enter init.");

    napi_property_descriptor descriptor[] = { DECLARE_NAPI_FUNCTION("createAtManager", CreateAtManager) };

    NAPI_CALL(env, napi_define_properties(env,
        exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor));

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("verifyAccessToken", VerifyAccessToken),
        DECLARE_NAPI_FUNCTION("verifyAccessTokenSync", VerifyAccessTokenSync),
        DECLARE_NAPI_FUNCTION("grantUserGrantedPermission", GrantUserGrantedPermission),
        DECLARE_NAPI_FUNCTION("revokeUserGrantedPermission", RevokeUserGrantedPermission),
        DECLARE_NAPI_FUNCTION("getPermissionFlags", GetPermissionFlags),
        DECLARE_NAPI_FUNCTION("on", RegisterPermStateChangeCallback),
        DECLARE_NAPI_FUNCTION("off", UnregisterPermStateChangeCallback),
    };

    napi_value cons = nullptr;
    NAPI_CALL(env, napi_define_class(env, ATMANAGER_CLASS_NAME.c_str(), ATMANAGER_CLASS_NAME.size(),
        JsConstructor, nullptr, sizeof(properties) / sizeof(napi_property_descriptor), properties, &cons));

    NAPI_CALL(env, napi_create_reference(env, cons, 1, &atManagerRef_));
    NAPI_CALL(env, napi_set_named_property(env, exports, ATMANAGER_CLASS_NAME.c_str(), cons));

    napi_value GrantStatus = nullptr;
    napi_create_object(env, &GrantStatus);

    SetNamedProperty(env, GrantStatus, PERMISSION_DENIED, "PERMISSION_DENIED");
    SetNamedProperty(env, GrantStatus, PERMISSION_GRANTED, "PERMISSION_GRANTED");

    napi_value permStateChangeType = nullptr;
    napi_create_object(env, &permStateChangeType);

    SetNamedProperty(env, permStateChangeType, PERMISSION_REVOKED_OPER, "PERMISSION_REVOKED_OPER");
    SetNamedProperty(env, permStateChangeType, PERMISSION_GRANTED_OPER, "PERMISSION_GRANTED_OPER");

    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_PROPERTY("GrantStatus", GrantStatus),
        DECLARE_NAPI_PROPERTY("PermissionStateChangeType", permStateChangeType),
    };
    napi_define_properties(env, exports, sizeof(exportFuncs) / sizeof(*exportFuncs), exportFuncs);

    return exports;
}

napi_value NapiAtManager::JsConstructor(napi_env env, napi_callback_info cbinfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "enter JsConstructor");

    napi_value thisVar = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, nullptr));
    AccessTokenKit* objectInfo = new (std::nothrow) AccessTokenKit();
    if (objectInfo == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "objectInfo == nullptr");
        return nullptr;
    }
    if (napi_wrap(env, thisVar, objectInfo, [](napi_env env, void* data, void* hint) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "delete accesstoken kit");
        if (data != nullptr) {
            AccessTokenKit* objectInfo = (AccessTokenKit*) data;
            delete objectInfo;
        }
    }, nullptr, nullptr) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_wrap failed");
        return nullptr;
    }

    return thisVar;
}

napi_value NapiAtManager::CreateAtManager(napi_env env, napi_callback_info cbInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "enter CreateAtManager");

    napi_value instance = nullptr;
    napi_value cons = nullptr;

    if (napi_get_reference_value(env, atManagerRef_, &cons) != napi_ok) {
        return nullptr;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "Get a reference to the global variable atManagerRef_ complete");

    if (napi_new_instance(env, cons, 0, nullptr, &instance) != napi_ok) {
        return nullptr;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "New the js instance complete");

    return instance;
}

void NapiAtManager::ParseInputVerifyPermissionOrGetFlag(const napi_env env, const napi_callback_info info,
    AtManagerAsyncContext& asyncContext)
{
    size_t argc = VERIFY_OR_FLAG_INPUT_MAX_VALUES;

    napi_value argv[VERIFY_OR_FLAG_INPUT_MAX_VALUES] = { 0 };
    napi_value thisVar = nullptr;

    void *data = nullptr;

    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    asyncContext.env = env;

    // parse input tokenId and permissionName
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (valueType == napi_number) {
            napi_get_value_uint32(env, argv[i], &(asyncContext.tokenId)); // get tokenId
        } else if (valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], asyncContext.permissionName,
                VALUE_BUFFER_SIZE + 1, &(asyncContext.pNameLen)); // get permissionName
        } else {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Type matching failed");
            return;
        }
    }

    asyncContext.result = AT_PERM_OPERA_SUCC;

    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID = %{public}d, permissionName = %{public}s", asyncContext.tokenId,
        asyncContext.permissionName);
}

void NapiAtManager::VerifyAccessTokenExecute(napi_env env, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext *>(data);

    // use innerkit class method to verify permission
    asyncContext->result = AccessTokenKit::VerifyAccessToken(asyncContext->tokenId,
        asyncContext->permissionName);
}

void NapiAtManager::VerifyAccessTokenComplete(napi_env env, napi_status status, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext *>(data);
    napi_value result;

    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenId = %{public}d, permissionName = %{public}s, verify result = %{public}d.",
        asyncContext->tokenId, asyncContext->permissionName, asyncContext->result);

    // only resolve, no reject currently
    napi_create_int32(env, asyncContext->result, &result); // verify result
    napi_resolve_deferred(env, asyncContext->deferred, result);

    // after return the result, free resources
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
}

napi_value NapiAtManager::VerifyAccessToken(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "VerifyAccessToken begin.");

    auto *asyncContext = new AtManagerAsyncContext(); // for async work deliver data
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    ParseInputVerifyPermissionOrGetFlag(env, info, *asyncContext);
    if (asyncContext->result == AT_PERM_OPERA_FAIL) {
        delete asyncContext;
        return nullptr;
    }

    // after get input, keep result default failed
    asyncContext->result = AT_PERM_OPERA_FAIL;

    napi_value result = nullptr;
    napi_create_promise(env, &(asyncContext->deferred), &result); // create delay promise object

    napi_value resource = nullptr; // resource name
    napi_create_string_utf8(env, "VerifyAccessToken", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work( // define work
        env, nullptr, resource, VerifyAccessTokenExecute, VerifyAccessTokenComplete,
        reinterpret_cast<void *>(asyncContext), &(asyncContext->work));
    napi_queue_async_work(env, asyncContext->work); // add async work handle to the napi queue and wait for result

    ACCESSTOKEN_LOG_DEBUG(LABEL, "VerifyAccessToken end.");

    return result;
}

napi_value NapiAtManager::VerifyAccessTokenSync(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "VerifyAccessToken begin.");

    auto *asyncContext = new AtManagerAsyncContext(); // for async work deliver data
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    ParseInputVerifyPermissionOrGetFlag(env, info, *asyncContext);
    if (asyncContext->result == AT_PERM_OPERA_FAIL) {
        delete asyncContext;
        return nullptr;
    }

    // use innerkit class method to verify permission
    asyncContext->result = AccessTokenKit::VerifyAccessToken(asyncContext->tokenId,
        asyncContext->permissionName);

    napi_value result = nullptr;
    napi_create_int32(env, asyncContext->result, &result); // verify result

    ACCESSTOKEN_LOG_DEBUG(LABEL, "VerifyAccessToken end.");

    return result;
}

void NapiAtManager::ParseInputGrantOrRevokePermission(const napi_env env, const napi_callback_info info,
    AtManagerAsyncContext& asyncContext)
{
    size_t argc = GRANT_OR_REVOKE_INPUT_MAX_VALUES;

    napi_value argv[GRANT_OR_REVOKE_INPUT_MAX_VALUES] = {nullptr};
    napi_value thisVar = nullptr;

    void *data = nullptr;

    napi_get_cb_info(env, info, &argc, argv, &thisVar, &data);

    asyncContext.env = env;

    // parse input tokenId and permissionName
    for (size_t i = 0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if ((i == 0) && (valueType == napi_number)) {
            napi_get_value_uint32(env, argv[i], &(asyncContext.tokenId)); // get tokenId
        } else if (valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], asyncContext.permissionName,
                VALUE_BUFFER_SIZE + 1, &(asyncContext.pNameLen)); // get permissionName
        } else if (valueType == napi_number) {
            napi_get_value_int32(env, argv[i], &(asyncContext.flag)); // get flag
        } else if (valueType == napi_function) {
            napi_create_reference(env, argv[i], 1, &asyncContext.callbackRef); // get probably callback
        } else {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Type matching failed");
            return;
        }
    }

    asyncContext.result = AT_PERM_OPERA_SUCC;

    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID = %{public}d, permissionName = %{public}s, flag = %{public}d",
        asyncContext.tokenId, asyncContext.permissionName, asyncContext.flag);
}

void NapiAtManager::GrantUserGrantedPermissionExcute(napi_env env, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext *>(data);
    PermissionDef permissionDef;

    // struct init, can not use = { 0 } or memset otherwise program crashdump
    permissionDef.grantMode = 0;
    permissionDef.availableLevel = APL_NORMAL;
    permissionDef.provisionEnable = false;
    permissionDef.distributedSceneEnable = false;
    permissionDef.labelId = 0;
    permissionDef.descriptionId = 0;

    // use innerkit class method to check if the permission grantmode is USER_GRANT-0
    int ret = AccessTokenKit::GetDefPermission(asyncContext->permissionName, permissionDef);
    if (ret) {
        // this means permission is undefined, return failed
        return;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "permissionName = %{public}s, grantmode = %{public}d.", asyncContext->permissionName,
        permissionDef.grantMode);

    // only user_grant permission can use innerkit class method to grant permission, system_grant return failed
    if (permissionDef.grantMode == USER_GRANT) {
        asyncContext->result = AccessTokenKit::GrantPermission(asyncContext->tokenId, asyncContext->permissionName,
            asyncContext->flag);

        ACCESSTOKEN_LOG_DEBUG(LABEL,
            "tokenId = %{public}d, permissionName = %{public}s, flag = %{public}d, grant result = %{public}d.",
            asyncContext->tokenId, asyncContext->permissionName, asyncContext->flag, asyncContext->result);
    }
}

void NapiAtManager::GrantUserGrantedPermissionComplete(napi_env env, napi_status status, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    napi_value results[ASYNC_CALL_BACK_VALUES_NUM] = {nullptr}; // for AsyncCallback <err, data>

    // no err, results[0] remain nullptr
    napi_create_int32(env, asyncContext->result, &results[ASYNC_CALL_BACK_VALUES_NUM - 1]);

    if (asyncContext->deferred) {
        // promise type, no reject currently
        napi_resolve_deferred(env, asyncContext->deferred, results[ASYNC_CALL_BACK_VALUES_NUM - 1]);
    } else {
        // callback type
        napi_value callback = nullptr;
        napi_value thisValue = nullptr; // recv napi value
        napi_value thatValue = nullptr; // result napi value

        // set call function params->napi_call_function(env, recv, func, argc, argv, result)
        napi_get_undefined(env, &thisValue); // can not null otherwise js code can not get return
        napi_create_int32(env, 0, &thatValue); // can not null otherwise js code can not get return
        napi_get_reference_value(env, asyncContext->callbackRef, &callback);
        napi_call_function(env, thisValue, callback, ASYNC_CALL_BACK_VALUES_NUM, results, &thatValue);
        napi_delete_reference(env, asyncContext->callbackRef); // release callback handle
    }

    // after return the result, free resources
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
}

napi_value NapiAtManager::GrantUserGrantedPermission(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GrantUserGrantedPermission begin.");

    auto *asyncContext = new (std::nothrow) AtManagerAsyncContext(); // for async work deliver data
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    ParseInputGrantOrRevokePermission(env, info, *asyncContext);
    if (asyncContext->result == AT_PERM_OPERA_FAIL) {
        delete asyncContext;
        return nullptr;
    }

    // after get input, keep result default failed
    asyncContext->result = AT_PERM_OPERA_FAIL;

    napi_value result = nullptr;

    if (asyncContext->callbackRef == nullptr) {
        // when callback null, create delay promise object for returning result in async work complete function
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        // callback not null, use callback type to return result
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr; // resource name
    napi_create_string_utf8(env, "GrantUserGrantedPermission", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work( // define work
        env, nullptr, resource, GrantUserGrantedPermissionExcute, GrantUserGrantedPermissionComplete,
        reinterpret_cast<void *>(asyncContext), &(asyncContext->work));

    napi_queue_async_work(env, asyncContext->work); // add async work handle to the napi queue and wait for result

    ACCESSTOKEN_LOG_DEBUG(LABEL, "GrantUserGrantedPermission end.");

    return result;
}

void NapiAtManager::RevokeUserGrantedPermissionExcute(napi_env env, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext *>(data);
    PermissionDef permissionDef;

    // struct init, can not use = { 0 } or memset otherwise program crashdump
    permissionDef.grantMode = 0;
    permissionDef.availableLevel = APL_NORMAL;
    permissionDef.provisionEnable = false;
    permissionDef.distributedSceneEnable = false;
    permissionDef.labelId = 0;
    permissionDef.descriptionId = 0;

    // use innerkit class method to check if the permission grantmode is USER_GRANT-0
    int ret = AccessTokenKit::GetDefPermission(asyncContext->permissionName, permissionDef);
    if (ret) {
        // this means permission is undefined, return failed
        return;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "permissionName = %{public}s, grantmode = %{public}d.", asyncContext->permissionName,
        permissionDef.grantMode);

    // only user_grant permission can use innerkit class method to grant permission, system_grant return failed
    if (permissionDef.grantMode == USER_GRANT) {
        asyncContext->result = AccessTokenKit::RevokePermission(asyncContext->tokenId, asyncContext->permissionName,
            asyncContext->flag);

        ACCESSTOKEN_LOG_DEBUG(LABEL,
            "tokenId = %{public}d, permissionName = %{public}s, flag = %{public}d, revoke result = %{public}d.",
            asyncContext->tokenId, asyncContext->permissionName, asyncContext->flag, asyncContext->result);
    }
}

void NapiAtManager::RevokeUserGrantedPermissionComplete(napi_env env, napi_status status, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    napi_value results[ASYNC_CALL_BACK_VALUES_NUM] = {nullptr}; // for AsyncCallback <err, data>

    // no err, results[0] remain nullptr
    napi_create_int32(env, asyncContext->result, &results[ASYNC_CALL_BACK_VALUES_NUM - 1]);

    if (asyncContext->deferred) {
        // promise type, no reject currently
        napi_resolve_deferred(env, asyncContext->deferred, results[ASYNC_CALL_BACK_VALUES_NUM - 1]);
    } else {
        // callback type
        napi_value callback = nullptr;
        napi_value thisValue = nullptr; // recv napi value
        napi_value thatValue = nullptr; // result napi value

        // set call function params->napi_call_function(env, recv, func, argc, argv, result)
        napi_get_undefined(env, &thisValue); // can not null otherwise js code can not get return
        napi_create_int32(env, 0, &thatValue); // can not null otherwise js code can not get return
        napi_get_reference_value(env, asyncContext->callbackRef, &callback);
        napi_call_function(env, thisValue, callback, ASYNC_CALL_BACK_VALUES_NUM, results, &thatValue);
        napi_delete_reference(env, asyncContext->callbackRef); // release callback handle
    }

    // after return the result, free resources
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
}

napi_value NapiAtManager::RevokeUserGrantedPermission(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "RevokeUserGrantedPermission begin.");

    auto *asyncContext = new AtManagerAsyncContext(); // for async work deliver data
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    ParseInputGrantOrRevokePermission(env, info, *asyncContext);
    if (asyncContext->result == AT_PERM_OPERA_FAIL) {
        delete asyncContext;
        return nullptr;
    }

    // after get input, keep result default failed
    asyncContext->result = AT_PERM_OPERA_FAIL;

    napi_value result = nullptr;

    if (asyncContext->callbackRef == nullptr) {
        // when callback null, create delay promise object for returning result in async work complete function
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        // callback not null, use callback type to return result
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr; // resource name
    napi_create_string_utf8(env, "RevokeUserGrantedPermission", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work( // define work
        env, nullptr, resource, RevokeUserGrantedPermissionExcute, RevokeUserGrantedPermissionComplete,
        reinterpret_cast<void *>(asyncContext), &(asyncContext->work));

    napi_queue_async_work(env, asyncContext->work); // add async work handle to the napi queue and wait for result

    ACCESSTOKEN_LOG_DEBUG(LABEL, "RevokeUserGrantedPermission end.");

    return result;
}

void NapiAtManager::GetPermissionFlagsExcute(napi_env env, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);

    // use innerkit class method to get permission flag
    asyncContext->flag = AccessTokenKit::GetPermissionFlag(asyncContext->tokenId,
        asyncContext->permissionName);
}

void NapiAtManager::GetPermissionFlagsComplete(napi_env env, napi_status status, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    napi_value result;

    ACCESSTOKEN_LOG_DEBUG(LABEL, "permissionName = %{public}s, tokenId = %{public}d, flag = %{public}d.",
        asyncContext->permissionName, asyncContext->tokenId, asyncContext->flag);

    // only resolve, no reject currently
    napi_create_int32(env, asyncContext->flag, &result);
    napi_resolve_deferred(env, asyncContext->deferred, result);

    // after return the result, free resources
    napi_delete_async_work(env, asyncContext->work);
    delete asyncContext;
}

napi_value NapiAtManager::GetPermissionFlags(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetPermissionFlags begin.");

    auto *asyncContext = new AtManagerAsyncContext(); // for async work deliver data
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    ParseInputVerifyPermissionOrGetFlag(env, info, *asyncContext);
    if (asyncContext->result == AT_PERM_OPERA_FAIL) {
        delete asyncContext;
        return nullptr;
    }

    // after get input, keep result default failed
    asyncContext->result = AT_PERM_OPERA_FAIL;

    napi_value result = nullptr;
    napi_create_promise(env, &(asyncContext->deferred), &result); // create delay promise object

    napi_value resource = nullptr; // resource name
    napi_create_string_utf8(env, "VerifyAccessToken", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work( // define work
        env, nullptr, resource, GetPermissionFlagsExcute, GetPermissionFlagsComplete,
        reinterpret_cast<void *>(asyncContext), &(asyncContext->work));
    napi_queue_async_work(env, asyncContext->work); // add async work handle to the napi queue and wait for result

    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetPermissionFlags end.");

    return result;
}

bool NapiAtManager::ParseInputToRegister(const napi_env env, const napi_callback_info cbInfo,
    RegisterPermStateChangeInfo& registerPermStateChangeInfo)
{
    size_t argc = ARGS_FOUR;
    napi_value argv[ARGS_FOUR] = {nullptr};
    napi_value thisVar = nullptr;
    napi_ref callback = nullptr;
    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_get_cb_info failed");
        return false;
    }
    std::string type = ParseString(env, argv[PARAM0]);
    PermStateChangeScope scopeInfo;
    if (!ParseAccessTokenIDArray(env, argv[PARAM1], scopeInfo.tokenIDs)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ParseAccessTokenIDArray failed");
        return false;
    }
    scopeInfo.permList = ParseStringArray(env, argv[PARAM2]);
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[PARAM3], &valueType); // get PRARM[3] type
    if (valueType == napi_function) {
        if (napi_create_reference(env, argv[PARAM3], 1, &callback) != napi_ok) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "napi_create_reference failed");
            return false;
        }
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "argv[PARAM3] type matching failed");
        return false;
    }
    registerPermStateChangeInfo.env = env;
    registerPermStateChangeInfo.work = nullptr;
    registerPermStateChangeInfo.callbackRef = callback;
    registerPermStateChangeInfo.permStateChangeType = type;
    registerPermStateChangeInfo.scopeInfo = scopeInfo;
    registerPermStateChangeInfo.subscriber = std::make_shared<RegisterPermStateChangeScopePtr>(scopeInfo);
    AccessTokenKit* accessTokenKitInfo = nullptr;
    if (napi_unwrap(env, thisVar, reinterpret_cast<void **>(&accessTokenKitInfo)) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_unwrap failed");
        return false;
    }
    registerPermStateChangeInfo.accessTokenKit = accessTokenKitInfo;
    return true;
}

void NapiAtManager::RegisterPermStateChangeExecute(napi_env env, void* data)
{
    if (data == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "data is null");
        return;
    }
    RegisterPermStateChangeInfo* registerPermStateChangeInfo =
        reinterpret_cast<RegisterPermStateChangeInfo*>(data);
    (*registerPermStateChangeInfo->subscriber).SetEnv(env);
    (*registerPermStateChangeInfo->subscriber).SetCallbackRef(registerPermStateChangeInfo->callbackRef);
    registerPermStateChangeInfo->errCode =
        AccessTokenKit::RegisterPermStateChangeCallback(registerPermStateChangeInfo->subscriber);
    ACCESSTOKEN_LOG_DEBUG(LABEL, "RegisterPermStateChangeCallback ret = %{public}d",
        registerPermStateChangeInfo->errCode);
}

void NapiAtManager::RegisterPermStateChangeComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "data is null");
        return;
    }
    RegisterPermStateChangeInfo* registerPermStateChangeInfo =
        reinterpret_cast<RegisterPermStateChangeInfo*>(data);
    std::unique_ptr<RegisterPermStateChangeInfo> callbackPtr {registerPermStateChangeInfo};
    if (registerPermStateChangeInfo->errCode != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "errCode = %{public}d, delete register in map",
            registerPermStateChangeInfo->errCode);
        // Even if napi_delete_async_work failed, invalid registerPermStateChangeInfo needs to be deleted
        napi_delete_async_work(env, registerPermStateChangeInfo->work);
        registerPermStateChangeInfo->work = nullptr;
        DeleteRegisterInMap(registerPermStateChangeInfo->accessTokenKit, registerPermStateChangeInfo->scopeInfo);
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_delete_async_work(env, registerPermStateChangeInfo->work));
    registerPermStateChangeInfo->work = nullptr;
    callbackPtr.release();
}

napi_value NapiAtManager::RegisterPermStateChangeCallback(napi_env env, napi_callback_info cbInfo)
{
    RegisterPermStateChangeInfo* registerPermStateChangeInfo =
        new (std::nothrow) RegisterPermStateChangeInfo();
    if (registerPermStateChangeInfo == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "insufficient memory for subscribeCBInfo!");
        return nullptr;
    }
    std::unique_ptr<RegisterPermStateChangeInfo> callbackPtr {registerPermStateChangeInfo};
    if (!ParseInputToRegister(env, cbInfo, *registerPermStateChangeInfo)) {
        return nullptr;
    }
    if (IsExistRegister(registerPermStateChangeInfo)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Subscribe failed. The current subscriber has been existed");
        return nullptr;
    }
    { // add to map
        std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
        g_permStateChangeRegisters[registerPermStateChangeInfo->accessTokenKit].emplace_back(
            registerPermStateChangeInfo);
        ACCESSTOKEN_LOG_DEBUG(LABEL, "add g_PermStateChangeRegisters->second.size = %{public}zu",
            g_permStateChangeRegisters[registerPermStateChangeInfo->accessTokenKit].size());
    }
    napi_value resource = nullptr;
    if (napi_create_string_utf8(env, "RegisterPermStateChangeCallback", NAPI_AUTO_LENGTH, &resource) != napi_ok) {
        DeleteRegisterInMap(registerPermStateChangeInfo->accessTokenKit, registerPermStateChangeInfo->scopeInfo);
        return nullptr;
    }
    if (napi_create_async_work(env,
        nullptr,
        resource,
        RegisterPermStateChangeExecute,
        RegisterPermStateChangeComplete,
        reinterpret_cast<void *>(registerPermStateChangeInfo),
        &registerPermStateChangeInfo->work) != napi_ok) {
            DeleteRegisterInMap(registerPermStateChangeInfo->accessTokenKit, registerPermStateChangeInfo->scopeInfo);
            return nullptr;
    }
    if (napi_queue_async_work(env, registerPermStateChangeInfo->work) != napi_ok) {
        DeleteRegisterInMap(registerPermStateChangeInfo->accessTokenKit, registerPermStateChangeInfo->scopeInfo);
        return nullptr;
    }
    callbackPtr.release();
    return nullptr;
}

bool NapiAtManager::ParseInputToUnregister(const napi_env env, napi_callback_info cbInfo,
    UnregisterPermStateChangeInfo& unregisterPermStateChangeInfo)
{
    size_t argc = ARGS_FOUR;
    napi_value argv[ARGS_FOUR] = {nullptr};
    napi_value thisVar = nullptr;
    napi_ref callback = nullptr;
    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_get_cb_info failed");
        return false;
    }
    std::string type = ParseString(env, argv[PARAM0]);
    PermStateChangeScope scopeInfo;
    if (!ParseAccessTokenIDArray(env, argv[PARAM1], scopeInfo.tokenIDs)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ParseAccessTokenIDArray failed");
        return false;
    }
    scopeInfo.permList = ParseStringArray(env, argv[PARAM2]);
    if (argc >= ARGS_FOUR) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[PARAM3], &valueType); // get PRARM[3] type
        if (valueType == napi_function) {
            if (napi_create_reference(env, argv[PARAM3], 1, &callback) != napi_ok) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "napi_create_reference failed");
                return false;
            }
        } else {
            ACCESSTOKEN_LOG_ERROR(LABEL, "argv[PARAM3] type matching failed");
            return false;
        }
    }
    unregisterPermStateChangeInfo.env = env;
    unregisterPermStateChangeInfo.callbackRef = callback;
    unregisterPermStateChangeInfo.permStateChangeType = type;
    unregisterPermStateChangeInfo.scopeInfo = scopeInfo;
    AccessTokenKit* accessTokenKitInfo = nullptr;
    if (napi_unwrap(env, thisVar, reinterpret_cast<void **>(&accessTokenKitInfo)) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_unwrap failed");
        return false;
    }
    unregisterPermStateChangeInfo.accessTokenKit = accessTokenKitInfo;
    return true;
}

void NapiAtManager::UnregisterPermStateChangeExecute(napi_env env, void* data)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "UnregisterPermStateChangeExecute begin");
    if (data == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "data is null");
        return;
    }
    UnregisterPermStateChangeInfo* unregisterPermStateChangeInfo =
        reinterpret_cast<UnregisterPermStateChangeInfo*>(data);
    auto subscriber = unregisterPermStateChangeInfo->subscriber;
    unregisterPermStateChangeInfo->errCode = AccessTokenKit::UnRegisterPermStateChangeCallback(subscriber);
}

void NapiAtManager::UnregisterPermStateChangeCompleted(napi_env env, napi_status status, void* data)
{
    if (data == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "data is null");
        return;
    }
    UnregisterPermStateChangeInfo* unregisterPermStateChangeInfo =
        reinterpret_cast<UnregisterPermStateChangeInfo*>(data);
    std::unique_ptr<UnregisterPermStateChangeInfo> callbackPtr {unregisterPermStateChangeInfo};
    if (unregisterPermStateChangeInfo->callbackRef != nullptr) {
        napi_value results[ARGS_ONE] = {nullptr};
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &results[PARAM0]));
        napi_value undefined;
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
        napi_value resultout = nullptr;
        napi_value callback = nullptr;
        NAPI_CALL_RETURN_VOID(env,
            napi_get_reference_value(env, unregisterPermStateChangeInfo->callbackRef, &callback));
        NAPI_CALL_RETURN_VOID(env,
            napi_call_function(env, undefined, callback, ARGS_ONE, &results[PARAM0], &resultout));
    }
    if (unregisterPermStateChangeInfo->errCode == RET_SUCCESS) {
        DeleteRegisterInMap(unregisterPermStateChangeInfo->accessTokenKit, unregisterPermStateChangeInfo->scopeInfo);
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "errCode = %{public}d", unregisterPermStateChangeInfo->errCode);
    }
}

napi_value NapiAtManager::UnregisterPermStateChangeCallback(napi_env env, napi_callback_info cbInfo)
{
    UnregisterPermStateChangeInfo* unregisterPermStateChangeInfo =
        new (std::nothrow) UnregisterPermStateChangeInfo();
    if (unregisterPermStateChangeInfo == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "insufficient memory for subscribeCBInfo!");
        return nullptr;
    }
    std::unique_ptr<UnregisterPermStateChangeInfo> callbackPtr {unregisterPermStateChangeInfo};
    if (!ParseInputToUnregister(env, cbInfo, *unregisterPermStateChangeInfo)) {
        return nullptr;
    }
    if (!FindAndGetSubscriberInMap(unregisterPermStateChangeInfo)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Unsubscribe failed. The current subscriber does not exist");
        return nullptr;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "The current subscriber exist");
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "RegisterPermStateChangeCallback", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env,
        nullptr,
        resource,
        UnregisterPermStateChangeExecute,
        UnregisterPermStateChangeCompleted,
        reinterpret_cast<void *>(unregisterPermStateChangeInfo),
        &(unregisterPermStateChangeInfo->work)));
    NAPI_CALL(env, napi_queue_async_work(env, unregisterPermStateChangeInfo->work));
    callbackPtr.release();
    return nullptr;
}

bool NapiAtManager::FindAndGetSubscriberInMap(UnregisterPermStateChangeInfo* unregisterPermStateChangeInfo)
{
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    std::vector<AccessTokenID> tokenIDs = unregisterPermStateChangeInfo->scopeInfo.tokenIDs;
    std::vector<std::string> permList = unregisterPermStateChangeInfo->scopeInfo.permList;
    std::sort(tokenIDs.begin(), tokenIDs.end());
    std::sort(permList.begin(), permList.end());
    auto registerInstance = g_permStateChangeRegisters.find(unregisterPermStateChangeInfo->accessTokenKit);
    if (registerInstance != g_permStateChangeRegisters.end()) {
        for (const auto& item : registerInstance->second) {
            PermStateChangeScope scopeInfo;
            item->subscriber->GetScope(scopeInfo);
            if (CompareScopeInfo(scopeInfo, tokenIDs, permList)) {
                ACCESSTOKEN_LOG_DEBUG(LABEL, "find subscriber in map");
                unregisterPermStateChangeInfo->subscriber = item->subscriber;
                return true;
            }
        }
    }
    return false;
}

bool NapiAtManager::IsExistRegister(const RegisterPermStateChangeInfo* registerPermStateChangeInfo)
{
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    std::vector<AccessTokenID> tokenIDs = registerPermStateChangeInfo->scopeInfo.tokenIDs;
    std::vector<std::string> permList = registerPermStateChangeInfo->scopeInfo.permList;
    std::sort(tokenIDs.begin(), tokenIDs.end());
    std::sort(permList.begin(), permList.end());
    auto registerInstance = g_permStateChangeRegisters.find(registerPermStateChangeInfo->accessTokenKit);
    if (registerInstance != g_permStateChangeRegisters.end()) {
        for (const auto& item : registerInstance->second) {
            PermStateChangeScope scopeInfo;
            item->subscriber->GetScope(scopeInfo);
            if (CompareScopeInfo(scopeInfo, tokenIDs, permList)) {
                ACCESSTOKEN_LOG_DEBUG(LABEL, "find subscriber in map");
                return true;
            }
        }
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "cannot find subscriber in map");
    return false;
}

void NapiAtManager::DeleteRegisterInMap(AccessTokenKit* accessTokenKit, const PermStateChangeScope& scopeInfo)
{
    std::vector<AccessTokenID> tokenIDs = scopeInfo.tokenIDs;
    std::vector<std::string> permList = scopeInfo.permList;
    std::sort(tokenIDs.begin(), tokenIDs.end());
    std::sort(permList.begin(), permList.end());
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    auto subscribers = g_permStateChangeRegisters.find(accessTokenKit);
    if (subscribers != g_permStateChangeRegisters.end()) {
        auto it = subscribers->second.begin();
        while (it != subscribers->second.end()) {
            if (CompareScopeInfo((*it)->scopeInfo, tokenIDs, permList)) {
                ACCESSTOKEN_LOG_DEBUG(LABEL, "Find subscribers in map, delete");
                subscribers->second.erase(it);
                delete *it;
                *it =nullptr;
                break;
            } else {
                ++it;
            }
        }
        if (subscribers->second.empty()) {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "No subscriberInfo in the vector, erase the map.");
            g_permStateChangeRegisters.erase(subscribers);
        }
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS

EXTERN_C_START
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports)
{
    ACCESSTOKEN_LOG_DEBUG(OHOS::Security::AccessToken::LABEL, "Register end, start init.");

    return OHOS::Security::AccessToken::NapiAtManager::Init(env, exports);
}
EXTERN_C_END

/*
 * Module define
 */
static napi_module _module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "abilityAccessCtrl",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void AbilityAccessCtrlmoduleRegister(void)
{
    napi_module_register(&_module);
}
