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

#include "ability.h"
#include "ability_manager_client.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_base_context.h"
#include "napi_error.h"
#include "parameter.h"
#include "remote_object_wrapper.h"
#include "string_wrapper.h"
#include "token_setproc.h"
#include "want_params_wrapper.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::mutex g_lockForPermStateChangeRegisters;
std::vector<RegisterPermStateChangeInfo*> g_permStateChangeRegisters;
std::mutex g_lockCache;
std::map<std::string, PermissionStatusCache> g_cache;
static PermissionParamCache g_paramCache;
std::mutex g_lockForPermRequestCallbacks;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenAbilityAccessCtrl"
};
static constexpr int32_t VERIFY_OR_FLAG_INPUT_MAX_PARAMS = 2;
static constexpr int32_t GRANT_OR_REVOKE_INPUT_MAX_PARAMS = 4;
static constexpr int32_t REQUEST_PERMISSION_MAX_PARAMS = 3;
static constexpr int32_t ON_OFF_MAX_PARAMS = 4;
static constexpr int32_t MAX_LENGTH = 256;
static const char* PERMISSION_STATUS_CHANGE_KEY = "accesstoken.permission.change";
static constexpr int32_t VALUE_MAX_LEN = 32;

const std::string GRANT_ABILITY_BUNDLE_NAME = "com.ohos.permissionmanager";
const std::string GRANT_ABILITY_ABILITY_NAME = "com.ohos.permissionmanager.GrantAbility";
const std::string PERMISSION_KEY = "ohos.user.grant.permission";
const std::string STATE_KEY = "ohos.user.grant.permission.state";
const std::string TOKEN_KEY = "ohos.ability.params.token";
const std::string CALLBACK_KEY = "ohos.ability.params.callback";

static void ReturnPromiseResult(napi_env env, int32_t contextResult, napi_deferred deferred, napi_value result)
{
    if (contextResult != RET_SUCCESS) {
        napi_value businessError = GenerateBusinessError(env, contextResult, GetErrorMessage(contextResult));
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, deferred, businessError));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, deferred, result));
    }
}

static void ReturnCallbackResult(napi_env env, int32_t contextResult, napi_ref &callbackRef, napi_value result)
{
    napi_value businessError = GetNapiNull(env);
    if (contextResult != RET_SUCCESS) {
        businessError = GenerateBusinessError(env, contextResult, GetErrorMessage(contextResult));
    }
    napi_value results[ASYNC_CALL_BACK_VALUES_NUM] = { businessError, result };

    napi_value callback = nullptr;
    napi_value thisValue = nullptr;
    napi_value thatValue = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &thisValue));
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 0, &thatValue));
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, callbackRef, &callback));
    NAPI_CALL_RETURN_VOID(env,
        napi_call_function(env, thisValue, callback, ASYNC_CALL_BACK_VALUES_NUM, results, &thatValue));
}

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
    napi_value result = {nullptr};
    NAPI_CALL_RETURN_VOID(registerPermStateChangeData->env,
        napi_create_array(registerPermStateChangeData->env, &result));
    if (!ConvertPermStateChangeInfo(registerPermStateChangeData->env,
        result, registerPermStateChangeData->result)) {
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
        undefined, callback, 1, &result, &resultout));
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
    std::lock_guard<std::mutex> lock(validMutex_);
    if (!valid_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "object is invalid.");
        return;
    }
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

void RegisterPermStateChangeScopePtr::SetValid(bool valid)
{
    std::lock_guard<std::mutex> lock(validMutex_);
    valid_ = valid;
}

PermStateChangeContext::~PermStateChangeContext()
{
    if (callbackRef == nullptr) {
        return;
    }
    DeleteNapiRef();
}

void UvQueueWorkDeleteRef(uv_work_t *work, int32_t status)
{
    if (work == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "work == nullptr : %{public}d", work == nullptr);
        return;
    } else if (work->data == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "work->data == nullptr : %{public}d", work->data == nullptr);
        return;
    }
    RegisterPermStateChangeWorker* registerPermStateChangeWorker =
        reinterpret_cast<RegisterPermStateChangeWorker*>(work->data);
    if (registerPermStateChangeWorker == nullptr) {
        delete work;
        return;
    }
    napi_delete_reference(registerPermStateChangeWorker->env, registerPermStateChangeWorker->ref);
    delete registerPermStateChangeWorker;
    registerPermStateChangeWorker = nullptr;
    delete work;
    ACCESSTOKEN_LOG_DEBUG(LABEL, "UvQueueWorkDeleteRef end");
}

void PermStateChangeContext::DeleteNapiRef()
{
    uv_loop_s* loop = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_uv_event_loop(env, &loop));
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
    registerPermStateChangeWorker->env = env;
    registerPermStateChangeWorker->ref = callbackRef;

    work->data = reinterpret_cast<void *>(registerPermStateChangeWorker);
    NAPI_CALL_RETURN_VOID(env,
        uv_queue_work(loop, work, [](uv_work_t* work) {}, UvQueueWorkDeleteRef));
    ACCESSTOKEN_LOG_DEBUG(LABEL, "DeleteNapiRef");
    uvWorkPtr.release();
    workPtr.release();
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
        DECLARE_NAPI_FUNCTION("checkAccessToken", CheckAccessToken),
        DECLARE_NAPI_FUNCTION("getPermissionFlags", GetPermissionFlags),
        DECLARE_NAPI_FUNCTION("on", RegisterPermStateChangeCallback),
        DECLARE_NAPI_FUNCTION("off", UnregisterPermStateChangeCallback),
        DECLARE_NAPI_FUNCTION("getVersion", GetVersion),
        DECLARE_NAPI_FUNCTION("requestPermissionsFromUser", RequestPermissionsFromUser),
    };

    napi_value cons = nullptr;
    NAPI_CALL(env, napi_define_class(env, ATMANAGER_CLASS_NAME.c_str(), ATMANAGER_CLASS_NAME.size(),
        JsConstructor, nullptr, sizeof(properties) / sizeof(napi_property_descriptor), properties, &cons));

    NAPI_CALL(env, napi_create_reference(env, cons, 1, &g_atManagerRef_));
    NAPI_CALL(env, napi_set_named_property(env, exports, ATMANAGER_CLASS_NAME.c_str(), cons));

    napi_value grantStatus = nullptr;
    napi_create_object(env, &grantStatus);

    SetNamedProperty(env, grantStatus, PERMISSION_DENIED, "PERMISSION_DENIED");
    SetNamedProperty(env, grantStatus, PERMISSION_GRANTED, "PERMISSION_GRANTED");

    napi_value permStateChangeType = nullptr;
    napi_create_object(env, &permStateChangeType);

    SetNamedProperty(env, permStateChangeType, PERMISSION_REVOKED_OPER, "PERMISSION_REVOKED_OPER");
    SetNamedProperty(env, permStateChangeType, PERMISSION_GRANTED_OPER, "PERMISSION_GRANTED_OPER");

    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_PROPERTY("GrantStatus", grantStatus),
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
    return thisVar;
}

napi_value NapiAtManager::CreateAtManager(napi_env env, napi_callback_info cbInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "enter CreateAtManager");

    napi_value instance = nullptr;
    napi_value cons = nullptr;

    NAPI_CALL(env, napi_get_reference_value(env, g_atManagerRef_, &cons));
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Get a reference to the global variable g_atManagerRef_ complete");

    NAPI_CALL(env, napi_new_instance(env, cons, 0, nullptr, &instance));

    ACCESSTOKEN_LOG_DEBUG(LABEL, "New the js instance complete");

    return instance;
}

bool NapiAtManager::ParseInputVerifyPermissionOrGetFlag(const napi_env env, const napi_callback_info info,
    AtManagerAsyncContext& asyncContext)
{
    size_t argc = VERIFY_OR_FLAG_INPUT_MAX_PARAMS;

    napi_value argv[VERIFY_OR_FLAG_INPUT_MAX_PARAMS] = { nullptr };
    napi_value thisVar = nullptr;
    std::string errMsg;
    void *data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
    if (argc < VERIFY_OR_FLAG_INPUT_MAX_PARAMS) {
        NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env,
            JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }
    asyncContext.env = env;
    // 0: the first parameter of argv
    if (!ParseUint32(env, argv[0], asyncContext.tokenId)) {
        errMsg = GetParamErrorMsg("tokenId", "number");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    // 1: the second parameter of argv
    if (!ParseString(env, argv[1], asyncContext.permissionName)) {
        errMsg = GetParamErrorMsg("permissionName", "string");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID = %{public}d, permissionName = %{public}s", asyncContext.tokenId,
        asyncContext.permissionName.c_str());
    return true;
}

void NapiAtManager::VerifyAccessTokenExecute(napi_env env, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext *>(data);
    if (asyncContext == nullptr) {
        return;
    }
    asyncContext->result = AccessTokenKit::VerifyAccessToken(asyncContext->tokenId, asyncContext->permissionName);
}

void NapiAtManager::VerifyAccessTokenComplete(napi_env env, napi_status status, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext *>(data);
    if (asyncContext == nullptr) {
        return;
    }
    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    napi_value result;

    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenId = %{public}d, permissionName = %{public}s, verify result = %{public}d.",
        asyncContext->tokenId, asyncContext->permissionName.c_str(), asyncContext->result);

    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->result, &result)); // verify result
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred, result));
}

napi_value NapiAtManager::VerifyAccessToken(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "VerifyAccessToken begin.");

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct failed.");
        return nullptr;
    }

    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    if (!ParseInputVerifyPermissionOrGetFlag(env, info, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));

    napi_value resources = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "VerifyAccessToken", NAPI_AUTO_LENGTH, &resources));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resources,
        VerifyAccessTokenExecute, VerifyAccessTokenComplete,
        reinterpret_cast<void *>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));

    ACCESSTOKEN_LOG_DEBUG(LABEL, "VerifyAccessToken end.");
    context.release();
    return result;
}

void NapiAtManager::CheckAccessTokenExecute(napi_env env, void *data)
{
    if (data == nullptr) {
        return;
    }
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext *>(data);
    if (asyncContext == nullptr) {
        return;
    }
    if (asyncContext->tokenId == 0) {
        asyncContext->errorCode = JS_ERROR_PARAM_INVALID;
        return;
    }
    if (asyncContext->permissionName.empty() || (asyncContext->permissionName.length() > MAX_LENGTH)) {
        asyncContext->errorCode = JS_ERROR_PARAM_INVALID;
        return;
    }

    asyncContext->result = AccessTokenKit::VerifyAccessToken(asyncContext->tokenId,
        asyncContext->permissionName);
}

void NapiAtManager::CheckAccessTokenComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        return;
    }
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext *>(data);
    if (asyncContext == nullptr) {
        return;
    }
    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};

    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->result, &result));
    ReturnPromiseResult(env, asyncContext->errorCode, asyncContext->deferred, result);
}

napi_value NapiAtManager::CheckAccessToken(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "CheckAccessToken begin.");

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    if (!ParseInputVerifyPermissionOrGetFlag(env, info, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "CheckAccessToken", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        CheckAccessTokenExecute, CheckAccessTokenComplete,
        reinterpret_cast<void *>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));

    ACCESSTOKEN_LOG_DEBUG(LABEL, "CheckAccessToken end.");
    context.release();
    return result;
}

std::string NapiAtManager::GetPermParamValue()
{
    long long sysCommitId = GetSystemCommitId();
    if (sysCommitId == g_paramCache.sysCommitIdCache) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "sysCommitId = %{public}lld", sysCommitId);
        return g_paramCache.sysParamCache;
    }
    g_paramCache.sysCommitIdCache = sysCommitId;
    if (g_paramCache.handle == PARAM_DEFAULT_VALUE) {
        int32_t handle = static_cast<int32_t>(FindParameter(PERMISSION_STATUS_CHANGE_KEY));
        if (handle == PARAM_DEFAULT_VALUE) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "FindParameter failed");
            return "-1";
        }
        g_paramCache.handle = handle;
    }

    int32_t currCommitId = static_cast<int32_t>(GetParameterCommitId(g_paramCache.handle));
    if (currCommitId != g_paramCache.commitIdCache) {
        char value[VALUE_MAX_LEN] = {0};
        auto ret = GetParameterValue(g_paramCache.handle, value, VALUE_MAX_LEN - 1);
        if (ret < 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "return default value, ret=%{public}d", ret);
            return "-1";
        }
        std::string resStr(value);
        g_paramCache.sysParamCache = resStr;
        g_paramCache.commitIdCache = currCommitId;
    }
    return g_paramCache.sysParamCache;
}

void NapiAtManager::UpdatePermissionCache(AtManagerAsyncContext* asyncContext)
{
    std::lock_guard<std::mutex> lock(g_lockCache);
    auto iter = g_cache.find(asyncContext->permissionName);
    if (iter != g_cache.end()) {
        std::string currPara = GetPermParamValue();
        if (currPara != iter->second.paramValue) {
            asyncContext->result = AccessTokenKit::VerifyAccessToken(
                asyncContext->tokenId, asyncContext->permissionName);
            iter->second.status = asyncContext->result;
            iter->second.paramValue = currPara;
            ACCESSTOKEN_LOG_DEBUG(LABEL, "Param changed currPara %{public}s", currPara.c_str());
        } else {
            asyncContext->result = iter->second.status;
        }
    } else {
        asyncContext->result = AccessTokenKit::VerifyAccessToken(asyncContext->tokenId, asyncContext->permissionName);
        g_cache[asyncContext->permissionName].status = asyncContext->result;
        g_cache[asyncContext->permissionName].paramValue = GetPermParamValue();
        ACCESSTOKEN_LOG_DEBUG(LABEL, "g_cacheParam set %{public}s",
            g_cache[asyncContext->permissionName].paramValue.c_str());
    }
}

napi_value NapiAtManager::VerifyAccessTokenSync(napi_env env, napi_callback_info info)
{
    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    if (!ParseInputVerifyPermissionOrGetFlag(env, info, *asyncContext)) {
        return nullptr;
    }
    if (asyncContext->tokenId == 0) {
        std::string errMsg = GetParamErrorMsg("tokenID", "number");
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_INVALID, errMsg)));
        return nullptr;
    }
    if (asyncContext->permissionName.empty() || (asyncContext->permissionName.length() > MAX_LENGTH)) {
        std::string errMsg = GetParamErrorMsg("permissionName", "string");
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_INVALID, errMsg)));
        return nullptr;
    }
    if (asyncContext->tokenId != GetSelfTokenID()) {
        asyncContext->result = AccessTokenKit::VerifyAccessToken(asyncContext->tokenId, asyncContext->permissionName);
        napi_value result = nullptr;
        NAPI_CALL(env, napi_create_int32(env, asyncContext->result, &result));
        ACCESSTOKEN_LOG_DEBUG(LABEL, "VerifyAccessTokenSync end.");
        return result;
    }

    UpdatePermissionCache(asyncContext);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, asyncContext->result, &result));
    return result;
}

bool NapiAtManager::ParseInputGrantOrRevokePermission(const napi_env env, const napi_callback_info info,
    AtManagerAsyncContext& asyncContext)
{
    size_t argc = GRANT_OR_REVOKE_INPUT_MAX_PARAMS;
    napi_value argv[GRANT_OR_REVOKE_INPUT_MAX_PARAMS] = {nullptr};
    napi_value thatVar = nullptr;

    void *data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thatVar, &data), false);
    // 1: grant and revoke required minnum argc
    if (argc < GRANT_OR_REVOKE_INPUT_MAX_PARAMS - 1) {
        NAPI_CALL_BASE(env, napi_throw(env,
            GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }
    asyncContext.env = env;
    std::string errMsg;
    // 0: the first parameter of argv
    if (!ParseUint32(env, argv[0], asyncContext.tokenId)) {
        errMsg = GetParamErrorMsg("tokenId", "number");
        NAPI_CALL_BASE(
            env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    // 1: the second parameter of argv
    if (!ParseString(env, argv[1], asyncContext.permissionName)) {
        errMsg = GetParamErrorMsg("permissionName", "string");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    // 2: the third parameter of argv
    if (!ParseInt32(env, argv[2], asyncContext.flag)) {
        errMsg = GetParamErrorMsg("flag", "number");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    if (argc == GRANT_OR_REVOKE_INPUT_MAX_PARAMS) {
        // 3: the fourth parameter of argv
        if (!ParseCallback(env, argv[3], asyncContext.callbackRef)) {
            NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL,
                                GetErrorMessage(JsErrorCode::JS_ERROR_PARAM_ILLEGAL))), false);
            return false;
        }
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID = %{public}d, permissionName = %{public}s, flag = %{public}d",
        asyncContext.tokenId, asyncContext.permissionName.c_str(), asyncContext.flag);
    return true;
}

void NapiAtManager::GrantUserGrantedPermissionExecute(napi_env env, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext *>(data);
    if (asyncContext == nullptr) {
        return;
    }
    PermissionDef permissionDef;

    permissionDef.grantMode = 0;
    permissionDef.availableLevel = APL_NORMAL;
    permissionDef.provisionEnable = false;
    permissionDef.distributedSceneEnable = false;
    permissionDef.labelId = 0;
    permissionDef.descriptionId = 0;

    int32_t result = AccessTokenKit::GetDefPermission(asyncContext->permissionName, permissionDef);
    if (result != AT_PERM_OPERA_SUCC) {
        asyncContext->result = result;
        return;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "permissionName = %{public}s, grantmode = %{public}d.",
        asyncContext->permissionName.c_str(), permissionDef.grantMode);

    // only user_grant permission can use innerkit class method to grant permission, system_grant return failed
    if (permissionDef.grantMode == USER_GRANT) {
        asyncContext->result = AccessTokenKit::GrantPermission(asyncContext->tokenId, asyncContext->permissionName,
            asyncContext->flag);

        ACCESSTOKEN_LOG_DEBUG(LABEL,
            "tokenId = %{public}d, permissionName = %{public}s, flag = %{public}d, grant result = %{public}d.",
            asyncContext->tokenId, asyncContext->permissionName.c_str(), asyncContext->flag, asyncContext->result);
    }
}

void NapiAtManager::GrantUserGrantedPermissionComplete(napi_env env, napi_status status, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }
    std::unique_ptr<AtManagerAsyncContext> callbackPtr {asyncContext};
    napi_value result = GetNapiNull(env);

    if (asyncContext->deferred != nullptr) {
        ReturnPromiseResult(env, asyncContext->result, asyncContext->deferred, result);
    } else {
        ReturnCallbackResult(env, asyncContext->result, asyncContext->callbackRef, result);
    }
}

napi_value NapiAtManager::GetVersion(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetVersion begin.");

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }
    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetVersion", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, GetVersionExecute, GetVersionComplete,
        reinterpret_cast<void *>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));

    context.release();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetVersion end.");
    return result;
}

void NapiAtManager::GetVersionExecute(napi_env env, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext *>(data);
    if (asyncContext == nullptr) {
        return;
    }
    asyncContext->result = AccessTokenKit::GetVersion();
    ACCESSTOKEN_LOG_DEBUG(LABEL, "version result = %{public}d.", asyncContext->result);
}

void NapiAtManager::GetVersionComplete(napi_env env, napi_status status, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext *>(data);
    if (asyncContext == nullptr) {
        return;
    }
    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    napi_value result;

    ACCESSTOKEN_LOG_DEBUG(LABEL, "version result = %{public}d.", asyncContext->result);

    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->result, &result));
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred, result));
}

napi_value NapiAtManager::GrantUserGrantedPermission(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GrantUserGrantedPermission begin.");

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env); // for async work deliver data
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    if (!ParseInputGrantOrRevokePermission(env, info, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;

    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GrantUserGrantedPermission", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        GrantUserGrantedPermissionExecute, GrantUserGrantedPermissionComplete,
        reinterpret_cast<void *>(asyncContext), &(asyncContext->work)));

    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));

    ACCESSTOKEN_LOG_DEBUG(LABEL, "GrantUserGrantedPermission end.");
    context.release();
    return result;
}

void NapiAtManager::RevokeUserGrantedPermissionExecute(napi_env env, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext *>(data);
    if (asyncContext == nullptr) {
        return;
    }
    PermissionDef permissionDef;

    permissionDef.grantMode = 0;
    permissionDef.availableLevel = APL_NORMAL;
    permissionDef.provisionEnable = false;
    permissionDef.distributedSceneEnable = false;
    permissionDef.labelId = 0;
    permissionDef.descriptionId = 0;

    int32_t result = AccessTokenKit::GetDefPermission(asyncContext->permissionName, permissionDef);
    if (result != AT_PERM_OPERA_SUCC) {
        asyncContext->result = result;
        return;
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL, "permissionName = %{public}s, grantmode = %{public}d.",
        asyncContext->permissionName.c_str(), permissionDef.grantMode);

    // only user_grant permission can use innerkit class method to grant permission, system_grant return failed
    if (permissionDef.grantMode == USER_GRANT) {
        asyncContext->result = AccessTokenKit::RevokePermission(asyncContext->tokenId, asyncContext->permissionName,
            asyncContext->flag);

        ACCESSTOKEN_LOG_DEBUG(LABEL,
            "tokenId = %{public}d, permissionName = %{public}s, flag = %{public}d, revoke result = %{public}d.",
            asyncContext->tokenId, asyncContext->permissionName.c_str(), asyncContext->flag, asyncContext->result);
    }
}

void NapiAtManager::RevokeUserGrantedPermissionComplete(napi_env env, napi_status status, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }

    std::unique_ptr<AtManagerAsyncContext> callbackPtr {asyncContext};
    napi_value result = GetNapiNull(env);
    if (asyncContext->deferred != nullptr) {
        ReturnPromiseResult(env, asyncContext->result, asyncContext->deferred, result);
    } else {
        ReturnCallbackResult(env, asyncContext->result, asyncContext->callbackRef, result);
    }
}

napi_value NapiAtManager::RevokeUserGrantedPermission(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "RevokeUserGrantedPermission begin.");

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env); // for async work deliver data
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    if (!ParseInputGrantOrRevokePermission(env, info, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "RevokeUserGrantedPermission", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        RevokeUserGrantedPermissionExecute, RevokeUserGrantedPermissionComplete,
        reinterpret_cast<void *>(asyncContext), &(asyncContext->work)));

    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    ACCESSTOKEN_LOG_DEBUG(LABEL, "RevokeUserGrantedPermission end.");
    context.release();
    return result;
}

void NapiAtManager::GetPermissionFlagsExecute(napi_env env, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);

    asyncContext->result = AccessTokenKit::GetPermissionFlag(asyncContext->tokenId,
        asyncContext->permissionName, asyncContext->flag);
}

void NapiAtManager::GetPermissionFlagsComplete(napi_env env, napi_status status, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }
    std::unique_ptr<AtManagerAsyncContext> callbackPtr {asyncContext};

    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->flag, &result));

    ReturnPromiseResult(env, asyncContext->result, asyncContext->deferred, result);
}

napi_value NapiAtManager::GetPermissionFlags(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetPermissionFlags begin.");

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    if (!ParseInputVerifyPermissionOrGetFlag(env, info, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    napi_create_promise(env, &(asyncContext->deferred), &result); // create delay promise object

    napi_value resource = nullptr; // resource name
    napi_create_string_utf8(env, "GetPermissionFlags", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work( // define work
        env, nullptr, resource, GetPermissionFlagsExecute, GetPermissionFlagsComplete,
        reinterpret_cast<void *>(asyncContext), &(asyncContext->work));
    napi_queue_async_work(env, asyncContext->work); // add async work handle to the napi queue and wait for result

    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetPermissionFlags end.");
    context.release();
    return result;
}

static napi_value WrapVoidToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

static napi_value GetAbilityContext(const napi_env &env, const napi_value &value,
    std::shared_ptr<AbilityRuntime::AbilityContext> &abilityContext)
{
    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, value, stageMode);
    if (status != napi_ok || !stageMode) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "it is not a stage mode");
        return nullptr;
    } else {
        auto context = AbilityRuntime::GetStageModeContext(env, value);
        if (context == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "get context failed");
            return nullptr;
        }
        abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
        if (abilityContext == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "get Stage model ability context failed");
            return nullptr;
        }
        return WrapVoidToJS(env);
    }
}

bool NapiAtManager::ParseRequestPermissionFromUser(
    const napi_env& env, const napi_callback_info& cbInfo, RequestAsyncContext& asyncContext)
{
    size_t argc = REQUEST_PERMISSION_MAX_PARAMS;
    napi_value argv[REQUEST_PERMISSION_MAX_PARAMS] = { nullptr };
    napi_value thisVar = nullptr;

    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_get_cb_info failed");
        return false;
    }
    if (argc < REQUEST_PERMISSION_MAX_PARAMS - 1) {
        NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env,
            JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }
    asyncContext.env = env;
    std::string errMsg;

    // argv[0] : context : AbilityContext
    if (GetAbilityContext(env, argv[0], asyncContext.abilityContext) == nullptr) {
        errMsg = GetParamErrorMsg("context", "Ability Context");
        NAPI_CALL_BASE(
            env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    // argv[1] : permissionList
    if (!ParseStringArray(env, argv[1], asyncContext.permissionList) ||
        (asyncContext.permissionList.empty())) {
        errMsg = GetParamErrorMsg("permissions", "Array<string>");
        NAPI_CALL_BASE(
            env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "asyncContext.permissionList size: %{public}zu.", asyncContext.permissionList.size());

    if (argc == REQUEST_PERMISSION_MAX_PARAMS) {
        if (!ParseCallback(env, argv[2], asyncContext.callbackRef)) {    // argv[2] : callback
            errMsg = GetParamErrorMsg("callback", "Callback<PermissionRequestResult>");
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg));
            return false;
        }
    }

    return true;
}

static napi_value WrapRequestResult(const napi_env& env,
    const std::vector<std::string>& permissions, const std::vector<int>& grantResults)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));

    napi_value objPermissions;
    NAPI_CALL(env, napi_create_array(env, &objPermissions));
    for (size_t i = 0; i < permissions.size(); i++) {
        napi_value nPerm = nullptr;
        NAPI_CALL(env, napi_create_string_utf8(env, permissions[i].c_str(), NAPI_AUTO_LENGTH, &nPerm));
        NAPI_CALL(env, napi_set_element(env, objPermissions, i, nPerm));
    }
    NAPI_CALL(env, napi_set_named_property(env, result, "permissions", objPermissions));

    napi_value objGrantResults;
    NAPI_CALL(env, napi_create_array(env, &objGrantResults));
    for (size_t i = 0; i < grantResults.size(); i++) {
        napi_value nGrantResult = nullptr;
        NAPI_CALL(env, napi_create_int32(env, grantResults[i], &nGrantResult));
        NAPI_CALL(env, napi_set_element(env, objGrantResults, i, nGrantResult));
    }
    NAPI_CALL(env, napi_set_named_property(env, result, "authResults", objGrantResults));

    return result;
}

static void ResultCallbackJSThreadWorker(uv_work_t* work, int32_t status)
{
    (void)status;
    if (work == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "uv_queue_work input work is nullptr");
        return;
    }
    std::unique_ptr<uv_work_t> uvWorkPtr {work};
    ResultCallback *retCB = reinterpret_cast<ResultCallback*>(work->data);
    if (retCB == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "retCB is nullptr");
        return;
    }
    std::unique_ptr<ResultCallback> callbackPtr {retCB};

    RequestAsyncContext* context = reinterpret_cast<RequestAsyncContext*>(retCB->data);
    if (context == nullptr) {
        return;
    }
    std::unique_ptr<RequestAsyncContext> contextPtr {context};

    int32_t result = JsErrorCode::JS_OK;
    if (retCB->grantResults.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "grantResults empty");
        result = JsErrorCode::JS_ERROR_INNER;
    }
    napi_value requestResult = WrapRequestResult(context->env, retCB->permissions, retCB->grantResults);
    if (requestResult == nullptr) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "wrap requestResult failed");
        result = JsErrorCode::JS_ERROR_INNER;
    }

    if (context->deferred != nullptr) {
        ReturnPromiseResult(context->env, result,  context->deferred, requestResult);
    } else {
        ReturnCallbackResult(context->env, result, context->callbackRef, requestResult);
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "OnRequestPermissionsFromUser async callback is called end");
}

void AuthorizationResult::GrantResultsCallback(const std::vector<std::string>& permissions,
    const std::vector<int>& grantResults)
{
    ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s called.", __func__);
    auto* retCB = new (std::nothrow) ResultCallback();
    if (retCB == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "insufficient memory for work!");
        return;
    }
    std::unique_ptr<ResultCallback> callbackPtr {retCB};
    retCB->permissions = permissions;
    retCB->grantResults = grantResults;
    retCB->requestCode = requestCode_;
    retCB->data = data_;

    RequestAsyncContext* asyncContext = reinterpret_cast<RequestAsyncContext*>(data_);
    if (asyncContext == nullptr) {
        return;
    }
    std::unique_ptr<RequestAsyncContext> contextPtr {asyncContext};

    uv_loop_s* loop = nullptr;
    NAPI_CALL_RETURN_VOID(asyncContext->env, napi_get_uv_event_loop(asyncContext->env, &loop));
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
    work->data = reinterpret_cast<void *>(retCB);
    NAPI_CALL_RETURN_VOID(asyncContext->env,
        uv_queue_work(loop, work, [](uv_work_t* work) {}, ResultCallbackJSThreadWorker));

    uvWorkPtr.release();
    callbackPtr.release();
    contextPtr.release();
}

static void StartGrantExtension(sptr<IRemoteObject>& remoteObject, const std::vector<std::string>& permissions,
                                const std::shared_ptr<AbilityRuntime::AbilityContext>& context,
                                const std::vector<int32_t>& permissionsState, int32_t requestCode)
{
    AAFwk::Want want;
    want.SetElementName(GRANT_ABILITY_BUNDLE_NAME, GRANT_ABILITY_ABILITY_NAME);
    want.SetParam(PERMISSION_KEY, permissions);
    want.SetParam(STATE_KEY, permissionsState);
    want.SetParam(TOKEN_KEY, context->GetToken());
    want.SetParam(CALLBACK_KEY, remoteObject);

    int32_t err = context->StartAbility(want, requestCode);
    ACCESSTOKEN_LOG_DEBUG(LABEL, "End calling StartExtension. ret=%{public}d", err);
}

bool NapiAtManager::IsDynamicRequest(
    const std::vector<std::string>& permissions, std::vector<int32_t>& permissionsState)
{
    std::vector<PermissionListState> permList;
    for (const auto& permission : permissions) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "permission: %{public}s.", permission.c_str());
        PermissionListState permState;
        permState.permissionName = permission;
        permState.state = -1;
        permList.emplace_back(permState);
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "permList size: %{public}zu, permissions size: %{public}zu.",
        permList.size(), permissions.size());

    auto ret = AccessTokenKit::GetSelfPermissionsState(permList);

    for (const auto& permState : permList) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "permissions: %{public}s. permissionsState: %{public}u",
            permState.permissionName.c_str(), permState.state);
        permissionsState.emplace_back(permState.state);
    }
    if (permList.size() != permissions.size()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Returned permList size: %{public}zu.", permList.size());
        return false;
    }
    if (ret != TypePermissionOper::DYNAMIC_OPER) {
        return false;
    }

    return true;
}
void NapiAtManager::RequestPermissionsFromUserExecute(napi_env env, void* data)
{
    RequestAsyncContext* asyncContext = reinterpret_cast<RequestAsyncContext*>(data);

    auto applicationInfo = asyncContext->abilityContext->GetApplicationInfo();
    if (applicationInfo->accessTokenId != GetSelfTokenID()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "The context is not belong to the current application.");
        asyncContext->result = JsErrorCode::JS_ERROR_PARAM_INVALID;
        return;
    }

    if (!IsDynamicRequest(asyncContext->permissionList, asyncContext->permissionsState)) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "it does not need to request permission exsion");
        asyncContext->isResultCalled = false;
        return;
    }

    std::lock_guard<std::mutex> lock(g_lockForPermRequestCallbacks);
    curRequestCode_ = (curRequestCode_ == INT_MAX) ? 0 : (curRequestCode_ + 1);

    sptr<IRemoteObject> remoteObject = new (std::nothrow) AccessToken::AuthorizationResult(
        curRequestCode_, reinterpret_cast<void *>(asyncContext));
    if (remoteObject == nullptr) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "it does not need to request permission exsion");
        asyncContext->isResultCalled = false;
        asyncContext->result = JsErrorCode::JS_ERROR_INNER;
        return;
    }
    StartGrantExtension(remoteObject, asyncContext->permissionList, asyncContext->abilityContext,
        asyncContext->permissionsState, curRequestCode_);
}

void NapiAtManager::RequestPermissionsFromUserComplete(napi_env env, napi_status status, void* data)
{
    RequestAsyncContext* asyncContext = reinterpret_cast<RequestAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }
    std::unique_ptr<RequestAsyncContext> callbackPtr {asyncContext};

    if (asyncContext->isResultCalled) {
        callbackPtr.release();
        return;
    }
    if (asyncContext->permissionsState.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "grantResults empty");
        asyncContext->result = JsErrorCode::JS_ERROR_INNER;
    }
    napi_value requestResult = WrapRequestResult(
        env, asyncContext->permissionList, asyncContext->permissionsState);
    if (requestResult == nullptr) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "wrap requestResult failed");
        asyncContext->result = JsErrorCode::JS_ERROR_INNER;
    } else {
        asyncContext->requestResult = requestResult;
    }
    if (asyncContext->deferred != nullptr) {
        ReturnPromiseResult(env, asyncContext->result, asyncContext->deferred, asyncContext->requestResult);
    } else {
        ReturnCallbackResult(env, asyncContext->result, asyncContext->callbackRef, asyncContext->requestResult);
    }
}

napi_value NapiAtManager::RequestPermissionsFromUser(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "RequestPermissionsFromUser begin.");

    auto* asyncContext = new (std::nothrow) RequestAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    std::unique_ptr<RequestAsyncContext> callbackPtr {asyncContext};
    if (!ParseRequestPermissionFromUser(env, info, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (asyncContext->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr; // resource name
    NAPI_CALL(env, napi_create_string_utf8(env, "RequestPermissionsFromUser", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, RequestPermissionsFromUserExecute, RequestPermissionsFromUserComplete,
        reinterpret_cast<void *>(asyncContext), &(asyncContext->work)));

    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));

    ACCESSTOKEN_LOG_DEBUG(LABEL, "RequestPermissionsFromUser end.");
    callbackPtr.release();
    return result;
}

bool NapiAtManager::FillPermStateChangeInfo(const napi_env env, const napi_value* argv, const std::string& type,
    const napi_value thisVar, RegisterPermStateChangeInfo& registerPermStateChangeInfo)
{
    PermStateChangeScope scopeInfo;
    std::string errMsg;
    napi_ref callback = nullptr;

    // 1: the second parameter of argv
    if (!ParseAccessTokenIDArray(env, argv[1], scopeInfo.tokenIDs)) {
        errMsg = GetParamErrorMsg("tokenIDList", "Array<number>");
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg));
        return false;
    }
    // 2: the third parameter of argv
    if (!ParseStringArray(env, argv[2], scopeInfo.permList)) {
        errMsg = GetParamErrorMsg("tokenIDList", "Array<string>");
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg));
        return false;
    }
    // 3: the fourth parameter of argv
    if (!ParseCallback(env, argv[3], callback)) {
        errMsg = GetParamErrorMsg("tokenIDList", "Callback<PermissionStateChangeInfo>");
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg));
        return false;
    }
    std::sort(scopeInfo.tokenIDs.begin(), scopeInfo.tokenIDs.end());
    std::sort(scopeInfo.permList.begin(), scopeInfo.permList.end());
    registerPermStateChangeInfo.env = env;
    registerPermStateChangeInfo.callbackRef = callback;
    registerPermStateChangeInfo.permStateChangeType = type;
    registerPermStateChangeInfo.subscriber = std::make_shared<RegisterPermStateChangeScopePtr>(scopeInfo);
    registerPermStateChangeInfo.subscriber->SetEnv(env);
    registerPermStateChangeInfo.subscriber->SetCallbackRef(callback);
    std::shared_ptr<RegisterPermStateChangeScopePtr> *subscriber =
        new (std::nothrow) std::shared_ptr<RegisterPermStateChangeScopePtr>(
            registerPermStateChangeInfo.subscriber);
    if (subscriber == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "failed to create subscriber");
        return false;
    }
    napi_wrap(env, thisVar, reinterpret_cast<void*>(subscriber), [](napi_env nev, void *data, void *hint) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "RegisterPermStateChangeScopePtr delete");
        std::shared_ptr<RegisterPermStateChangeScopePtr>* subscriber =
            static_cast<std::shared_ptr<RegisterPermStateChangeScopePtr>*>(data);
        if (subscriber != nullptr && *subscriber != nullptr) {
            (*subscriber)->SetValid(false);
            delete subscriber;
        }
    }, nullptr, nullptr);

    return true;
}

bool NapiAtManager::ParseInputToRegister(const napi_env env, const napi_callback_info cbInfo,
    RegisterPermStateChangeInfo& registerPermStateChangeInfo)
{
    size_t argc = ON_OFF_MAX_PARAMS;
    napi_value argv[ON_OFF_MAX_PARAMS] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr), false);
    if (argc < ON_OFF_MAX_PARAMS) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return false;
    }
    if (thisVar == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "thisVar is nullptr");
        return false;
    }
    napi_valuetype valueTypeOfThis = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, thisVar, &valueTypeOfThis), false);
    if (valueTypeOfThis == napi_undefined) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "thisVar is undefined");
        return false;
    }
    // 0: the first parameter of argv
    std::string type;
    if (!ParseString(env, argv[0], type)) {
        std::string errMsg = GetParamErrorMsg("type", "string");
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg));
        return false;
    }
    if (!FillPermStateChangeInfo(env, argv, type, thisVar, registerPermStateChangeInfo)) {
        return false;
    }

    return true;
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
        std::string errMsg = GetErrorMessage(JsErrorCode::JS_ERROR_PARAM_INVALID);
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_INVALID, errMsg)));
        return nullptr;
    }
    int32_t result = AccessTokenKit::RegisterPermStateChangeCallback(registerPermStateChangeInfo->subscriber);
    if (result != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "RegisterPermStateChangeCallback failed");
        registerPermStateChangeInfo->errCode = result;
        std::string errMsg = GetErrorMessage(result);
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, result, errMsg)));
        return nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
        g_permStateChangeRegisters.emplace_back(registerPermStateChangeInfo);
        ACCESSTOKEN_LOG_DEBUG(LABEL, "add g_PermStateChangeRegisters.size = %{public}zu",
            g_permStateChangeRegisters.size());
    }
    callbackPtr.release();
    return nullptr;
}

bool NapiAtManager::ParseInputToUnregister(const napi_env env, napi_callback_info cbInfo,
    UnregisterPermStateChangeInfo& unregisterPermStateChangeInfo)
{
    size_t argc = ON_OFF_MAX_PARAMS;
    napi_value argv[ON_OFF_MAX_PARAMS] = {nullptr};
    napi_value thisVar = nullptr;
    napi_ref callback = nullptr;
    std::string errMsg;
    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_get_cb_info failed");
        return false;
    }
    // 1: off required minnum argc
    if (argc < ON_OFF_MAX_PARAMS - 1) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return false;
    }
    // 0: the first parameter of argv
    std::string type;
    if (!ParseString(env, argv[0], type)) {
        errMsg = GetParamErrorMsg("type", "permissionStateChange");
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg));
        return false;
    }
    PermStateChangeScope scopeInfo;
    // 1: the second parameter of argv
    if (!ParseAccessTokenIDArray(env, argv[1], scopeInfo.tokenIDs)) {
        errMsg = GetParamErrorMsg("tokenIDList", "Array<number>");
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg));
        return false;
    }
    // 2: the third parameter of argv
    if (!ParseStringArray(env, argv[2], scopeInfo.permList)) {
        errMsg = GetParamErrorMsg("permissionNameList", "Array<string>");
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg));
        return false;
    }
    if (argc == ON_OFF_MAX_PARAMS) {
        // 3: the fourth parameter of argv
        if (!ParseCallback(env, argv[3], callback)) {
            errMsg = GetParamErrorMsg("callback", "Callback<PermissionStateChangeInfo>");
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg));
            return false;
        }
    }

    std::sort(scopeInfo.tokenIDs.begin(), scopeInfo.tokenIDs.end());
    std::sort(scopeInfo.permList.begin(), scopeInfo.permList.end());
    unregisterPermStateChangeInfo.env = env;
    unregisterPermStateChangeInfo.callbackRef = callback;
    unregisterPermStateChangeInfo.permStateChangeType = type;
    unregisterPermStateChangeInfo.scopeInfo = scopeInfo;
    return true;
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
    if (!FindAndGetSubscriberInVector(unregisterPermStateChangeInfo)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Unsubscribe failed. The current subscriber does not exist");
        std::string errMsg = GetErrorMessage(JsErrorCode::JS_ERROR_PARAM_INVALID);
        NAPI_CALL(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_INVALID, errMsg)));
        return nullptr;
    }
    int32_t result = AccessTokenKit::UnRegisterPermStateChangeCallback(unregisterPermStateChangeInfo->subscriber);
    if (result == RET_SUCCESS) {
        DeleteRegisterInVector(unregisterPermStateChangeInfo->scopeInfo);
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UnregisterPermActiveChangeCompleted failed");
        std::string errMsg = GetErrorMessage(result);
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, result, errMsg)));
    }
    return nullptr;
}

bool NapiAtManager::FindAndGetSubscriberInVector(UnregisterPermStateChangeInfo* unregisterPermStateChangeInfo)
{
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    std::vector<AccessTokenID> targetTokenIDs = unregisterPermStateChangeInfo->scopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = unregisterPermStateChangeInfo->scopeInfo.permList;
    for (const auto& item : g_permStateChangeRegisters) {
        PermStateChangeScope scopeInfo;
        item->subscriber->GetScope(scopeInfo);
        if (scopeInfo.tokenIDs == targetTokenIDs && scopeInfo.permList == targetPermList) {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "find subscriber in map");
            unregisterPermStateChangeInfo->subscriber = item->subscriber;
            return true;
        }
    }
    return false;
}

bool NapiAtManager::IsExistRegister(const RegisterPermStateChangeInfo* registerPermStateChangeInfo)
{
    PermStateChangeScope targetScopeInfo;
    registerPermStateChangeInfo->subscriber->GetScope(targetScopeInfo);
    std::vector<AccessTokenID> targetTokenIDs = targetScopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = targetScopeInfo.permList;
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    for (const auto& item : g_permStateChangeRegisters) {
        PermStateChangeScope scopeInfo;
        item->subscriber->GetScope(scopeInfo);
        if (scopeInfo.tokenIDs == targetTokenIDs && scopeInfo.permList == targetPermList) {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "find subscriber in vector");
            return true;
        }
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "cannot find subscriber in vector");
    return false;
}

void NapiAtManager::DeleteRegisterInVector(const PermStateChangeScope& scopeInfo)
{
    std::vector<AccessTokenID> targetTokenIDs = scopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = scopeInfo.permList;
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    auto item = g_permStateChangeRegisters.begin();
    while (item != g_permStateChangeRegisters.end()) {
        PermStateChangeScope stateChangeScope;
        (*item)->subscriber->GetScope(stateChangeScope);
        if (stateChangeScope.tokenIDs == targetTokenIDs && stateChangeScope.permList == targetPermList) {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "Find subscribers in vector, delete");
            delete *item;
            *item = nullptr;
            g_permStateChangeRegisters.erase(item);
            break;
        } else {
            ++item;
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
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "abilityAccessCtrl",
    .nm_priv = ((void *)nullptr),
    .reserved = {nullptr}
};

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void AbilityAccessCtrlmoduleRegister(void)
{
    napi_module_register(&g_module);
}
