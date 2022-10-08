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

#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "napi/native_api.h"
#include "napi_error.h"
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
static constexpr int32_t VERIFY_OR_FLAG_INPUT_MAX_PARAMS = 2;
static constexpr int32_t GRANT_OR_REVOKE_INPUT_MAX_PARAMS = 4;
static constexpr int32_t ON_OFF_MAX_PARAMS = 4;
static constexpr int32_t MAX_LENGTH = 256;

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
        DECLARE_NAPI_FUNCTION("checkAccessTokenSync", CheckAccessTokenSync),
        DECLARE_NAPI_FUNCTION("getPermissionFlags", GetPermissionFlags),
        DECLARE_NAPI_FUNCTION("on", RegisterPermStateChangeCallback),
        DECLARE_NAPI_FUNCTION("off", UnregisterPermStateChangeCallback),
        DECLARE_NAPI_FUNCTION("getVersion", GetVersion),
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "objectInfo is nullptr");
        return nullptr;
    }

    std::unique_ptr<AccessTokenKit> objPtr {objectInfo};
    NAPI_CALL(env, napi_wrap(env, thisVar, objectInfo,
        [](napi_env env, void* data, void* hint) {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "delete accesstoken kit");
            if (data != nullptr) {
                AccessTokenKit* objectInfo = (AccessTokenKit*)data;
                delete objectInfo;
            }
        },
        nullptr, nullptr));
    objPtr.release();
    return thisVar;
}

napi_value NapiAtManager::CreateAtManager(napi_env env, napi_callback_info cbInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "enter CreateAtManager");

    napi_value instance = nullptr;
    napi_value cons = nullptr;

    NAPI_CALL(env, napi_get_reference_value(env, atManagerRef_, &cons));
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Get a reference to the global variable atManagerRef_ complete");

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
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
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
    if (asyncContext->tokenId == 0 || asyncContext->permissionName.empty() ||
        asyncContext->permissionName.length() > MAX_LENGTH) {
        asyncContext->errorCode = JsErrorCode::JS_ERROR_PARAM_INVALID;
        asyncContext->errorMessage = GetErrorMessage(asyncContext->errorCode);
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
    if (asyncContext->errorCode == 0) {
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->result, &result)); // verify result

        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred, result));
    } else {
        napi_value errorMessage = GenerateBusinessError(env, asyncContext->errorCode, asyncContext->errorMessage);
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncContext->deferred, errorMessage));
    }
}

napi_value NapiAtManager::VerifyAccessToken(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "VerifyAccessToken begin.");

    auto *asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
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
    NAPI_CALL(env, napi_create_string_utf8(env, "VerifyAccessToken", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
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
        std::string errMsg = GetParamErrorMsg("tokenID", "number");
        asyncContext->errorCode = JS_ERROR_PARAM_INVALID;
        asyncContext->errorMessage = errMsg;
        return;
    }
    if (asyncContext->permissionName.empty() || (asyncContext->permissionName.length() > MAX_LENGTH)) {
        std::string errMsg = GetParamErrorMsg("permissionName", "string");
        asyncContext->errorCode = JS_ERROR_PARAM_INVALID;
        asyncContext->errorMessage = errMsg;
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

    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenId = %{public}d, permissionName = %{public}s, verify result = %{public}d.",
        asyncContext->tokenId, asyncContext->permissionName.c_str(), asyncContext->result);

    if (asyncContext->errorCode != 0) {
        napi_value errorMessage = GenerateBusinessError(env, asyncContext->errorCode, asyncContext->errorMessage);
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncContext->deferred, errorMessage));
    } else {
        napi_value result;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->result, &result));
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred, result));
    }
}

napi_value NapiAtManager::CheckAccessToken(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "CheckAccessToken begin.");

    auto *asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
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

napi_value NapiAtManager::CheckAccessTokenSync(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "CheckAccessTokenSync begin.");

    auto *asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
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
    asyncContext->result = AccessTokenKit::VerifyAccessToken(asyncContext->tokenId,
        asyncContext->permissionName);

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, asyncContext->result, &result));

    ACCESSTOKEN_LOG_DEBUG(LABEL, "CheckAccessTokenSync end.");
    return result;
}

napi_value NapiAtManager::VerifyAccessTokenSync(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "VerifyAccessTokenSync begin.");

    auto *asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
        return nullptr;
    }

    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    if (!ParseInputVerifyPermissionOrGetFlag(env, info, *asyncContext)) {
        return nullptr;
    }
    if (asyncContext->tokenId == 0 || asyncContext->permissionName.empty() ||
        asyncContext->permissionName.length() > MAX_LENGTH) {
        asyncContext->errorCode = JsErrorCode::JS_ERROR_PARAM_INVALID;
        asyncContext->errorMessage = GetErrorMessage(asyncContext->errorCode);
        NAPI_CALL(env, napi_throw(env,
            GenerateBusinessError(env, asyncContext->errorCode, asyncContext->errorMessage)));
        return nullptr;
    }

    asyncContext->result = AccessTokenKit::VerifyAccessToken(asyncContext->tokenId,
        asyncContext->permissionName);

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, asyncContext->result, &result));

    ACCESSTOKEN_LOG_DEBUG(LABEL, "VerifyAccessTokenSync end.");
    return result;
}

bool NapiAtManager::ParseInputGrantOrRevokePermission(const napi_env env, const napi_callback_info info,
    AtManagerAsyncContext& asyncContext)
{
    size_t argc = GRANT_OR_REVOKE_INPUT_MAX_PARAMS;
    napi_value argv[GRANT_OR_REVOKE_INPUT_MAX_PARAMS] = {nullptr};
    napi_value thisVar = nullptr;

    void *data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
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
    napi_value results[ASYNC_CALL_BACK_VALUES_NUM] = {nullptr}; 

    std::unique_ptr<AtManagerAsyncContext> callbackPtr {asyncContext};
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->result, &results[ASYNC_CALL_BACK_VALUES_NUM - 1]));

    if (asyncContext->deferred != nullptr) {
        if (asyncContext->result == RET_SUCCESS) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(
                env, asyncContext->deferred, results[ASYNC_CALL_BACK_VALUES_NUM - 1])); // 1: success result index
        } else {
            results[ASYNC_CALL_BACK_VALUES_NUM - 2] =
                GenerateBusinessError(env, asyncContext->result, GetErrorMessage(asyncContext->result)); // 2: reject result index
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncContext->deferred,
                results[ASYNC_CALL_BACK_VALUES_NUM - 2])); // 2: reject result index
        }
    } else {
        napi_value callback = nullptr;
        napi_value thisValue = nullptr;
        napi_value thatValue = nullptr;
        CreateNapiRetMsg(env, asyncContext->result, results);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &thisValue));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 0, &thatValue));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef, &callback));
        NAPI_CALL_RETURN_VOID(env,
            napi_call_function(env, thisValue, callback, ASYNC_CALL_BACK_VALUES_NUM, results, &thatValue));
    }
}

napi_value NapiAtManager::GetVersion(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetVersion begin.");

    auto *asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
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

    auto *asyncContext = new (std::nothrow) AtManagerAsyncContext(env); // for async work deliver data
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
    napi_value results[ASYNC_CALL_BACK_VALUES_NUM] = {nullptr}; // for AsyncCallback <err, data>

    std::unique_ptr<AtManagerAsyncContext> callbackPtr {asyncContext};
    // 1: success result index
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->result, &results[ASYNC_CALL_BACK_VALUES_NUM - 1]));

    if (asyncContext->deferred != nullptr) {
        if (asyncContext->result == RET_SUCCESS) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred,
                results[ASYNC_CALL_BACK_VALUES_NUM - 1])); // 1: success result index
        } else {
            // 2: reject result index
            results[ASYNC_CALL_BACK_VALUES_NUM - 2] =
                GenerateBusinessError(env, asyncContext->result, GetErrorMessage(asyncContext->result));
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncContext->deferred,
                results[ASYNC_CALL_BACK_VALUES_NUM - 2])); // 2: reject result index
        }
    } else {
        napi_value callback = nullptr;
        napi_value thisValue = nullptr;
        napi_value thatValue = nullptr;
        CreateNapiRetMsg(env, asyncContext->result, results);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &thisValue));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 0, &thatValue));
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncContext->callbackRef, &callback));
        NAPI_CALL_RETURN_VOID(env,
            napi_call_function(env, thisValue, callback, ASYNC_CALL_BACK_VALUES_NUM, results, &thatValue));
    }
}

napi_value NapiAtManager::RevokeUserGrantedPermission(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "RevokeUserGrantedPermission begin.");

    auto *asyncContext = new (std::nothrow) AtManagerAsyncContext(env); // for async work deliver data
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
    napi_value result = nullptr;

    ACCESSTOKEN_LOG_DEBUG(LABEL, "permissionName = %{public}s, tokenId = %{public}d, flag = %{public}d.",
        asyncContext->permissionName.c_str(), asyncContext->tokenId, asyncContext->flag);

    std::unique_ptr<AtManagerAsyncContext> callbackPtr {asyncContext};
    if (asyncContext->result == RET_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->flag, &result));
        NAPI_CALL_RETURN_VOID(
            env, napi_resolve_deferred(env, asyncContext->deferred, result));
    } else {
        result = GenerateBusinessError(env, asyncContext->result, GetErrorMessage(asyncContext->result));
        NAPI_CALL_RETURN_VOID(
            env, napi_reject_deferred(env, asyncContext->deferred, result));
    }
}

napi_value NapiAtManager::GetPermissionFlags(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetPermissionFlags begin.");

    auto *asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
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

bool NapiAtManager::ParseInputToRegister(const napi_env env, const napi_callback_info cbInfo,
    RegisterPermStateChangeInfo& registerPermStateChangeInfo)
{
    size_t argc = ON_OFF_MAX_PARAMS;
    napi_value argv[ON_OFF_MAX_PARAMS] = {nullptr};
    napi_value thisVar = nullptr;
    napi_ref callback = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL), false);
    if (argc < ON_OFF_MAX_PARAMS) {
        NAPI_CALL_BASE(env, napi_throw(env,
            GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }
    // 0: the first parameter of argv
    std::string type;
    std::string errMsg;
    if (!ParseString(env, argv[0], type)) {
        errMsg = GetParamErrorMsg("type", "string");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    PermStateChangeScope scopeInfo;
    // 1: the second parameter of argv
    if (!ParseAccessTokenIDArray(env, argv[1], scopeInfo.tokenIDs)) {
        errMsg = GetParamErrorMsg("tokenIDList", "Array<number>");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    // 2: the third parameter of argv
    if (!ParseStringArray(env, argv[2], scopeInfo.permList)) {
        errMsg = GetParamErrorMsg("tokenIDList", "Array<string>");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    // 3: the fourth parameter of argv
    if (!ParseCallback(env, argv[3], callback)) {
        errMsg = GetParamErrorMsg("tokenIDList", "Callback<PermissionStateChangeInfo>");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    AccessTokenKit* accessTokenKitInfo = nullptr;
    if (napi_unwrap(env, thisVar, reinterpret_cast<void **>(&accessTokenKitInfo)) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_unwrap failed");
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
    registerPermStateChangeInfo.accessTokenKit = accessTokenKitInfo;
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
        g_permStateChangeRegisters[registerPermStateChangeInfo->accessTokenKit].emplace_back(
            registerPermStateChangeInfo);
        ACCESSTOKEN_LOG_DEBUG(LABEL, "add g_PermStateChangeRegisters->second.size = %{public}zu",
            g_permStateChangeRegisters[registerPermStateChangeInfo->accessTokenKit].size());
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
    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, NULL) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_get_cb_info failed");
        return false;
    }
    //1: off required minnum argc
    if (argc < ON_OFF_MAX_PARAMS - 1) {
        NAPI_CALL_BASE(env, napi_throw(env,
            GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }
    // 0: the first parameter of argv
    std::string type;
    if (!ParseString(env, argv[0], type)) {
        errMsg = GetParamErrorMsg("type", "permissionStateChange");
        NAPI_CALL_BASE(env, napi_throw(env,
            GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    PermStateChangeScope scopeInfo;
    // 1: the second parameter of argv
    if (!ParseAccessTokenIDArray(env, argv[1], scopeInfo.tokenIDs)) {
        errMsg = GetParamErrorMsg("tokenIDList", "Array<number>");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    // 2: the third parameter of argv
    if (!ParseStringArray(env, argv[2], scopeInfo.permList)) {
        errMsg = GetParamErrorMsg("permissionNameList", "Array<string>");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    if (argc == ON_OFF_MAX_PARAMS) {
        // 3: the fourth parameter of argv
        if (!ParseCallback(env, argv[3], callback)) {
            errMsg = GetParamErrorMsg("callback", "Callback<PermissionStateChangeInfo>");
            NAPI_CALL_BASE(env,
                napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
            return false;
        }
    }
    AccessTokenKit* accessTokenKitInfo = nullptr;
    NAPI_CALL_BASE(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(&accessTokenKitInfo)), false);
    std::sort(scopeInfo.tokenIDs.begin(), scopeInfo.tokenIDs.end());
    std::sort(scopeInfo.permList.begin(), scopeInfo.permList.end());
    unregisterPermStateChangeInfo.env = env;
    unregisterPermStateChangeInfo.callbackRef = callback;
    unregisterPermStateChangeInfo.permStateChangeType = type;
    unregisterPermStateChangeInfo.scopeInfo = scopeInfo;
    unregisterPermStateChangeInfo.accessTokenKit = accessTokenKitInfo;
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
    if (!FindAndGetSubscriberInMap(unregisterPermStateChangeInfo)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Unsubscribe failed. The current subscriber does not exist");
        std::string errMsg = GetErrorMessage(JsErrorCode::JS_ERROR_PARAM_INVALID);
        NAPI_CALL(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_INVALID, errMsg)));
        return nullptr;
    }
    int32_t result = AccessTokenKit::UnRegisterPermStateChangeCallback(unregisterPermStateChangeInfo->subscriber);
    if (result == RET_SUCCESS) {
        DeleteRegisterInMap(unregisterPermStateChangeInfo->accessTokenKit, unregisterPermStateChangeInfo->scopeInfo);
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UnregisterPermActiveChangeCompleted failed");
        std::string errMsg = GetErrorMessage(result);
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, result, errMsg)));
    }
    return nullptr;
}

bool NapiAtManager::FindAndGetSubscriberInMap(UnregisterPermStateChangeInfo* unregisterPermStateChangeInfo)
{
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    std::vector<AccessTokenID> targetTokenIDs = unregisterPermStateChangeInfo->scopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = unregisterPermStateChangeInfo->scopeInfo.permList;
    auto registerInstance = g_permStateChangeRegisters.find(unregisterPermStateChangeInfo->accessTokenKit);
    if (registerInstance != g_permStateChangeRegisters.end()) {
        for (const auto& item : registerInstance->second) {
            PermStateChangeScope scopeInfo;
            item->subscriber->GetScope(scopeInfo);
            if (scopeInfo.tokenIDs == targetTokenIDs && scopeInfo.permList == targetPermList) {
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
    PermStateChangeScope targetScopeInfo;
    registerPermStateChangeInfo->subscriber->GetScope(targetScopeInfo);
    std::vector<AccessTokenID> targetTokenIDs = targetScopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = targetScopeInfo.permList;
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    auto registerInstance = g_permStateChangeRegisters.find(registerPermStateChangeInfo->accessTokenKit);
    if (registerInstance != g_permStateChangeRegisters.end()) {
        for (const auto& item : registerInstance->second) {
            PermStateChangeScope scopeInfo;
            item->subscriber->GetScope(scopeInfo);
            if (scopeInfo.tokenIDs == targetTokenIDs && scopeInfo.permList == targetPermList) {
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
    std::vector<AccessTokenID> targetTokenIDs = scopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = scopeInfo.permList;
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    auto subscribers = g_permStateChangeRegisters.find(accessTokenKit);
    if (subscribers != g_permStateChangeRegisters.end()) {
        auto it = subscribers->second.begin();
        while (it != subscribers->second.end()) {
            if (scopeInfo.tokenIDs == targetTokenIDs && scopeInfo.permList == targetPermList) {
                ACCESSTOKEN_LOG_DEBUG(LABEL, "Find subscribers in map, delete");
                delete *it;
                *it = nullptr;
                subscribers->second.erase(it);
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
