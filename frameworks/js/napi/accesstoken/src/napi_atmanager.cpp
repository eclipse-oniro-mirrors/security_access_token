/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "access_token.h"
#include "data_validator.h"
#include "hisysevent.h"
#include "napi_hisysevent_adapter.h"
#include "napi_open_permission_on_setting.h"
#include "napi_request_global_switch_on_setting.h"
#include "napi_request_permission.h"
#include "napi_request_permission_on_setting.h"
#include "parameter.h"
#include "permission_map.h"
#include "token_setproc.h"
#include "want.h"
#include "accesstoken_common_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::mutex g_lockForPermStateChangeRegisters;
std::vector<RegisterPermStateChangeInfo*> g_permStateChangeRegisters;
std::mutex g_lockCache;
std::map<std::string, GrantStatusCache> g_cache;
std::mutex g_lockStatusCache;
std::map<std::string, PermissionStatusCache> g_statusCache;
static PermissionParamCache g_paramCache;
static PermissionParamCache g_paramFlagCache;
static std::atomic<int32_t> g_cnt = 0;
constexpr uint32_t REPORT_CNT = 10;
constexpr int32_t MAX_LENGTH = 256;
namespace {
static const char* PERMISSION_STATUS_CHANGE_KEY = "accesstoken.permission.change";
static const char* PERMISSION_STATUS_FLAG_CHANGE_KEY = "accesstoken.permission.flagchange";
static const char* REGISTER_PERMISSION_STATE_CHANGE_TYPE = "permissionStateChange";
static const char* REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE = "selfPermissionStateChange";
constexpr uint32_t THIRD_PARAM = 2;
constexpr uint32_t FORTH_PARAM = 3;

static void ReturnPromiseResult(napi_env env, const AtManagerAsyncContext& context, napi_value result)
{
    if (context.errorCode != RET_SUCCESS) {
        int32_t jsCode = GetJsErrorCode(context.errorCode);
        napi_value businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode, context.extErrorMsg));
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, context.deferred, businessError));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, context.deferred, result));
    }
}

static void ReturnCallbackResult(napi_env env, const AtManagerAsyncContext& context, napi_value result)
{
    napi_value businessError = GetNapiNull(env);
    if (context.errorCode != RET_SUCCESS) {
        int32_t jsCode = GetJsErrorCode(context.errorCode);
        businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode, context.extErrorMsg));
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

static bool ConvertPermStateChangeInfo(napi_env env, napi_value value, const PermStateChangeInfo& result)
{
    napi_value element;
    NAPI_CALL_BASE(env, napi_create_int32(env, result.permStateChangeType, &element), false);
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

static void NotifyPermStateChanged(RegisterPermStateChangeWorker* registerPermStateChangeData)
{
    napi_value result = { nullptr };
    NAPI_CALL_RETURN_VOID(registerPermStateChangeData->env,
        napi_create_object(registerPermStateChangeData->env, &result));
    if (!ConvertPermStateChangeInfo(registerPermStateChangeData->env,
        result, registerPermStateChangeData->result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ConvertPermStateChangeInfo failed");
        return;
    }

    napi_value undefined = nullptr;
    napi_value callback = nullptr;
    napi_value resultOut = nullptr;
    NAPI_CALL_RETURN_VOID(registerPermStateChangeData->env,
        napi_get_undefined(registerPermStateChangeData->env, &undefined));
    NAPI_CALL_RETURN_VOID(registerPermStateChangeData->env,
        napi_get_reference_value(registerPermStateChangeData->env, registerPermStateChangeData->ref, &callback));
    NAPI_CALL_RETURN_VOID(registerPermStateChangeData->env,
        napi_call_function(registerPermStateChangeData->env, undefined, callback, 1, &result, &resultOut));
}

static bool IsPermissionFlagValid(uint32_t flag)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Permission flag is %{public}d", flag);
    return (flag == PermissionFlag::PERMISSION_USER_SET) || (flag == PermissionFlag::PERMISSION_USER_FIXED) ||
        (flag == PermissionFlag::PERMISSION_ALLOW_THIS_TIME);
};
} // namespace

RegisterPermStateChangeScopePtr::RegisterPermStateChangeScopePtr(const PermStateChangeScope& subscribeInfo)
    : PermStateChangeCallbackCustomize(subscribeInfo)
{}

RegisterPermStateChangeScopePtr::~RegisterPermStateChangeScopePtr()
{
    if (ref_ == nullptr) {
        return;
    }
    DeleteNapiRef();
}

void RegisterPermStateChangeScopePtr::PermStateChangeCallback(PermStateChangeInfo& result)
{
    std::lock_guard<std::mutex> lock(validMutex_);
    if (!valid_) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Object is invalid.");
        return;
    }
    RegisterPermStateChangeWorker* registerPermStateChangeWorker = new (std::nothrow) RegisterPermStateChangeWorker();
    if (registerPermStateChangeWorker == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Insufficient memory for RegisterPermStateChangeWorker!");
        return;
    }
    std::unique_ptr<RegisterPermStateChangeWorker> workPtr {registerPermStateChangeWorker};
    registerPermStateChangeWorker->env = env_;
    registerPermStateChangeWorker->ref = ref_;
    registerPermStateChangeWorker->result = result;
    auto task = [registerPermStateChangeWorker]() {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(registerPermStateChangeWorker->env, &scope);
        if (scope == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Fail to open scope");
            delete registerPermStateChangeWorker;
            return;
        }
        NotifyPermStateChanged(registerPermStateChangeWorker);
        napi_close_handle_scope(registerPermStateChangeWorker->env, scope);
        delete registerPermStateChangeWorker;
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_high, "PermStateChangeCallback")) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermStateChangeCallback: Failed to SendEvent");
    } else {
        workPtr.release();
    }
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
{}

void RegisterPermStateChangeScopePtr::DeleteNapiRef()
{
    RegisterPermStateChangeWorker* registerPermStateChangeWorker = new (std::nothrow) RegisterPermStateChangeWorker();
    if (registerPermStateChangeWorker == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Insufficient memory for RegisterPermStateChangeWorker!");
        return;
    }
    std::unique_ptr<RegisterPermStateChangeWorker> workPtr {registerPermStateChangeWorker};
    registerPermStateChangeWorker->env = env_;
    registerPermStateChangeWorker->ref = ref_;
    auto task = [registerPermStateChangeWorker]() {
        napi_delete_reference(registerPermStateChangeWorker->env, registerPermStateChangeWorker->ref);
        delete registerPermStateChangeWorker;
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_high, "DeleteNapiRefForPermStateChange")) {
        LOGE(ATM_DOMAIN, ATM_TAG, "DeleteNapiRef: Failed to SendEvent");
    } else {
        workPtr.release();
    }
}

void NapiAtManager::SetNamedProperty(napi_env env, napi_value dstObj, const int32_t objValue, const char* propName)
{
    napi_value prop = nullptr;
    napi_create_int32(env, objValue, &prop);
    napi_set_named_property(env, dstObj, propName, prop);
}

napi_value NapiAtManager::Init(napi_env env, napi_value exports)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Enter init.");

    napi_property_descriptor descriptor[] = { DECLARE_NAPI_FUNCTION("createAtManager", CreateAtManager) };

    NAPI_CALL(env, napi_define_properties(env,
        exports, sizeof(descriptor) / sizeof(napi_property_descriptor), descriptor));

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("verifyAccessToken", VerifyAccessToken),
        DECLARE_NAPI_FUNCTION("verifyAccessTokenSync", VerifyAccessTokenSync),
        DECLARE_NAPI_FUNCTION("grantUserGrantedPermission", GrantUserGrantedPermission),
        DECLARE_NAPI_FUNCTION("revokeUserGrantedPermission", RevokeUserGrantedPermission),
        DECLARE_NAPI_FUNCTION("grantPermission", GrantPermission),
        DECLARE_NAPI_FUNCTION("revokePermission", RevokePermission),
        DECLARE_NAPI_FUNCTION("checkAccessToken", CheckAccessToken),
        DECLARE_NAPI_FUNCTION("checkAccessTokenSync", VerifyAccessTokenSync),
        DECLARE_NAPI_FUNCTION("getPermissionFlags", GetPermissionFlags),
        DECLARE_NAPI_FUNCTION("on", RegisterPermStateChangeCallback),
        DECLARE_NAPI_FUNCTION("off", UnregisterPermStateChangeCallback),
        DECLARE_NAPI_FUNCTION("getVersion", GetVersion),
        DECLARE_NAPI_FUNCTION("setPermissionRequestToggleStatus", SetPermissionRequestToggleStatus),
        DECLARE_NAPI_FUNCTION("getPermissionRequestToggleStatus", GetPermissionRequestToggleStatus),
        DECLARE_NAPI_FUNCTION("requestPermissionsFromUser", NapiRequestPermission::RequestPermissionsFromUser),
        DECLARE_NAPI_FUNCTION("getPermissionsStatus", NapiRequestPermission::GetPermissionsStatus),
        DECLARE_NAPI_FUNCTION("requestPermissionOnSetting", NapiRequestPermissionOnSetting::RequestPermissionOnSetting),
        DECLARE_NAPI_FUNCTION("requestGlobalSwitch", NapiRequestGlobalSwitch::RequestGlobalSwitch),
        DECLARE_NAPI_FUNCTION("requestPermissionOnApplicationSetting", RequestAppPermOnSetting),
        DECLARE_NAPI_FUNCTION("getSelfPermissionStatus", GetSelfPermissionStatusSync),
        DECLARE_NAPI_FUNCTION("openPermissionOnSetting", NapiOpenPermissionOnSetting::OpenPermissionOnSetting),
    };

    napi_value cons = nullptr;
    NAPI_CALL(env, napi_define_class(env, ATMANAGER_CLASS_NAME.c_str(), ATMANAGER_CLASS_NAME.size(),
        JsConstructor, nullptr, sizeof(properties) / sizeof(napi_property_descriptor), properties, &cons));

    NAPI_CALL(env, napi_create_reference(env, cons, 1, &g_atManagerRef_));
    NAPI_CALL(env, napi_set_named_property(env, exports, ATMANAGER_CLASS_NAME.c_str(), cons));

    CreateObjects(env, exports);

    return exports;
}

void NapiAtManager::CreateObjects(napi_env env, napi_value exports)
{
    napi_value grantStatus = nullptr;
    napi_create_object(env, &grantStatus);
    SetNamedProperty(env, grantStatus, PERMISSION_DENIED, "PERMISSION_DENIED");
    SetNamedProperty(env, grantStatus, PERMISSION_GRANTED, "PERMISSION_GRANTED");

    napi_value permStateChangeType = nullptr;
    napi_create_object(env, &permStateChangeType);
    SetNamedProperty(env, permStateChangeType, PERMISSION_REVOKED_OPER, "PERMISSION_REVOKED_OPER");
    SetNamedProperty(env, permStateChangeType, PERMISSION_GRANTED_OPER, "PERMISSION_GRANTED_OPER");

    napi_value permissionStatus = nullptr;
    napi_create_object(env, &permissionStatus);
    SetNamedProperty(env, permissionStatus, SETTING_OPER, "DENIED");
    SetNamedProperty(env, permissionStatus, PASS_OPER, "GRANTED");
    SetNamedProperty(env, permissionStatus, DYNAMIC_OPER, "NOT_DETERMINED");
    SetNamedProperty(env, permissionStatus, INVALID_OPER, "INVALID");
    SetNamedProperty(env, permissionStatus, FORBIDDEN_OPER, "RESTRICTED");

    napi_value permissionRequestToggleStatus = nullptr;
    napi_create_object(env, &permissionRequestToggleStatus);
    SetNamedProperty(env, permissionRequestToggleStatus, CLOSED, "CLOSED");
    SetNamedProperty(env, permissionRequestToggleStatus, OPEN, "OPEN");

    napi_value globalSwitchType = nullptr;
    napi_create_object(env, &globalSwitchType);
    SetNamedProperty(env, globalSwitchType, CAMERA, "CAMERA");
    SetNamedProperty(env, globalSwitchType, MICROPHONE, "MICROPHONE");
    SetNamedProperty(env, globalSwitchType, LOCATION, "LOCATION");

    napi_value selectedResult = nullptr;
    napi_create_object(env, &selectedResult);
    SetNamedProperty(env, selectedResult, SELECTED_REJECTED, "REJECTED");
    SetNamedProperty(env, selectedResult, SELECTED_OPENED, "OPENED");
    SetNamedProperty(env, selectedResult, SELECTED_GRANTED, "GRANTED");

    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_PROPERTY("GrantStatus", grantStatus),
        DECLARE_NAPI_PROPERTY("PermissionStateChangeType", permStateChangeType),
        DECLARE_NAPI_PROPERTY("PermissionStatus", permissionStatus),
        DECLARE_NAPI_PROPERTY("PermissionRequestToggleStatus", permissionRequestToggleStatus),
        DECLARE_NAPI_PROPERTY("SwitchType", globalSwitchType),
        DECLARE_NAPI_PROPERTY("SelectedResult", selectedResult),
    };
    napi_define_properties(env, exports, sizeof(exportFuncs) / sizeof(*exportFuncs), exportFuncs);
}

napi_value NapiAtManager::JsConstructor(napi_env env, napi_callback_info cbinfo)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Enter JsConstructor");

    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, cbinfo, nullptr, nullptr, &thisVar, nullptr));
    return thisVar;
}

napi_value NapiAtManager::CreateAtManager(napi_env env, napi_callback_info cbInfo)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Enter CreateAtManager");

    napi_value instance = nullptr;
    napi_value cons = nullptr;

    NAPI_CALL(env, napi_get_reference_value(env, g_atManagerRef_, &cons));
    LOGD(ATM_DOMAIN, ATM_TAG, "Get a reference to the global variable g_atManagerRef_ complete");

    NAPI_CALL(env, napi_new_instance(env, cons, 0, nullptr, &instance));

    LOGD(ATM_DOMAIN, ATM_TAG, "New the js instance complete");

    return instance;
}

bool NapiAtManager::ParseInputVerifyPermissionOrGetFlag(const napi_env env, const napi_callback_info info,
    AtManagerAsyncContext& asyncContext)
{
    size_t argc = MAX_PARAMS_TWO;

    napi_value argv[MAX_PARAMS_TWO] = { nullptr };
    napi_value thisVar = nullptr;
    std::string errMsg;
    void* data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
    if (argc < MAX_PARAMS_TWO) {
        NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env,
            JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }
    asyncContext.env = env;
    // 0: the first parameter of argv
    if (!ParseUint32(env, argv[0], asyncContext.tokenId)) {
        errMsg = GetParamErrorMsg("tokenID", "number");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    // 1: the second parameter of argv
    if (!ParseString(env, argv[1], asyncContext.permissionName)) {
        errMsg = GetParamErrorMsg("permissionName", "Permissions");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID = %{public}d, permissionName = %{public}s", asyncContext.tokenId,
        asyncContext.permissionName.c_str());
    return true;
}

bool NapiAtManager::ParseInputVerifyPermissionSync(const napi_env env, const napi_callback_info info,
    AtManagerSyncContext& syncContext)
{
    size_t argc = MAX_PARAMS_TWO;

    napi_value argv[MAX_PARAMS_TWO] = { nullptr };
    napi_value thisVar = nullptr;
    std::string errMsg;
    void* data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
    if (argc < MAX_PARAMS_TWO) {
        NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env,
            JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }
    syncContext.env = env;
    // 0: the first parameter of argv
    if (!ParseUint32(env, argv[0], syncContext.tokenId)) {
        errMsg = GetParamErrorMsg("tokenID", "number");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    // 1: the second parameter of argv
    if (!ParseString(env, argv[1], syncContext.permissionName)) {
        errMsg = GetParamErrorMsg("permissionName", "Permissions");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID = %{public}d, permissionName = %{public}s", syncContext.tokenId,
        syncContext.permissionName.c_str());
    return true;
}

void NapiAtManager::VerifyAccessTokenExecute(napi_env env, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }
    AccessTokenIDEx selfTokenIdEx = {GetSelfTokenID()};
    if (!AccessTokenKit::IsSystemAppByFullTokenID(static_cast<uint64_t>(selfTokenIdEx.tokenIDEx)) &&
        asyncContext->tokenId != selfTokenIdEx.tokenIdExStruct.tokenID) {
        int32_t cnt = g_cnt.fetch_add(1);
        if (cnt % REPORT_CNT == 0) {
            (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "VERIFY_ACCESS_TOKEN_EVENT",
                HiviewDFX::HiSysEvent::EventType::STATISTIC, "EVENT_CODE", VERIFY_TOKENID_INCONSISTENCY,
                "SELF_TOKENID", selfTokenIdEx.tokenIdExStruct.tokenID, "CONTEXT_TOKENID", asyncContext->tokenId);
        }
    }
    asyncContext->result = AccessTokenKit::VerifyAccessToken(asyncContext->tokenId, asyncContext->permissionName);
}

void NapiAtManager::VerifyAccessTokenComplete(napi_env env, napi_status status, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return;
    }
    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    napi_value result;

    LOGD(ATM_DOMAIN, ATM_TAG, "TokenId = %{public}d, permissionName = %{public}s, verify result = %{public}d.",
        asyncContext->tokenId, asyncContext->permissionName.c_str(), asyncContext->result);

    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->result, &result)); // verify result
    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncContext->deferred, result));
}

napi_value NapiAtManager::VerifyAccessToken(napi_env env, napi_callback_info info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "VerifyAccessToken begin.");

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New struct failed.");
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
        reinterpret_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));

    LOGD(ATM_DOMAIN, ATM_TAG, "VerifyAccessToken end.");
    context.release();
    return result;
}

void NapiAtManager::CheckAccessTokenExecute(napi_env env, void* data)
{
    if (data == nullptr) {
        return;
    }
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }
    if (asyncContext->tokenId == 0) {
        asyncContext->errorCode = JS_ERROR_PARAM_INVALID;
        asyncContext->extErrorMsg = "The tokenID is 0.";
        return;
    }
    if ((asyncContext->permissionName.empty()) ||
        ((asyncContext->permissionName.length() > MAX_LENGTH))) {
        asyncContext->errorCode = JS_ERROR_PARAM_INVALID;
        asyncContext->extErrorMsg = "The permission name is empty or exceeds 256 characters.";
        return;
    }
    AccessTokenIDEx selfTokenIdEx = {GetSelfTokenID()};
    if (!AccessTokenKit::IsSystemAppByFullTokenID(static_cast<uint64_t>(selfTokenIdEx.tokenIDEx)) &&
        asyncContext->tokenId != selfTokenIdEx.tokenIdExStruct.tokenID) {
        int32_t cnt = g_cnt.fetch_add(1);
        if (cnt % REPORT_CNT == 0) {
            (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "VERIFY_ACCESS_TOKEN_EVENT",
                HiviewDFX::HiSysEvent::EventType::STATISTIC, "EVENT_CODE", VERIFY_TOKENID_INCONSISTENCY,
                "SELF_TOKENID", selfTokenIdEx.tokenIdExStruct.tokenID, "CONTEXT_TOKENID", asyncContext->tokenId);
        }
    }

    asyncContext->result = AccessTokenKit::VerifyAccessToken(asyncContext->tokenId,
        asyncContext->permissionName);
}

void NapiAtManager::CheckAccessTokenComplete(napi_env env, napi_status status, void* data)
    __attribute__((no_sanitize("cfi")))
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return;
    }
    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->result, &result));
    ReturnPromiseResult(env, *asyncContext, result);
}

napi_value NapiAtManager::CheckAccessToken(napi_env env, napi_callback_info info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "CheckAccessToken begin.");

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New struct fail.");
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
        reinterpret_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));

    LOGD(ATM_DOMAIN, ATM_TAG, "CheckAccessToken end.");
    context.release();
    return result;
}

std::string NapiAtManager::GetPermParamValue(PermissionParamCache& paramCache, const char* paramKey)
{
    long long sysCommitId = GetSystemCommitId();
    if (sysCommitId == paramCache.sysCommitIdCache) {
        LOGD(ATM_DOMAIN, ATM_TAG, "SysCommitId = %{public}lld", sysCommitId);
        return paramCache.sysParamCache;
    }
    paramCache.sysCommitIdCache = sysCommitId;
    if (paramCache.handle == PARAM_DEFAULT_VALUE) {
        int32_t handle = static_cast<int32_t>(FindParameter(paramKey));
        if (handle == PARAM_DEFAULT_VALUE) {
            LOGE(ATM_DOMAIN, ATM_TAG, "FindParameter failed");
            return "-1";
        }
        paramCache.handle = handle;
    }

    int32_t currCommitId = static_cast<int32_t>(GetParameterCommitId(paramCache.handle));
    if (currCommitId != paramCache.commitIdCache) {
        char value[VALUE_MAX_LEN] = {0};
        auto ret = GetParameterValue(paramCache.handle, value, VALUE_MAX_LEN - 1);
        if (ret < 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Return default value, ret=%{public}d", ret);
            return "-1";
        }
        std::string resStr(value);
        paramCache.sysParamCache = resStr;
        paramCache.commitIdCache = currCommitId;
    }
    return paramCache.sysParamCache;
}

void NapiAtManager::UpdatePermissionCache(AtManagerSyncContext* syncContext)
{
    std::lock_guard<std::mutex> lock(g_lockCache);
    auto iter = g_cache.find(syncContext->permissionName);
    if (iter != g_cache.end()) {
        std::string currPara = GetPermParamValue(g_paramCache, PERMISSION_STATUS_CHANGE_KEY);
        if (currPara != iter->second.paramValue) {
            syncContext->result = AccessTokenKit::VerifyAccessToken(
                syncContext->tokenId, syncContext->permissionName);
            iter->second.status = syncContext->result;
            iter->second.paramValue = currPara;
            LOGD(ATM_DOMAIN, ATM_TAG, "Param changed currPara %{public}s", currPara.c_str());
        } else {
            syncContext->result = iter->second.status;
        }
    } else {
        syncContext->result = AccessTokenKit::VerifyAccessToken(syncContext->tokenId, syncContext->permissionName);
        g_cache[syncContext->permissionName].status = syncContext->result;
        g_cache[syncContext->permissionName].paramValue = GetPermParamValue(g_paramCache, PERMISSION_STATUS_CHANGE_KEY);
        LOGD(ATM_DOMAIN, ATM_TAG, "G_cacheParam set %{public}s",
            g_cache[syncContext->permissionName].paramValue.c_str());
    }
}

napi_value NapiAtManager::VerifyAccessTokenSync(napi_env env, napi_callback_info info)
{
    static uint64_t selfTokenId = GetSelfTokenID();
    auto* syncContext = new (std::nothrow) AtManagerSyncContext();
    if (syncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New struct fail.");
        return nullptr;
    }

    std::unique_ptr<AtManagerSyncContext> context {syncContext};
    if (!ParseInputVerifyPermissionSync(env, info, *syncContext)) {
        return nullptr;
    }
    if (syncContext->tokenId == 0) {
        std::string errMsg = GetErrorMessage(JS_ERROR_PARAM_INVALID, "The tokenID is 0.");
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_INVALID, errMsg)));
        return nullptr;
    }
    if ((syncContext->permissionName.empty()) ||
        ((syncContext->permissionName.length() > MAX_LENGTH))) {
            std::string errMsg = GetErrorMessage(
                JS_ERROR_PARAM_INVALID, "The permissionName is empty or exceeds 256 characters.");
            NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_INVALID, errMsg)));
        return nullptr;
    }
    if (syncContext->tokenId != static_cast<AccessTokenID>(selfTokenId)) {
        int32_t cnt = g_cnt.fetch_add(1);
        if (!AccessTokenKit::IsSystemAppByFullTokenID(selfTokenId) && cnt % REPORT_CNT == 0) {
            AccessTokenID selfToken = static_cast<AccessTokenID>(selfTokenId);
            (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "VERIFY_ACCESS_TOKEN_EVENT",
                HiviewDFX::HiSysEvent::EventType::STATISTIC, "EVENT_CODE", VERIFY_TOKENID_INCONSISTENCY,
                "SELF_TOKENID", selfToken, "CONTEXT_TOKENID", syncContext->tokenId);
        }
        syncContext->result = AccessTokenKit::VerifyAccessToken(syncContext->tokenId, syncContext->permissionName);
        napi_value result = nullptr;
        NAPI_CALL(env, napi_create_int32(env, syncContext->result, &result));
        LOGD(ATM_DOMAIN, ATM_TAG, "VerifyAccessTokenSync end.");
        return result;
    }

    UpdatePermissionCache(syncContext);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, syncContext->result, &result));
    return result;
}

bool NapiAtManager::ParseInputGrantOrRevokePermission(const napi_env env, const napi_callback_info info,
    AtManagerAsyncContext& asyncContext, UpdatePermissionFlag updateFlag)
{
    size_t argc = MAX_PARAMS_FOUR;
    napi_value argv[MAX_PARAMS_FOUR] = { nullptr };
    napi_value thatVar = nullptr;

    void* data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thatVar, &data), false);
    // 1: grant and revoke required minnum argc
    if (argc < MAX_PARAMS_FOUR - 1) {
        NAPI_CALL_BASE(env, napi_throw(env,
            GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }
    asyncContext.env = env;
    std::string errMsg;
    // 0: the first parameter of argv
    if (!ParseUint32(env, argv[0], asyncContext.tokenId)) {
        errMsg = GetParamErrorMsg("tokenID", "number");
        NAPI_CALL_BASE(
            env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    // 1: the second parameter of argv
    if (!ParseString(env, argv[1], asyncContext.permissionName)) {
        errMsg = GetParamErrorMsg("permissionName", "Permissions");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    // 2: the third parameter of argv
    if (!ParseUint32(env, argv[2], asyncContext.flag)) {
        errMsg = GetParamErrorMsg("flag", "number");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    if (updateFlag < UpdatePermissionFlag::OPERABLE_PERM && argc == MAX_PARAMS_FOUR) {
        // 3: the fourth parameter of argv
        if ((!IsUndefinedOrNull(env, argv[3])) && (!ParseCallback(env, argv[3], asyncContext.callbackRef))) {
            NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL,
                                GetErrorMessage(JsErrorCode::JS_ERROR_PARAM_ILLEGAL))), false);
            return false;
        }
    }

    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID = %{public}d, permissionName = %{public}s, flag = %{public}d",
        asyncContext.tokenId, asyncContext.permissionName.c_str(), asyncContext.flag);
    return true;
}

void NapiAtManager::GrantUserGrantedPermissionExecute(napi_env env, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
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
    if (result != RET_SUCCESS) {
        asyncContext->errorCode = result;
        return;
    }

    LOGD(ATM_DOMAIN, ATM_TAG, "PermissionName = %{public}s, grantmode = %{public}d.",
        asyncContext->permissionName.c_str(), permissionDef.grantMode);

    if (!IsPermissionFlagValid(asyncContext->flag)) {
        asyncContext->errorCode = ERR_PARAM_INVALID;
    }
    // only user_grant permission can use innerkit class method to grant permission
    // system_grant or manual_settings return failed
    if (permissionDef.grantMode == USER_GRANT) {
        asyncContext->errorCode = AccessTokenKit::GrantPermission(asyncContext->tokenId, asyncContext->permissionName,
            asyncContext->flag);
    } else {
        asyncContext->errorCode = ERR_PERMISSION_NOT_EXIST;
    }
    LOGD(ATM_DOMAIN, ATM_TAG,
        "tokenId = %{public}d, permissionName = %{public}s, flag = %{public}d, grant result = %{public}d.",
        asyncContext->tokenId, asyncContext->permissionName.c_str(), asyncContext->flag, asyncContext->errorCode);
}

void NapiAtManager::GrantUserGrantedPermissionComplete(napi_env env, napi_status status, void* data)
{
    AtManagerAsyncContext* context = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (context == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return;
    }
    std::unique_ptr<AtManagerAsyncContext> callbackPtr {context};
    napi_value result = GetNapiNull(env);

    if (context->deferred != nullptr) {
        ReturnPromiseResult(env, *context, result);
    } else {
        ReturnCallbackResult(env, *context, result);
    }
}

napi_value NapiAtManager::GetVersion(napi_env env, napi_callback_info info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "GetVersion begin.");

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New struct fail.");
        return nullptr;
    }
    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetVersion", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, GetVersionExecute, GetVersionComplete,
        reinterpret_cast<void*>(asyncContext), &(asyncContext->work)));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));

    context.release();
    LOGD(ATM_DOMAIN, ATM_TAG, "GetVersion end.");
    return result;
}

void NapiAtManager::GetVersionExecute(napi_env env, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }
    uint32_t version;
    int32_t result = AccessTokenKit::GetVersion(version);
    if (result != RET_SUCCESS) {
        asyncContext->errorCode = result;
        return;
    }
    asyncContext->result = static_cast<int32_t>(version);
    LOGD(ATM_DOMAIN, ATM_TAG, "Version result = %{public}d.", asyncContext->result);
}

void NapiAtManager::GetVersionComplete(napi_env env, napi_status status, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return;
    }
    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    napi_value result = nullptr;
    LOGD(ATM_DOMAIN, ATM_TAG, "Version result = %{public}d.", asyncContext->result);

    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->result, &result));
    ReturnPromiseResult(env, *asyncContext, result);
}

napi_value NapiAtManager::GrantUserGrantedPermission(napi_env env, napi_callback_info info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "GrantUserGrantedPermission begin.");

    auto* context = new (std::nothrow) AtManagerAsyncContext(env); // for async work deliver data
    if (context == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New struct fail.");
        return nullptr;
    }

    std::unique_ptr<AtManagerAsyncContext> contextPtr {context};
    if (!ParseInputGrantOrRevokePermission(env, info, *context)) {
        return nullptr;
    }

    napi_value result = nullptr;

    if (context->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &(context->deferred), &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GrantUserGrantedPermission", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        GrantUserGrantedPermissionExecute, GrantUserGrantedPermissionComplete,
        reinterpret_cast<void*>(context), &(context->work)));

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));

    LOGD(ATM_DOMAIN, ATM_TAG, "GrantUserGrantedPermission end.");
    contextPtr.release();
    return result;
}

void NapiAtManager::RevokeUserGrantedPermissionExecute(napi_env env, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
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
    if (result != RET_SUCCESS) {
        asyncContext->errorCode = result;
        return;
    }

    LOGD(ATM_DOMAIN, ATM_TAG, "PermissionName = %{public}s, grantmode = %{public}d.",
        asyncContext->permissionName.c_str(), permissionDef.grantMode);

    if (!IsPermissionFlagValid(asyncContext->flag)) {
        asyncContext->errorCode = ERR_PARAM_INVALID;
    }
    // only user_grant permission can use innerkit class method to grant permission
    // system_grant or manual_settings return failed
    if (permissionDef.grantMode == USER_GRANT) {
        asyncContext->errorCode = AccessTokenKit::RevokePermission(asyncContext->tokenId, asyncContext->permissionName,
            asyncContext->flag);
    } else {
        asyncContext->errorCode = ERR_PERMISSION_NOT_EXIST;
    }
    LOGD(ATM_DOMAIN, ATM_TAG,
        "tokenId = %{public}d, permissionName = %{public}s, flag = %{public}d, revoke errorCode = %{public}d.",
        asyncContext->tokenId, asyncContext->permissionName.c_str(), asyncContext->flag, asyncContext->errorCode);
}

void NapiAtManager::RevokeUserGrantedPermissionComplete(napi_env env, napi_status status, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    std::unique_ptr<AtManagerAsyncContext> callbackPtr {asyncContext};

    napi_value result = GetNapiNull(env);
    if (asyncContext->deferred != nullptr) {
        ReturnPromiseResult(env, *asyncContext, result);
    } else {
        ReturnCallbackResult(env, *asyncContext, result);
    }
}

napi_value NapiAtManager::RevokeUserGrantedPermission(napi_env env, napi_callback_info info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "RevokeUserGrantedPermission begin.");

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env); // for async work deliver data
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New struct fail.");
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
        reinterpret_cast<void*>(asyncContext), &(asyncContext->work)));

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));
    LOGD(ATM_DOMAIN, ATM_TAG, "RevokeUserGrantedPermission end.");
    context.release();
    return result;
}

void NapiAtManager::GrantPermissionExecute(napi_env env, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext *>(data);
    if (asyncContext == nullptr) {
        return;
    }

    LOGI(ATM_DOMAIN, ATM_TAG,
        "tokenId = %{public}d, permissionName = %{public}s, flag = %{public}d.",
        asyncContext->tokenId, asyncContext->permissionName.c_str(), asyncContext->flag);

    if (!DataValidator::IsTokenIDValid(asyncContext->tokenId) ||
        !DataValidator::IsPermissionNameValid(asyncContext->permissionName) ||
        !IsPermissionFlagValid(asyncContext->flag)) {
        asyncContext->errorCode = ERR_PARAM_INVALID;
        return;
    }

    PermissionBriefDef permissionDef;
    if (!GetPermissionBriefDef(asyncContext->permissionName, permissionDef)) {
        asyncContext->errorCode = ERR_PERMISSION_NOT_EXIST;
        return;
    }

    LOGD(ATM_DOMAIN, ATM_TAG, "PermissionName = %{public}s, grantmode = %{public}d.",
        asyncContext->permissionName.c_str(), permissionDef.grantMode);

    // only user_grant or manual_settings permission can use innerkit class method to grant permission
    // system_grant return failed
    if (permissionDef.grantMode == USER_GRANT || permissionDef.grantMode == MANUAL_SETTINGS) {
        asyncContext->errorCode = AccessTokenKit::GrantPermission(asyncContext->tokenId,
            asyncContext->permissionName, asyncContext->flag, UpdatePermissionFlag::OPERABLE_PERM);
    } else {
        asyncContext->errorCode = ERR_EXPECTED_PERMISSION_TYPE;
        asyncContext->extErrorMsg = "The specified permission is not a user_grant or manual_settings permission.";
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "grant result = %{public}d.", asyncContext->errorCode);
}

void NapiAtManager::GrantPermissionComplete(napi_env env, napi_status status, void *data)
{
    AtManagerAsyncContext* context = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (context == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return;
    }
    std::unique_ptr<AtManagerAsyncContext> callbackPtr {context};
    napi_value result = GetNapiNull(env);

    ReturnPromiseResult(env, *context, result);
}

napi_value NapiAtManager::GrantPermission(napi_env env, napi_callback_info info)
{
    auto* context = new (std::nothrow) AtManagerAsyncContext(env); // for async work deliver data
    if (context == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New struct fail.");
        return nullptr;
    }

    std::unique_ptr<AtManagerAsyncContext> contextPtr {context};
    if (!ParseInputGrantOrRevokePermission(env, info, *context, OPERABLE_PERM)) {
        return nullptr;
    }

    napi_value result = nullptr;

    NAPI_CALL(env, napi_create_promise(env, &(context->deferred), &result));

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GrantPermission", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        GrantPermissionExecute, GrantPermissionComplete,
        reinterpret_cast<void *>(context), &(context->work)));

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, context->work, napi_qos_default));

    contextPtr.release();
    return result;
}

void NapiAtManager::RevokePermissionExecute(napi_env env, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext *>(data);
    if (asyncContext == nullptr) {
        return;
    }

    LOGI(ATM_DOMAIN, ATM_TAG,
        "tokenId = %{public}d, permissionName = %{public}s, flag = %{public}d.",
        asyncContext->tokenId, asyncContext->permissionName.c_str(), asyncContext->flag);

    if (!DataValidator::IsTokenIDValid(asyncContext->tokenId) ||
        !DataValidator::IsPermissionNameValid(asyncContext->permissionName) ||
        !IsPermissionFlagValid(asyncContext->flag)) {
        asyncContext->errorCode = ERR_PARAM_INVALID;
        return;
    }

    PermissionBriefDef permissionDef;
    if (!GetPermissionBriefDef(asyncContext->permissionName, permissionDef)) {
        asyncContext->errorCode = ERR_PERMISSION_NOT_EXIST;
        return;
    }

    LOGD(ATM_DOMAIN, ATM_TAG, "PermissionName = %{public}s, grantmode = %{public}d.",
        asyncContext->permissionName.c_str(), permissionDef.grantMode);

    // only user_grant or manual_settings permission can use innerkit class method to grant permission
    // system_grant return failed
    if (permissionDef.grantMode == USER_GRANT || permissionDef.grantMode == MANUAL_SETTINGS) {
        asyncContext->errorCode = AccessTokenKit::RevokePermission(asyncContext->tokenId,
            asyncContext->permissionName, asyncContext->flag, UpdatePermissionFlag::OPERABLE_PERM);
    } else {
        asyncContext->errorCode = ERR_EXPECTED_PERMISSION_TYPE;
        asyncContext->extErrorMsg = "The specified permission is not a user_grant or manual_settings permission.";
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "revoke result = %{public}d.", asyncContext->errorCode);
}

void NapiAtManager::RevokePermissionComplete(napi_env env, napi_status status, void *data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    std::unique_ptr<AtManagerAsyncContext> callbackPtr {asyncContext};

    napi_value result = GetNapiNull(env);
    ReturnPromiseResult(env, *asyncContext, result);
}

napi_value NapiAtManager::RevokePermission(napi_env env, napi_callback_info info)
{
    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env); // for async work deliver data
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New struct fail.");
        return nullptr;
    }

    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    if (!ParseInputGrantOrRevokePermission(env, info, *asyncContext, OPERABLE_PERM)) {
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "RevokePermission", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        RevokePermissionExecute, RevokePermissionComplete,
        reinterpret_cast<void *>(asyncContext), &(asyncContext->work)));

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));

    context.release();
    return result;
}

void NapiAtManager::GetPermissionFlagsExecute(napi_env env, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return;
    }

    asyncContext->errorCode = AccessTokenKit::GetPermissionFlag(asyncContext->tokenId,
        asyncContext->permissionName, asyncContext->flag);
}

void NapiAtManager::GetPermissionFlagsComplete(napi_env env, napi_status status, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return;
    }
    std::unique_ptr<AtManagerAsyncContext> callbackPtr {asyncContext};

    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->flag, &result));

    ReturnPromiseResult(env, *asyncContext, result);
}

napi_value NapiAtManager::GetPermissionFlags(napi_env env, napi_callback_info info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "GetPermissionFlags begin.");

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New struct fail.");
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
    // define work
    napi_create_async_work(
        env, nullptr, resource, GetPermissionFlagsExecute, GetPermissionFlagsComplete,
        reinterpret_cast<void*>(asyncContext), &(asyncContext->work));
    // add async work handle to the napi queue and wait for result
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);

    LOGD(ATM_DOMAIN, ATM_TAG, "GetPermissionFlags end.");
    context.release();
    return result;
}

bool NapiAtManager::ParseInputSetToggleStatus(const napi_env env, const napi_callback_info info,
    AtManagerAsyncContext& asyncContext)
{
    size_t argc = MAX_PARAMS_TWO;
    napi_value argv[MAX_PARAMS_TWO] = { nullptr };
    napi_value thisVar = nullptr;
    void* data = nullptr;
    std::string errMsg;

    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
    if (argc < MAX_PARAMS_TWO) {
        NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env,
            JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }
    asyncContext.env = env;
    // 0: the first parameter of argv
    if (!ParseString(env, argv[0], asyncContext.permissionName)) {
        errMsg = GetParamErrorMsg("permissionName", "Permissions");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    // 1: the second parameter of argv
    if (!ParseUint32(env, argv[1], asyncContext.status)) {
        errMsg = GetParamErrorMsg("status", "number");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    return true;
}

bool NapiAtManager::ParseInputGetToggleStatus(const napi_env env, const napi_callback_info info,
    AtManagerAsyncContext& asyncContext)
{
    size_t argc = MAX_PARAMS_ONE;

    napi_value argv[MAX_PARAMS_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    std::string errMsg;
    void* data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
    if (argc < MAX_PARAMS_ONE) {
        NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env,
            JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }
    asyncContext.env = env;
    // 0: the first parameter of argv
    if (!ParseString(env, argv[0], asyncContext.permissionName)) {
        errMsg = GetParamErrorMsg("permissionName", "Permissions");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    return true;
}

void NapiAtManager::SetPermissionRequestToggleStatusExecute(napi_env env, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return;
    }

    asyncContext->errorCode = AccessTokenKit::SetPermissionRequestToggleStatus(asyncContext->permissionName,
        asyncContext->status, 0);
}

void NapiAtManager::SetPermissionRequestToggleStatusComplete(napi_env env, napi_status status, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return;
    }
    std::unique_ptr<AtManagerAsyncContext> callbackPtr {asyncContext};

    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->result, &result));

    ReturnPromiseResult(env, *asyncContext, result);
}

void NapiAtManager::GetPermissionRequestToggleStatusExecute(napi_env env, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return;
    }

    asyncContext->errorCode = AccessTokenKit::GetPermissionRequestToggleStatus(asyncContext->permissionName,
        asyncContext->status, 0);
}

void NapiAtManager::GetPermissionRequestToggleStatusComplete(napi_env env, napi_status status, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return;
    }
    std::unique_ptr<AtManagerAsyncContext> callbackPtr {asyncContext};

    napi_value result = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncContext->status, &result));

    ReturnPromiseResult(env, *asyncContext, result);
}

napi_value NapiAtManager::SetPermissionRequestToggleStatus(napi_env env, napi_callback_info info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "SetPermissionRequestToggleStatus begin.");

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New asyncContext failed.");
        return nullptr;
    }

    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    if (!ParseInputSetToggleStatus(env, info, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result)); // create delay promise object

    napi_value resource = nullptr; // resource name
    NAPI_CALL(env, napi_create_string_utf8(env, "SetPermissionRequestToggleStatus", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, SetPermissionRequestToggleStatusExecute, SetPermissionRequestToggleStatusComplete,
        reinterpret_cast<void*>(asyncContext), &(asyncContext->work)));
    // add async work handle to the napi queue and wait for result
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));

    LOGD(ATM_DOMAIN, ATM_TAG, "SetPermissionRequestToggleStatus end.");
    context.release();
    return result;
}

napi_value NapiAtManager::GetPermissionRequestToggleStatus(napi_env env, napi_callback_info info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "GetPermissionRequestToggleStatus begin.");

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New asyncContext failed.");
        return nullptr;
    }

    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    if (!ParseInputGetToggleStatus(env, info, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result)); // create delay promise object

    napi_value resource = nullptr; // resource name
    NAPI_CALL(env, napi_create_string_utf8(env, "GetPermissionRequestToggleStatus", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, GetPermissionRequestToggleStatusExecute, GetPermissionRequestToggleStatusComplete,
        reinterpret_cast<void*>(asyncContext), &(asyncContext->work)));
    // add async work handle to the napi queue and wait for result
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));

    LOGD(ATM_DOMAIN, ATM_TAG, "GetPermissionRequestToggleStatus end.");
    context.release();
    return result;
}

bool NapiAtManager::GetPermStateChangeType(const napi_env env, const size_t argc, const napi_value* argv,
    std::string& type)
{
    std::string errMsg;
    if (argc == 0) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return false;
    }
    // 0: the first parameter of argv
    if (!ParseString(env, argv[0], type)) {
        errMsg = GetParamErrorMsg("type", "permissionStateChange or selfPermissionStateChange");
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg));
        return false;
    }
    if ((type != REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) && (type != REGISTER_PERMISSION_STATE_CHANGE_TYPE)) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "type is invalid"));
        return false;
    }
    return true;
}

bool NapiAtManager::FillPermStateChangeScope(const napi_env env, const napi_value* argv,
    const std::string& type, PermStateChangeScope& scopeInfo)
{
    std::string errMsg;
    int index = 1;
    if (type == REGISTER_PERMISSION_STATE_CHANGE_TYPE) {
        if (!ParseAccessTokenIDArray(env, argv[index++], scopeInfo.tokenIDs)) {
            errMsg = GetParamErrorMsg("tokenIDList", "Array<number>");
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg));
            return false;
        }
    } else if (type == REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) {
        scopeInfo.tokenIDs = {GetSelfTokenID()};
    }
    if (!ParseStringArray(env, argv[index++], scopeInfo.permList)) {
        errMsg = GetParamErrorMsg("permissionNameList", "Array<Permissions>");
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg));
        return false;
    }
    return true;
}

void NapiAtManager::RequestAppPermOnSettingExecute(napi_env env, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        return;
    }
    asyncContext->errorCode = AccessTokenKit::RequestAppPermOnSetting(asyncContext->tokenId);
}

void NapiAtManager::RequestAppPermOnSettingComplete(napi_env env, napi_status status, void* data)
{
    AtManagerAsyncContext* asyncContext = reinterpret_cast<AtManagerAsyncContext*>(data);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return;
    }
    std::unique_ptr<AtManagerAsyncContext> callbackPtr {asyncContext};

    napi_value result = GetNapiNull(env);
    ReturnPromiseResult(env, *asyncContext, result);
}

napi_value NapiAtManager::RequestAppPermOnSetting(napi_env env, napi_callback_info info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "RequestAppPermOnSetting begin.");

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New asyncContext failed.");
        return nullptr;
    }
    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};

    size_t argc = MAX_PARAMS_ONE;
    napi_value argv[MAX_PARAMS_ONE] = { nullptr };
    napi_value thatVar = nullptr;

    void* data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thatVar, &data));
    if (argc < MAX_PARAMS_ONE) {
        NAPI_CALL(env, napi_throw(env,
            GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")));
        return nullptr;
    }

    asyncContext->env = env;
    if (!ParseUint32(env, argv[0], asyncContext->tokenId)) {
        std::string errMsg = GetParamErrorMsg("tokenID", "number");
        NAPI_CALL(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)));
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &(asyncContext->deferred), &result));

    napi_value resource = nullptr; // resource name
    NAPI_CALL(env, napi_create_string_utf8(env, "RequestAppPermOnSetting", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
        RequestAppPermOnSettingExecute, RequestAppPermOnSettingComplete,
        reinterpret_cast<void*>(asyncContext), &(asyncContext->work)));

    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default));

    LOGD(ATM_DOMAIN, ATM_TAG, "RequestAppPermOnSetting end.");
    context.release();
    return result;
}

bool NapiAtManager::ParseInputGetPermStatus(const napi_env env, const napi_callback_info info,
    AtManagerSyncContext& syncContext)
{
    size_t argc = MAX_PARAMS_ONE;
    napi_value argv[MAX_PARAMS_ONE] = { nullptr };
    napi_value thisVar = nullptr;

    void* data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data), false);
    if (argc < MAX_PARAMS_ONE) {
        NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env,
            JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }

    syncContext.env = env;
    if (!ParseString(env, argv[0], syncContext.permissionName)) {
        std::string errMsg = GetParamErrorMsg("permissionName", "Permissions");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    return true;
}

napi_value NapiAtManager::GetSelfPermissionStatusSync(napi_env env, napi_callback_info info)
{
    auto* syncContext = new (std::nothrow) AtManagerSyncContext();
    if (syncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New struct fail.");
        return nullptr;
    }

    std::unique_ptr<AtManagerSyncContext> context {syncContext};
    if (!ParseInputGetPermStatus(env, info, *syncContext)) {
        return nullptr;
    }

    if ((syncContext->permissionName.empty()) ||
        ((syncContext->permissionName.length() > MAX_LENGTH))) {
        std::string errMsg = GetErrorMessage(
            JS_ERROR_PARAM_INVALID, "The permissionName is empty or exceeds 256 characters.");
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, JS_ERROR_PARAM_INVALID, errMsg)));
        return nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(g_lockStatusCache);
        auto iter = g_statusCache.find(syncContext->permissionName);
        if (iter != g_statusCache.end()) {
            std::string currPara = GetPermParamValue(g_paramFlagCache, PERMISSION_STATUS_FLAG_CHANGE_KEY);
            if (currPara != iter->second.paramValue) {
                syncContext->result = AccessTokenKit::GetSelfPermissionStatus(syncContext->permissionName,
                    syncContext->permissionsState);
                iter->second.status = syncContext->permissionsState;
                iter->second.paramValue = currPara;
            } else {
                syncContext->result = RET_SUCCESS;
                syncContext->permissionsState = iter->second.status;
            }
        } else {
            syncContext->result = AccessTokenKit::GetSelfPermissionStatus(syncContext->permissionName,
                syncContext->permissionsState);
            g_statusCache[syncContext->permissionName].status = syncContext->permissionsState;
            g_statusCache[syncContext->permissionName].paramValue = GetPermParamValue(
                g_paramFlagCache, PERMISSION_STATUS_FLAG_CHANGE_KEY);
        }
    }

    if (syncContext->result != RET_SUCCESS) {
        int32_t jsCode = GetJsErrorCode(syncContext->result);
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode))));
        return nullptr;
    }

    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(syncContext->permissionsState), &result));
    return result;
}

bool NapiAtManager::FillPermStateChangeInfo(const napi_env env, const napi_value* argv, const std::string& type,
    const napi_value thisVar, RegisterPermStateChangeInfo& registerPermStateChangeInfo)
{
    PermStateChangeScope scopeInfo;
    std::string errMsg;
    napi_ref callback = nullptr;

    if (!FillPermStateChangeScope(env, argv, type, scopeInfo)) {
        return false;
    }
    uint32_t index;
    if (type == REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) {
        index = THIRD_PARAM;
    } else {
        index = FORTH_PARAM;
    }
    if (!ParseCallback(env, argv[index], callback)) {
        errMsg = GetParamErrorMsg("callback", "Callback<PermissionStateChangeInfo>");
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg));
        return false;
    }
    std::sort(scopeInfo.tokenIDs.begin(), scopeInfo.tokenIDs.end());
    std::sort(scopeInfo.permList.begin(), scopeInfo.permList.end());
    registerPermStateChangeInfo.callbackRef = callback;
    registerPermStateChangeInfo.subscriber = std::make_shared<RegisterPermStateChangeScopePtr>(scopeInfo);
    registerPermStateChangeInfo.subscriber->SetEnv(env);
    registerPermStateChangeInfo.subscriber->SetCallbackRef(callback);
    std::shared_ptr<RegisterPermStateChangeScopePtr> *subscriber =
        new (std::nothrow) std::shared_ptr<RegisterPermStateChangeScopePtr>(
            registerPermStateChangeInfo.subscriber);
    if (subscriber == nullptr) {
        return false;
    }
    napi_status status = napi_wrap(env, thisVar, reinterpret_cast<void*>(subscriber),
        [](napi_env nev, void* data, void* hint) {
        std::shared_ptr<RegisterPermStateChangeScopePtr>* subscriber =
            static_cast<std::shared_ptr<RegisterPermStateChangeScopePtr>*>(data);
        if (subscriber != nullptr && *subscriber != nullptr) {
            (*subscriber)->SetValid(false);
            delete subscriber;
        }
    }, nullptr, nullptr);
    if (status != napi_ok) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to wrap subscriber obj!");
        delete subscriber;
        subscriber = nullptr;
        return false;
    }

    return true;
}

bool NapiAtManager::ParseInputToRegister(const napi_env env, const napi_callback_info cbInfo,
    RegisterPermStateChangeInfo& registerPermStateChangeInfo)
{
    size_t argc = MAX_PARAMS_FOUR;
    napi_value argv[MAX_PARAMS_FOUR] = { nullptr };
    napi_value thisVar = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr), false);
    if (thisVar == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ThisVar is nullptr");
        return false;
    }
    napi_valuetype valueTypeOfThis = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, thisVar, &valueTypeOfThis), false);
    if (valueTypeOfThis == napi_undefined) {
        LOGE(ATM_DOMAIN, ATM_TAG, "ThisVar is undefined");
        return false;
    }
    std::string type;
    if (!GetPermStateChangeType(env, argc, argv, type)) {
        return false;
    }
    if ((type == REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) && (argc < MAX_PARAMS_THREE)) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return false;
    }
    if ((type == REGISTER_PERMISSION_STATE_CHANGE_TYPE) && (argc < MAX_PARAMS_FOUR)) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return false;
    }
    registerPermStateChangeInfo.env = env;
    registerPermStateChangeInfo.permStateChangeType = type;
    registerPermStateChangeInfo.threadId_ = std::this_thread::get_id();
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Insufficient memory for subscribeCBInfo!");
        return nullptr;
    }
    std::unique_ptr<RegisterPermStateChangeInfo> callbackPtr {registerPermStateChangeInfo};
    if (!ParseInputToRegister(env, cbInfo, *registerPermStateChangeInfo)) {
        return nullptr;
    }
    if (IsExistRegister(env, registerPermStateChangeInfo)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Subscribe failed. The current subscriber has been existed.");
        std::string errMsg = "The API reuses the same input. The subscriber already exists.";
        if (registerPermStateChangeInfo->permStateChangeType == REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) {
            NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_NOT_USE_TOGETHER, errMsg)));
        } else {
            std::string errMsgFull = GetErrorMessage(JS_ERROR_PARAM_INVALID, errMsg);
            NAPI_CALL(env,
                napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_INVALID, errMsgFull)));
        }
        return nullptr;
    }
    int32_t result;
    if (registerPermStateChangeInfo->permStateChangeType == REGISTER_PERMISSION_STATE_CHANGE_TYPE) {
        result = AccessTokenKit::RegisterPermStateChangeCallback(registerPermStateChangeInfo->subscriber);
    } else {
        result = AccessTokenKit::RegisterSelfPermStateChangeCallback(registerPermStateChangeInfo->subscriber);
    }
    if (result != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "RegisterPermStateChangeCallback failed");
        registerPermStateChangeInfo->errCode = result;
        int32_t jsCode = GetJsErrorCode(result);
        std::string errMsg = GetErrorMessage(jsCode);
        NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, jsCode, errMsg)));
        return nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
        g_permStateChangeRegisters.emplace_back(registerPermStateChangeInfo);
        LOGD(ATM_DOMAIN, ATM_TAG, "Add g_PermStateChangeRegisters.size = %{public}zu",
            g_permStateChangeRegisters.size());
    }
    callbackPtr.release();
    return nullptr;
}

bool NapiAtManager::ParseInputToUnregister(const napi_env env, napi_callback_info cbInfo,
    UnregisterPermStateChangeInfo& unregisterPermStateChangeInfo)
{
    size_t argc = MAX_PARAMS_FOUR;
    napi_value argv[MAX_PARAMS_FOUR] = { nullptr };
    napi_value thisVar = nullptr;
    napi_ref callback = nullptr;
    std::string errMsg;
    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr) != napi_ok) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Napi_get_cb_info failed");
        return false;
    }
    // 1: off required minnum argc
    if (argc == 0) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return false;
    }
    std::string type;
    if (!GetPermStateChangeType(env, argc, argv, type)) {
        return false;
    }
    if ((type == REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) && (argc < MAX_PARAMS_THREE - 1)) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return false;
    }
    if ((type == REGISTER_PERMISSION_STATE_CHANGE_TYPE) && (argc < MAX_PARAMS_FOUR - 1)) {
        napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing."));
        return false;
    }
    PermStateChangeScope scopeInfo;
    if (!FillPermStateChangeScope(env, argv, type, scopeInfo)) {
        return false;
    }
    if (((type == REGISTER_PERMISSION_STATE_CHANGE_TYPE) && (argc == MAX_PARAMS_FOUR)) ||
        ((type == REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) && (argc == MAX_PARAMS_THREE))) {
        int callbackIndex = (type == REGISTER_PERMISSION_STATE_CHANGE_TYPE) ? FORTH_PARAM : THIRD_PARAM;
        if (!ParseCallback(env, argv[callbackIndex], callback)) {
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
    unregisterPermStateChangeInfo.threadId_ = std::this_thread::get_id();
    return true;
}

napi_value NapiAtManager::UnregisterPermStateChangeCallback(napi_env env, napi_callback_info cbInfo)
{
    UnregisterPermStateChangeInfo* unregisterPermStateChangeInfo =
        new (std::nothrow) UnregisterPermStateChangeInfo();
    if (unregisterPermStateChangeInfo == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Insufficient memory for subscribeCBInfo!");
        return nullptr;
    }
    std::unique_ptr<UnregisterPermStateChangeInfo> callbackPtr {unregisterPermStateChangeInfo};
    if (!ParseInputToUnregister(env, cbInfo, *unregisterPermStateChangeInfo)) {
        return nullptr;
    }
    std::vector<RegisterPermStateChangeInfo*> batchPermStateChangeRegisters;
    if (!FindAndGetSubscriberInVector(unregisterPermStateChangeInfo, batchPermStateChangeRegisters, env)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Unsubscribe failed. The current subscriber does not exist");
        std::string errMsg = "The API is not used in pair with 'on'. The subscriber does not exist.";
        if (unregisterPermStateChangeInfo->permStateChangeType == REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) {
            NAPI_CALL(env,
                napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_NOT_USE_TOGETHER, errMsg)));
        } else {
            std::string errMsgFull = GetErrorMessage(JS_ERROR_PARAM_INVALID, errMsg);
            NAPI_CALL(env,
                napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_INVALID, errMsgFull)));
        }
        return nullptr;
    }
    for (const auto& item : batchPermStateChangeRegisters) {
        PermStateChangeScope scopeInfo;
        item->subscriber->GetScope(scopeInfo);
        int32_t result;
        if (unregisterPermStateChangeInfo->permStateChangeType == REGISTER_PERMISSION_STATE_CHANGE_TYPE) {
            result = AccessTokenKit::UnRegisterPermStateChangeCallback(item->subscriber);
        } else {
            result = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(item->subscriber);
        }
        if (result == RET_SUCCESS) {
            DeleteRegisterFromVector(scopeInfo, env, item->callbackRef);
        } else {
            LOGE(ATM_DOMAIN, ATM_TAG, "Batch UnregisterPermActiveChangeCompleted failed");
            int32_t jsCode = GetJsErrorCode(result);
            std::string errMsg = GetErrorMessage(jsCode);
            NAPI_CALL(env, napi_throw(env, GenerateBusinessError(env, jsCode, errMsg)));
        }
    }
    return nullptr;
}

bool NapiAtManager::FindAndGetSubscriberInVector(UnregisterPermStateChangeInfo* unregisterPermStateChangeInfo,
    std::vector<RegisterPermStateChangeInfo*>& batchPermStateChangeRegisters, const napi_env env)
{
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    std::vector<AccessTokenID> targetTokenIDs = unregisterPermStateChangeInfo->scopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = unregisterPermStateChangeInfo->scopeInfo.permList;
    for (const auto& item : g_permStateChangeRegisters) {
        if (unregisterPermStateChangeInfo->callbackRef != nullptr) {
            if (!CompareCallbackRef(env, item->callbackRef, unregisterPermStateChangeInfo->callbackRef,
                item->threadId_)) {
                continue;
            }
        } else {
            // batch delete currentThread callback
            if (!IsCurrentThread(item->threadId_)) {
                continue;
            }
        }
        PermStateChangeScope scopeInfo;
        item->subscriber->GetScope(scopeInfo);
        if (scopeInfo.tokenIDs == targetTokenIDs && scopeInfo.permList == targetPermList) {
            LOGD(ATM_DOMAIN, ATM_TAG, "Find subscriber in map");
            unregisterPermStateChangeInfo->subscriber = item->subscriber;
            batchPermStateChangeRegisters.emplace_back(item);
        }
    }
    if (!batchPermStateChangeRegisters.empty()) {
        return true;
    }
    return false;
}

bool NapiAtManager::IsExistRegister(const napi_env env, const RegisterPermStateChangeInfo* registerPermStateChangeInfo)
{
    PermStateChangeScope targetScopeInfo;
    registerPermStateChangeInfo->subscriber->GetScope(targetScopeInfo);
    std::vector<AccessTokenID> targetTokenIDs = targetScopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = targetScopeInfo.permList;
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    
    for (const auto& item : g_permStateChangeRegisters) {
        PermStateChangeScope scopeInfo;
        item->subscriber->GetScope(scopeInfo);

        bool hasPermIntersection = false;
        // Special cases:
        // 1.Have registered full, and then register some
        // 2.Have registered some, then register full
        if (scopeInfo.permList.empty() || targetPermList.empty()) {
            hasPermIntersection = true;
        }
        for (const auto& PermItem : targetPermList) {
            if (hasPermIntersection) {
                break;
            }
            auto iter = std::find(scopeInfo.permList.begin(), scopeInfo.permList.end(), PermItem);
            if (iter != scopeInfo.permList.end()) {
                hasPermIntersection = true;
            }
        }

        bool hasTokenIdIntersection = false;

        if (scopeInfo.tokenIDs.empty() || targetTokenIDs.empty()) {
            hasTokenIdIntersection = true;
        }
        for (const auto& tokenItem : targetTokenIDs) {
            if (hasTokenIdIntersection) {
                break;
            }
            auto iter = std::find(scopeInfo.tokenIDs.begin(), scopeInfo.tokenIDs.end(), tokenItem);
            if (iter != scopeInfo.tokenIDs.end()) {
                hasTokenIdIntersection = true;
            }
        }

        if (hasTokenIdIntersection && hasPermIntersection &&
            CompareCallbackRef(env, item->callbackRef, registerPermStateChangeInfo->callbackRef, item->threadId_)) {
            return true;
        }
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "Cannot find subscriber in vector");
    return false;
}

void NapiAtManager::DeleteRegisterFromVector(const PermStateChangeScope& scopeInfo, const napi_env env,
    napi_ref subscriberRef)
{
    std::vector<AccessTokenID> targetTokenIDs = scopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = scopeInfo.permList;
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    auto item = g_permStateChangeRegisters.begin();
    while (item != g_permStateChangeRegisters.end()) {
        PermStateChangeScope stateChangeScope;
        (*item)->subscriber->GetScope(stateChangeScope);
        if ((stateChangeScope.tokenIDs == targetTokenIDs) && (stateChangeScope.permList == targetPermList) &&
            CompareCallbackRef(env, (*item)->callbackRef, subscriberRef, (*item)->threadId_)) {
            LOGD(ATM_DOMAIN, ATM_TAG, "Find subscribers in vector, delete");
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
    LOGD(ATM_DOMAIN, ATM_TAG, "Register end, start init.");
    OHOS::Security::AccessToken::NapiAtManager::Init(env, exports);
    return exports;
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
    .nm_priv = static_cast<void*>(nullptr),
    .reserved = {nullptr}
};

/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void AbilityAccessCtrlmoduleRegister(void)
{
    napi_module_register(&g_module);
}
