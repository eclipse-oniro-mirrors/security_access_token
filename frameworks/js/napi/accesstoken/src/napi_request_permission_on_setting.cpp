/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "napi_request_permission_on_setting.h"

#include "ability.h"
#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "napi_base_context.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "NapiRequestPermissionOnSetting"
};
const std::string PERMISSION_KEY = "ohos.user.setting.permission";
const std::string PERMISSION_RESULT_KEY = "ohos.user.setting.permission.result";
const std::string RESULT_ERROR_KEY = "ohos.user.setting.error_code";
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string UI_EXTENSION_TYPE = "sys/commonUI";

// error code from dialog
const int32_t REQUEST_REALDY_EXIST = 1;
const int32_t PERM_NOT_BELONG_TO_SAME_GROUP = 2;
const int32_t PERM_IS_NOT_DECLARE = 3;
const int32_t ALL_PERM_GRANTED = 4;
const int32_t PERM_REVOKE_BY_USER = 5;
std::mutex g_lockFlag;
} // namespace
static void ReturnPromiseResult(napi_env env, int32_t jsCode, napi_deferred deferred, napi_value result)
{
    if (jsCode != JS_OK) {
        napi_value businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode));
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, deferred, businessError));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, deferred, result));
    }
}

static napi_value WrapVoidToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

static Ace::UIContent* GetUIContent(std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext)
{
    if (asyncContext == nullptr) {
        return nullptr;
    }
    Ace::UIContent* uiContent = nullptr;
    if (asyncContext->uiAbilityFlag) {
        uiContent = asyncContext->abilityContext->GetUIContent();
    } else {
        uiContent = asyncContext->uiExtensionContext->GetUIContent();
    }
    return uiContent;
}

static napi_value GetContext(
    const napi_env &env, const napi_value &value, std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, value, stageMode);
    if (status != napi_ok || !stageMode) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "It is not a stage mode.");
        return nullptr;
    } else {
        auto context = AbilityRuntime::GetStageModeContext(env, value);
        if (context == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to Get application context.");
            return nullptr;
        }
        asyncContext->abilityContext =
            AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
        if (asyncContext->abilityContext != nullptr) {
            asyncContext->uiAbilityFlag = true;
        } else {
            ACCESSTOKEN_LOG_WARN(LABEL, "Failed to convert to ability context.");
            asyncContext->uiExtensionContext =
                AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(context);
            if (asyncContext->uiExtensionContext == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to convert to ui extension context.");
                return nullptr;
            }
        }
        return WrapVoidToJS(env);
    }
}

static napi_value WrapRequestResult(const napi_env& env, const std::vector<int32_t>& pemResults)
{
    napi_value result;
    NAPI_CALL(env, napi_create_array(env, &result));

    for (size_t i = 0; i < pemResults.size(); i++) {
        napi_value nPermissionResult = nullptr;
        NAPI_CALL(env, napi_create_int32(env, pemResults[i], &nPermissionResult));
        NAPI_CALL(env, napi_set_element(env, result, i, nPermissionResult));
    }
    return result;
}

static int32_t TransferToJsErrorCode(int32_t errCode)
{
    int32_t jsCode = JS_OK;
    switch (errCode) {
        case RET_SUCCESS:
            jsCode = JS_OK;
            break;
        case REQUEST_REALDY_EXIST:
            jsCode = JS_ERROR_REQUEST_IS_ALREADY_EXIST;
            break;
        case PERM_NOT_BELONG_TO_SAME_GROUP:
            jsCode = JS_ERROR_PARAM_INVALID;
            break;
        case PERM_IS_NOT_DECLARE:
            jsCode = JS_ERROR_PARAM_INVALID;
            break;
        case ALL_PERM_GRANTED:
            jsCode = JS_ERROR_ALL_PERM_GRANTED;
            break;
        case PERM_REVOKE_BY_USER:
            jsCode = JS_ERROR_PERM_REVOKE_BY_USER;
            break;
        default:
            jsCode = JS_ERROR_INNER;
            break;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "dialog error(%{public}d) jsCode(%{public}d).", errCode, jsCode);
    return jsCode;
}

static void ResultCallbackJSThreadWorker(uv_work_t* work, int32_t status)
{
    (void)status;
    if (work == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Uv_queue_work_with_qos input work is nullptr");
        return;
    }
    std::unique_ptr<uv_work_t> uvWorkPtr {work};
    PermissonOnSettingResultCallback *retCB = reinterpret_cast<PermissonOnSettingResultCallback*>(work->data);
    if (retCB == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "RetCB is nullptr");
        return;
    }
    std::unique_ptr<PermissonOnSettingResultCallback> callbackPtr {retCB};
    std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext = retCB->data;
    if (asyncContext == nullptr) {
        return;
    }

    int32_t result = retCB->jsCode;
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(asyncContext->env, &scope);
    if (scope == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Napi_open_handle_scope failed");
        return;
    }
    napi_value requestResult = WrapRequestResult(asyncContext->env, retCB->stateList);
    if ((result == JS_OK) && (requestResult == nullptr)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Wrap requestResult failed");
        result = JS_ERROR_INNER;
    }

    ReturnPromiseResult(asyncContext->env, retCB->jsCode, asyncContext->deferred, requestResult);
    napi_close_handle_scope(asyncContext->env, scope);
}

static void PermissionResultsCallbackUI(int32_t jsCode,
    const std::vector<int32_t> stateList, std::shared_ptr<RequestPermOnSettingAsyncContext>& data)
{
    auto* retCB = new (std::nothrow) PermissonOnSettingResultCallback();
    if (retCB == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Insufficient memory for work!");
        return;
    }

    std::unique_ptr<PermissonOnSettingResultCallback> callbackPtr {retCB};
    retCB->jsCode = jsCode;
    retCB->stateList = stateList;
    retCB->data = data;

    uv_loop_s* loop = nullptr;
    NAPI_CALL_RETURN_VOID(data->env, napi_get_uv_event_loop(data->env, &loop));
    if (loop == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Loop instance is nullptr");
        return;
    }
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Insufficient memory for work!");
        return;
    }
    std::unique_ptr<uv_work_t> uvWorkPtr {work};
    work->data = reinterpret_cast<void *>(retCB);
    NAPI_CALL_RETURN_VOID(data->env, uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {}, ResultCallbackJSThreadWorker, uv_qos_user_initiated));

    uvWorkPtr.release();
    callbackPtr.release();
}

void PermissonOnSettingUICallback::ReleaseHandler(int32_t code)
{
    {
        std::lock_guard<std::mutex> lock(g_lockFlag);
        if (this->reqContext_->releaseFlag) {
            ACCESSTOKEN_LOG_WARN(LABEL, "Callback has executed.");
            return;
        }
        this->reqContext_->releaseFlag = true;
    }
    Ace::UIContent* uiContent = GetUIContent(this->reqContext_);
    if (uiContent == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Get ui content failed!");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Close uiextension component");
    uiContent->CloseModalUIExtension(this->sessionId_);
    if (code == -1) {
        this->reqContext_->errorCode = code;
    }
    PermissionResultsCallbackUI(
        TransferToJsErrorCode(this->reqContext_->errorCode), this->reqContext_->stateList, this->reqContext_);
}

PermissonOnSettingUICallback::PermissonOnSettingUICallback(
    const std::shared_ptr<RequestPermOnSettingAsyncContext>& reqContext)
{
    this->reqContext_ = reqContext;
}

PermissonOnSettingUICallback::~PermissonOnSettingUICallback()
{}

void PermissonOnSettingUICallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

/*
 * when UIExtensionAbility use terminateSelfWithResult
 */
void PermissonOnSettingUICallback::OnResult(int32_t resultCode, const AAFwk::Want& result)
{
    this->reqContext_->errorCode = result.GetIntParam(RESULT_ERROR_KEY, 0);
    this->reqContext_->stateList = result.GetIntArrayParam(PERMISSION_RESULT_KEY);
    ACCESSTOKEN_LOG_INFO(LABEL, "ResultCode is %{public}d, errorCode=%{public}d, listSize=%{public}zu",
        resultCode, this->reqContext_->errorCode, this->reqContext_->stateList.size());
    ReleaseHandler(0);
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void PermissonOnSettingUICallback::OnReceive(const AAFwk::WantParams& receive)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Called!");
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void PermissonOnSettingUICallback::OnRelease(int32_t releaseCode)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ReleaseCode is %{public}d", releaseCode);

    ReleaseHandler(-1);
}

/*
 * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
 */
void PermissonOnSettingUICallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Code is %{public}d, name is %{public}s, message is %{public}s",
        code, name.c_str(), message.c_str());

    ReleaseHandler(-1);
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void PermissonOnSettingUICallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Connect to UIExtensionAbility successfully.");
}

/*
 * when UIExtensionComponent destructed
 */
void PermissonOnSettingUICallback::OnDestroy()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "UIExtensionAbility destructed.");
    ReleaseHandler(-1);
}

static int32_t CreateUIExtension(const Want &want, std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext)
{
    Ace::UIContent* uiContent = GetUIContent(asyncContext);
    if (uiContent == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to get ui content!");
        asyncContext->result = RET_FAILED;
        return RET_FAILED;
    }
    auto uiExtCallback = std::make_shared<PermissonOnSettingUICallback>(asyncContext);
    Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) {
            uiExtCallback->OnRelease(releaseCode);
        },
        [uiExtCallback](int32_t resultCode, const AAFwk::Want &result) {
            uiExtCallback->OnResult(resultCode, result);
        },
        [uiExtCallback](const AAFwk::WantParams &receive) {
            uiExtCallback->OnReceive(receive);
        },
        [uiExtCallback](int32_t code, const std::string &name, [[maybe_unused]] const std::string &message) {
            uiExtCallback->OnError(code, name, name);
        },
        [uiExtCallback](const std::shared_ptr<Ace::ModalUIExtensionProxy> &uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy);
        },
        [uiExtCallback]() {
            uiExtCallback->OnDestroy();
        },
    };

    Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
    ACCESSTOKEN_LOG_INFO(LABEL, "Create end, sessionId: %{public}d, tokenId: %{public}d, permSize: %{public}zu.",
        sessionId, asyncContext->tokenId, asyncContext->permissionList.size());
    if (sessionId == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to create component, sessionId is 0.");
        asyncContext->result = RET_FAILED;
        return RET_FAILED;
    }
    uiExtCallback->SetSessionId(sessionId);
    return JS_OK;
}

static int32_t StartUIExtension(std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext)
{
    AAFwk::Want want;
    AccessTokenKit::GetPermissionManagerInfo(asyncContext->info);
    ACCESSTOKEN_LOG_INFO(LABEL, "bundleName: %{public}s, permStateAbilityName: %{public}s.",
        asyncContext->info.grantBundleName.c_str(), asyncContext->info.permStateAbilityName.c_str());
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.permStateAbilityName);
    want.SetParam(PERMISSION_KEY, asyncContext->permissionList);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);
    return CreateUIExtension(want, asyncContext);
}

napi_value NapiRequestPermissionOnSetting::RequestPermissionOnSetting(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "RequestPermissionOnSetting begin.");
    // use handle to protect asyncContext
    std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext =
        std::make_shared<RequestPermOnSettingAsyncContext>(env);

    if (!ParseRequestPermissionOnSetting(env, info, asyncContext)) {
        return nullptr;
    }
    auto asyncContextHandle = std::make_unique<RequestOnSettingAsyncContextHandle>(asyncContext);
    napi_value result = nullptr;
    if (asyncContextHandle->asyncContextPtr->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &(asyncContextHandle->asyncContextPtr->deferred), &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr; // resource name
    NAPI_CALL(env, napi_create_string_utf8(env, "RequestPermissionOnSetting", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, RequestPermissionOnSettingExecute, RequestPermissionOnSettingComplete,
        reinterpret_cast<void *>(asyncContextHandle.get()), &(asyncContextHandle->asyncContextPtr->work)));

    NAPI_CALL(env,
        napi_queue_async_work_with_qos(env, asyncContextHandle->asyncContextPtr->work, napi_qos_user_initiated));

    ACCESSTOKEN_LOG_DEBUG(LABEL, "RequestPermissionOnSetting end.");
    asyncContextHandle.release();
    return result;
}

bool NapiRequestPermissionOnSetting::ParseRequestPermissionOnSetting(const napi_env& env,
    const napi_callback_info& cbInfo, std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    size_t argc = NapiContextCommon::MAX_PARAMS_TWO;
    napi_value argv[NapiContextCommon::MAX_PARAMS_TWO] = { nullptr };
    napi_value thisVar = nullptr;

    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr) != napi_ok) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Napi_get_cb_info failed");
        return false;
    }
    if (argc < NapiContextCommon::MAX_PARAMS_TWO - 1) {
        NAPI_CALL_BASE(env, napi_throw(env, GenerateBusinessError(env,
            JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }
    asyncContext->env = env;
    std::string errMsg;

    // argv[0] : context : AbilityContext
    if (GetContext(env, argv[0], asyncContext) == nullptr) {
        errMsg = GetParamErrorMsg("context", "UIAbility or UIExtension Context");
        NAPI_CALL_BASE(
            env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "AsyncContext.uiAbilityFlag is: %{public}d.", asyncContext->uiAbilityFlag);

    // argv[1] : permissionList
    if (!ParseStringArray(env, argv[1], asyncContext->permissionList) ||
        (asyncContext->permissionList.empty())) {
        errMsg = GetParamErrorMsg("permissionList", "Array<Permissions>");
        NAPI_CALL_BASE(
            env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    return true;
}

void NapiRequestPermissionOnSetting::RequestPermissionOnSettingExecute(napi_env env, void* data)
{
    // asyncContext release in complete
    RequestOnSettingAsyncContextHandle* asyncContextHandle =
        reinterpret_cast<RequestOnSettingAsyncContextHandle*>(data);
    if (asyncContextHandle == nullptr) {
        return;
    }
    if (asyncContextHandle->asyncContextPtr->uiAbilityFlag) {
        asyncContextHandle->asyncContextPtr->tokenId =
            asyncContextHandle->asyncContextPtr->abilityContext->GetApplicationInfo()->accessTokenId;
    } else {
        asyncContextHandle->asyncContextPtr->tokenId =
            asyncContextHandle->asyncContextPtr->uiExtensionContext->GetApplicationInfo()->accessTokenId;
    }
    static AccessTokenID currToken = static_cast<AccessTokenID>(GetSelfTokenID());
    if (asyncContextHandle->asyncContextPtr->tokenId != currToken) {
        ACCESSTOKEN_LOG_ERROR(LABEL,
            "The context(token=%{public}d) is not belong to the current application(currToken=%{public}d).",
            asyncContextHandle->asyncContextPtr->tokenId, currToken);
        asyncContextHandle->asyncContextPtr->result = ERR_PARAM_INVALID;
        return;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "Start to pop ui extension dialog");
    StartUIExtension(asyncContextHandle->asyncContextPtr);
    if (asyncContextHandle->asyncContextPtr->result != JsErrorCode::JS_OK) {
        ACCESSTOKEN_LOG_WARN(LABEL, "Failed to pop uiextension dialog.");
    }
}

void NapiRequestPermissionOnSetting::RequestPermissionOnSettingComplete(napi_env env, napi_status status, void* data)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "RequestPermissionOnSettingComplete begin.");
    RequestOnSettingAsyncContextHandle* asyncContextHandle =
        reinterpret_cast<RequestOnSettingAsyncContextHandle*>(data);
    if (asyncContextHandle == nullptr || asyncContextHandle->asyncContextPtr == nullptr) {
        return;
    }
    std::unique_ptr<RequestOnSettingAsyncContextHandle> callbackPtr {asyncContextHandle};

    // need pop dialog
    if (asyncContextHandle->asyncContextPtr->result == RET_SUCCESS) {
        return;
    }
    // return error
    if (asyncContextHandle->asyncContextPtr->deferred != nullptr) {
        int32_t jsCode = NapiContextCommon::GetJsErrorCode(asyncContextHandle->asyncContextPtr->result);
        napi_value businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode));
        NAPI_CALL_RETURN_VOID(env,
            napi_reject_deferred(env, asyncContextHandle->asyncContextPtr->deferred, businessError));
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS