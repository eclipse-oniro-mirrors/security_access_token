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
#include "napi_request_global_switch_on_setting.h"

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
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "NapiRequestGlobalSwitch"
};
const std::string GLOBAL_SWITCH_KEY = "ohos.user.setting.global_switch";
const std::string GLOBAL_SWITCH_RESULT_KEY = "ohos.user.setting.global_switch.result";
const std::string RESULT_ERROR_KEY = "ohos.user.setting.error_code";
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string UI_EXTENSION_TYPE = "sys/commonUI";

// error code from dialog
const int32_t REQUEST_REALDY_EXIST = 1;
const int32_t GLOBAL_TYPE_IS_NOT_SUPPORT = 2;
const int32_t SWITCH_IS_ALREADY_OPEN = 3;
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

static Ace::UIContent* GetUIContent(std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext)
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
    const napi_env &env, const napi_value &value, std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext)
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
        case GLOBAL_TYPE_IS_NOT_SUPPORT:
            jsCode = JS_ERROR_PARAM_INVALID;
            break;
        case SWITCH_IS_ALREADY_OPEN:
            jsCode = JS_ERROR_GLOBAL_SWITCH_IS_ALREADY_OPEN;
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
    SwitchOnSettingResultCallback *retCB = reinterpret_cast<SwitchOnSettingResultCallback*>(work->data);
    if (retCB == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "RetCB is nullptr");
        return;
    }
    std::unique_ptr<SwitchOnSettingResultCallback> callbackPtr {retCB};
    std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext = retCB->data;
    if (asyncContext == nullptr) {
        return;
    }

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(asyncContext->env, &scope);
    if (scope == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Napi_open_handle_scope failed");
        return;
    }
    napi_value requestResult = nullptr;
    NAPI_CALL_RETURN_VOID(asyncContext->env, napi_create_int32(asyncContext->env, retCB->switchStatus, &requestResult));

    ReturnPromiseResult(asyncContext->env, retCB->jsCode, asyncContext->deferred, requestResult);
    napi_close_handle_scope(asyncContext->env, scope);
}

static void GlobalSwitchResultsCallbackUI(int32_t jsCode,
    bool switchStatus, std::shared_ptr<RequestGlobalSwitchAsyncContext>& data)
{
    auto* retCB = new (std::nothrow) SwitchOnSettingResultCallback();
    if (retCB == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Insufficient memory for work!");
        return;
    }

    std::unique_ptr<SwitchOnSettingResultCallback> callbackPtr {retCB};
    retCB->jsCode = jsCode;
    retCB->switchStatus = switchStatus;
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

void SwitchOnSettingUICallback::ReleaseOrErrorHandle(int32_t code)
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
    if (code == 0) {
        return; // code is 0 means request has return by OnResult
    }
    auto* retCB = new (std::nothrow) SwitchOnSettingResultCallback();
    if (retCB == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Insufficient memory for work!");
        return;
    }
    std::unique_ptr<SwitchOnSettingResultCallback> callbackPtr {retCB};
    retCB->data = this->reqContext_;
    retCB->jsCode = JS_ERROR_INNER;

    uv_loop_s* loop = nullptr;
    NAPI_CALL_RETURN_VOID(this->reqContext_->env, napi_get_uv_event_loop(this->reqContext_->env, &loop));
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
    NAPI_CALL_RETURN_VOID(this->reqContext_->env, uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {}, ResultCallbackJSThreadWorker, uv_qos_user_initiated));
    uvWorkPtr.release();
    callbackPtr.release();
    return;
}

SwitchOnSettingUICallback::SwitchOnSettingUICallback(
    const std::shared_ptr<RequestGlobalSwitchAsyncContext>& reqContext)
{
    this->reqContext_ = reqContext;
}

SwitchOnSettingUICallback::~SwitchOnSettingUICallback()
{}

void SwitchOnSettingUICallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

/*
 * when UIExtensionAbility use terminateSelfWithResult
 */
void SwitchOnSettingUICallback::OnResult(int32_t resultCode, const AAFwk::Want& result)
{
    int32_t errorCode = result.GetIntParam(RESULT_ERROR_KEY, 0);
    bool switchStatus = result.GetBoolParam(GLOBAL_SWITCH_RESULT_KEY, 0);
    ACCESSTOKEN_LOG_INFO(LABEL, "ResultCode is %{public}d, errorCode=%{public}d, switchStatus=%{public}d",
        resultCode, errorCode, switchStatus);
    {
        std::lock_guard<std::mutex> lock(g_lockFlag);
        this->reqContext_->resultCode = 0;
    }

    GlobalSwitchResultsCallbackUI(TransferToJsErrorCode(errorCode), switchStatus, this->reqContext_);
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void SwitchOnSettingUICallback::OnReceive(const AAFwk::WantParams& receive)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Called!");
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void SwitchOnSettingUICallback::OnRelease(int32_t releaseCode)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ReleaseCode is %{public}d", releaseCode);

    ReleaseOrErrorHandle(releaseCode);
}

/*
 * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
 */
void SwitchOnSettingUICallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Code is %{public}d, name is %{public}s, message is %{public}s",
        code, name.c_str(), message.c_str());

    ReleaseOrErrorHandle(code);
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void SwitchOnSettingUICallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Connect to UIExtensionAbility successfully.");
}

/*
 * when UIExtensionComponent destructed
 */
void SwitchOnSettingUICallback::OnDestroy()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "UIExtensionAbility destructed.");
    int32_t resultCode = -1;
    {
        std::lock_guard<std::mutex> lock(g_lockFlag);
        resultCode = this->reqContext_->resultCode;
    }
    ReleaseOrErrorHandle(resultCode);
}

static int32_t CreateUIExtension(const Want &want, std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext)
{
    Ace::UIContent* uiContent = GetUIContent(asyncContext);
    if (uiContent == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to get ui content!");
        asyncContext->result = RET_FAILED;
        return RET_FAILED;
    }
    auto uiExtCallback = std::make_shared<SwitchOnSettingUICallback>(asyncContext);
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
    ACCESSTOKEN_LOG_INFO(LABEL, "Create end, sessionId: %{public}d, tokenId: %{public}d, switchType: %{public}d.",
        sessionId, asyncContext->tokenId, asyncContext->switchType);
    if (sessionId == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to create component, sessionId is 0.");
        asyncContext->result = RET_FAILED;
        return RET_FAILED;
    }
    uiExtCallback->SetSessionId(sessionId);
    return JS_OK;
}

static int32_t StartUIExtension(std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext)
{
    AAFwk::Want want;
    AccessTokenKit::GetPermissionManagerInfo(asyncContext->info);
    ACCESSTOKEN_LOG_INFO(LABEL, "bundleName: %{public}s, globalSwitchAbilityName: %{public}s.",
        asyncContext->info.grantBundleName.c_str(), asyncContext->info.globalSwitchAbilityName.c_str());
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.globalSwitchAbilityName);
    want.SetParam(GLOBAL_SWITCH_KEY, asyncContext->switchType);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);

    return CreateUIExtension(want, asyncContext);
}

napi_value NapiRequestGlobalSwitch::RequestGlobalSwitch(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "RequestGlobalSwitch begin.");
    // use handle to protect asyncContext
    std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext =
        std::make_shared<RequestGlobalSwitchAsyncContext>(env);

    if (!ParseRequestGlobalSwitch(env, info, asyncContext)) {
        return nullptr;
    }
    auto asyncContextHandle = std::make_unique<RequestGlobalSwitchAsyncContextHandle>(asyncContext);
    napi_value result = nullptr;
    if (asyncContextHandle->asyncContextPtr->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &(asyncContextHandle->asyncContextPtr->deferred), &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr; // resource name
    NAPI_CALL(env, napi_create_string_utf8(env, "RequestGlobalSwitch", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, RequestGlobalSwitchExecute, RequestGlobalSwitchComplete,
        reinterpret_cast<void *>(asyncContextHandle.get()), &(asyncContextHandle->asyncContextPtr->work)));

    NAPI_CALL(env,
        napi_queue_async_work_with_qos(env, asyncContextHandle->asyncContextPtr->work, napi_qos_user_initiated));

    ACCESSTOKEN_LOG_DEBUG(LABEL, "RequestGlobalSwitch end.");
    asyncContextHandle.release();
    return result;
}

bool NapiRequestGlobalSwitch::ParseRequestGlobalSwitch(const napi_env& env,
    const napi_callback_info& cbInfo, std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext)
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

    // argv[1] : type
    if (!ParseInt32(env, argv[1], asyncContext->switchType)) {
        errMsg = GetParamErrorMsg("type", "SwitchType");
        NAPI_CALL_BASE(
            env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    return true;
}

void NapiRequestGlobalSwitch::RequestGlobalSwitchExecute(napi_env env, void* data)
{
    // asyncContext release in complete
    RequestGlobalSwitchAsyncContextHandle* asyncContextHandle =
        reinterpret_cast<RequestGlobalSwitchAsyncContextHandle*>(data);
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

void NapiRequestGlobalSwitch::RequestGlobalSwitchComplete(napi_env env, napi_status status, void* data)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "RequestGlobalSwitchComplete begin.");
    RequestGlobalSwitchAsyncContextHandle* asyncContextHandle =
        reinterpret_cast<RequestGlobalSwitchAsyncContextHandle*>(data);
    if (asyncContextHandle == nullptr && asyncContextHandle->asyncContextPtr == nullptr) {
        return;
    }
    std::unique_ptr<RequestGlobalSwitchAsyncContextHandle> callbackPtr {asyncContextHandle};

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