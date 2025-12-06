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
#include "accesstoken_common_log.h"
#include "hisysevent.h"
#include "napi_base_context.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::map<int32_t, std::vector<std::shared_ptr<RequestGlobalSwitchAsyncContext>>>
    RequestGlobalSwitchAsyncInstanceControl::instanceIdMap_;
std::mutex RequestGlobalSwitchAsyncInstanceControl::instanceIdMutex_;
namespace {
const std::string GLOBAL_SWITCH_KEY = "ohos.user.setting.global_switch";
const std::string GLOBAL_SWITCH_RESULT_KEY = "ohos.user.setting.global_switch.result";
const std::string RESULT_ERROR_KEY = "ohos.user.setting.error_code";
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string UI_EXTENSION_TYPE = "sys/commonUI";

// error code from dialog
const int32_t REQUEST_ALREADY_EXIST = 1;
const int32_t GLOBAL_TYPE_IS_NOT_SUPPORT = 2;
const int32_t SWITCH_IS_ALREADY_OPEN = 3;
std::mutex g_lockFlag;
} // namespace
static int32_t TransferToJsErrorCode(int32_t errCode)
{
    int32_t jsCode = JS_ERROR_INNER;
    switch (errCode) {
        case RET_SUCCESS:
            jsCode = JS_OK;
            break;
        case REQUEST_ALREADY_EXIST:
            jsCode = JS_ERROR_REQUEST_IS_ALREADY_EXIST;
            break;
        case GLOBAL_TYPE_IS_NOT_SUPPORT:
            jsCode = JS_ERROR_PARAM_INVALID;
            break;
        case SWITCH_IS_ALREADY_OPEN:
            jsCode = JS_ERROR_GLOBAL_SWITCH_IS_ALREADY_OPEN;
            break;
        default:
            break;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Dialog error(%{public}d) jsCode(%{public}d).", errCode, jsCode);
    return jsCode;
}

static inline void ReportHisysEventBehavior(const RequestGlobalSwitchAsyncContext& context)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQUEST_PERMISSIONS_FROM_USER",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "BUNDLENAME", context.bundleName,
        "UIEXTENSION_FLAG", true,
        "SCENE_CODE", context.contextType_,
        "TOKENID", context.tokenId,
        "EXTRA_INFO", std::to_string(context.switchType)
    );
}

static inline void ReportHisysEventError(
    const RequestGlobalSwitchAsyncContext& context, int32_t errorCode, int32_t innerCode)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQ_PERM_FROM_USER_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "ERROR_CODE", errorCode,
        "CONTEXT_TOKEN", context.tokenId,
        "INNER_CODE", innerCode,
        "BUNDLENAME", context.bundleName,
        "SCENE_CODE", context.contextType_,
        "EXTRA_INFO", std::to_string(context.switchType)
    );
}

static void ReturnPromiseResult(napi_env env, RequestGlobalSwitchAsyncContext& context, napi_value result)
{
    if (context.result.errorCode != RET_SUCCESS) {
        int32_t jsCode = TransferToJsErrorCode(context.result.errorCode);
        napi_value businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode, context.result.errorMsg));
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, context.deferred, businessError));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, context.deferred, result));
    }
    context.deferred = nullptr;
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
        LOGE(ATM_DOMAIN, ATM_TAG, "It is not a stage mode.");
        return nullptr;
    } else {
        auto context = AbilityRuntime::GetStageModeContext(env, value);
        if (context == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Get application context.");
            return nullptr;
        }
        asyncContext->abilityContext =
            AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
        if (asyncContext->abilityContext != nullptr) {
            asyncContext->uiAbilityFlag = true;
        } else {
            LOGW(ATM_DOMAIN, ATM_TAG, "Failed to convert to ability context.");
            asyncContext->uiExtensionContext =
                AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(context);
            if (asyncContext->uiExtensionContext == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Failed to convert to ui extension context.");
                return nullptr;
            }
        }
        return WrapVoidToJS(env);
    }
}

static void GlobalSwitchResultsCallbackUI(int32_t errorCode,
    bool switchStatus, std::shared_ptr<RequestGlobalSwitchAsyncContext>& data)
{
    auto* retCB = new (std::nothrow) SwitchOnSettingResultCallback();
    if (retCB == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Insufficient memory for work!");
        return;
    }
    std::unique_ptr<SwitchOnSettingResultCallback> callbackPtr {retCB};
    retCB->errorCode = errorCode;
    retCB->switchStatus = switchStatus;
    retCB->data = data;
    auto task = [retCB]() {
        std::unique_ptr<SwitchOnSettingResultCallback> callback {retCB};
        std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext = retCB->data;
        if (asyncContext == nullptr) {
            return;
        }
        asyncContext->result.errorCode = retCB->errorCode;
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(asyncContext->env, &scope);
        if (scope == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Napi_open_handle_scope failed");
            return;
        }
        napi_value requestResult = nullptr;
        NAPI_CALL_RETURN_VOID(asyncContext->env,
            napi_get_boolean(asyncContext->env, retCB->switchStatus, &requestResult));

        ReturnPromiseResult(asyncContext->env, *asyncContext, requestResult);
        napi_close_handle_scope(asyncContext->env, scope);
    };
    if (napi_status::napi_ok !=
        napi_send_event(data->env, task, napi_eprio_immediate, "GlobalSwitchResultsCallbackUI")) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GlobalSwitchResultsCallbackUI: Failed to SendEvent");
    } else {
        callbackPtr.release();
    }
}

static void CloseModalUIExtensionMainThread(std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext,
    int32_t sessionId)
{
    auto task = [asyncContext, sessionId]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext);
        if (uiContent == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get ui content failed!");
            return;
        }
        LOGI(ATM_DOMAIN, ATM_TAG, "Close uiextension component");
        uiContent->CloseModalUIExtension(sessionId);
    };
#ifdef EVENTHANDLER_ENABLE
    if (asyncContext->handler_ != nullptr) {
        asyncContext->handler_->PostSyncTask(task, "AT:CloseModalUIExtensionMainThread");
    } else {
        task();
    }
#else
    task();
#endif
}

void SwitchOnSettingUICallback::ReleaseHandler(int32_t code)
{
    if (this->reqContext_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Request context is null.");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(g_lockFlag);
        if (this->reqContext_->releaseFlag) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Callback has executed.");
            return;
        }
        this->reqContext_->releaseFlag = true;
    }
    CloseModalUIExtensionMainThread(this->reqContext_, this->sessionId_);
    if (code == -1) {
        this->reqContext_->errorCode = code;
    }
    RequestGlobalSwitchAsyncInstanceControl::UpdateQueueData(this->reqContext_);
    RequestGlobalSwitchAsyncInstanceControl::ExecCallback(this->reqContext_->instanceId);
    GlobalSwitchResultsCallbackUI(this->reqContext_->errorCode, this->reqContext_->switchStatus, this->reqContext_);
}

SwitchOnSettingUICallback::SwitchOnSettingUICallback(
    const std::shared_ptr<RequestGlobalSwitchAsyncContext>& reqContext)
{
    this->reqContext_ = reqContext;
    isOnResult_.exchange(false);
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
    if (this->reqContext_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Request context is null.");
        return;
    }
    isOnResult_.exchange(true);
    this->reqContext_->errorCode = result.GetIntParam(RESULT_ERROR_KEY, 0);
    this->reqContext_->switchStatus = result.GetBoolParam(GLOBAL_SWITCH_RESULT_KEY, 0);
    LOGI(ATM_DOMAIN, ATM_TAG, "ResultCode is %{public}d, errorCode=%{public}d, switchStatus=%{public}d",
        resultCode, this->reqContext_->errorCode, this->reqContext_->switchStatus);
    ReleaseHandler(0);
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void SwitchOnSettingUICallback::OnReceive(const AAFwk::WantParams& receive)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Called!");
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void SwitchOnSettingUICallback::OnRelease(int32_t releaseCode)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ReleaseCode is %{public}d", releaseCode);
    if (this->reqContext_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Request context is null.");
        return;
    }
    ReportHisysEventError(*reqContext_, TRIGGER_RELEASE, releaseCode);
    ReleaseHandler(-1);
}

/*
 * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
 */
void SwitchOnSettingUICallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Code is %{public}d, name is %{public}s, message is %{public}s",
        code, name.c_str(), message.c_str());
    if (this->reqContext_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Request context is null.");
        return;
    }
    ReportHisysEventError(*reqContext_, TRIGGER_ONERROR, code);
    ReleaseHandler(-1);
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void SwitchOnSettingUICallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Connect to UIExtensionAbility successfully.");
}

/*
 * when UIExtensionComponent destructed
 */
void SwitchOnSettingUICallback::OnDestroy()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UIExtensionAbility destructed.");
    if (this->reqContext_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Request context is null.");
        return;
    }
    if (isOnResult_.load() == false) {
        ReportHisysEventError(*reqContext_, TRIGGER_DESTROY, 0);
    }
    ReleaseHandler(-1);
}

static void CreateUIExtensionMainThread(std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext,
    const AAFwk::Want& want, const Ace::ModalUIExtensionCallbacks& uiExtensionCallbacks,
    const std::shared_ptr<SwitchOnSettingUICallback>& uiExtCallback)
{
    auto task = [asyncContext, want, uiExtensionCallbacks, uiExtCallback]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext);
        if (uiContent == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get ui content!");
            asyncContext->result.errorCode = RET_FAILED;
            return;
        }

        Ace::ModalUIExtensionConfig config;
        config.isProhibitBack = true;
        config.isModalRequestFocus = false;
        int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
        LOGI(ATM_DOMAIN, ATM_TAG, "Create end, sessionId: %{public}d, tokenId: %{public}d, switchType: %{public}d.",
            sessionId, asyncContext->tokenId, asyncContext->switchType);
        if (sessionId == 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create component, sessionId is 0.");
            asyncContext->result.errorCode = RET_FAILED;
            ReportHisysEventError(*asyncContext, CREATE_MODAL_UI_FAILED, 0);
            return;
        }
        uiExtCallback->SetSessionId(sessionId);
    };
#ifdef EVENTHANDLER_ENABLE
    if (asyncContext->handler_ != nullptr) {
        asyncContext->handler_->PostSyncTask(task, "AT:CreateUIExtensionMainThread");
    } else {
        task();
    }
#else
    task();
#endif
}

static int32_t CreateUIExtension(const Want &want, std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext)
{
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

    CreateUIExtensionMainThread(asyncContext, want, uiExtensionCallbacks, uiExtCallback);
    if (asyncContext->result.errorCode == RET_FAILED) {
        return RET_FAILED;
    }
    return RET_SUCCESS;
}

static int32_t StartUIExtension(std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext)
{
    AAFwk::Want want;
    AccessTokenKit::GetPermissionManagerInfo(asyncContext->info);
    LOGI(ATM_DOMAIN, ATM_TAG, "bundleName: %{public}s, globalSwitchAbilityName: %{public}s.",
        asyncContext->info.grantBundleName.c_str(), asyncContext->info.globalSwitchAbilityName.c_str());
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.globalSwitchAbilityName);
    want.SetParam(GLOBAL_SWITCH_KEY, asyncContext->switchType);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);

    return CreateUIExtension(want, asyncContext);
}

static void GetInstanceId(std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext)
{
    auto task = [asyncContext]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext);
        if (uiContent == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get ui content failed!");
            ReportHisysEventError(*asyncContext, GET_UI_CONTENT_FAILED, 0);
            return;
        }
        asyncContext->instanceId = uiContent->GetInstanceId();
    };
#ifdef EVENTHANDLER_ENABLE
    if (asyncContext->handler_ != nullptr) {
        asyncContext->handler_->PostSyncTask(task, "AT:GetInstanceId");
    } else {
        task();
    }
#else
    task();
#endif
    LOGI(ATM_DOMAIN, ATM_TAG, "Instance id: %{public}d", asyncContext->instanceId);
}

void RequestGlobalSwitchAsyncInstanceControl::AddCallbackByInstanceId(
    std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "InstanceId: %{public}d", asyncContext->instanceId);
    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        auto iter = instanceIdMap_.find(asyncContext->instanceId);
        // id is existed mean a pop window is showing, add context to waiting queue
        if (iter != instanceIdMap_.end()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "InstanceId: %{public}d has existed.", asyncContext->instanceId);
            instanceIdMap_[asyncContext->instanceId].emplace_back(asyncContext);
            return;
        }
        // make sure id is in map to indicate a pop-up window is showing
        instanceIdMap_[asyncContext->instanceId] = {};
    }
    (void)StartUIExtension(asyncContext);
}

void RequestGlobalSwitchAsyncInstanceControl::UpdateQueueData(
    const std::shared_ptr<RequestGlobalSwitchAsyncContext>& reqContext)
{
    if ((reqContext->errorCode != RET_SUCCESS) || !(reqContext->switchStatus)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "The queue data does not need to be updated.");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        int32_t id = reqContext->instanceId;
        auto iter = instanceIdMap_.find(id);
        if (iter == instanceIdMap_.end()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d not existed.", id);
            return;
        }
        int32_t targetSwitchType = reqContext->switchType;
        LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d, map size: %{public}zu.", id, iter->second.size());
        for (auto& asyncContext : iter->second) {
            if (asyncContext == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
                continue;
            }
            if (targetSwitchType == asyncContext->switchType) {
                asyncContext->errorCode = reqContext->errorCode;
                asyncContext->switchStatus = reqContext->switchStatus;
                asyncContext->isDynamic = false;
            }
        }
    }
}

void RequestGlobalSwitchAsyncInstanceControl::ExecCallback(int32_t id)
{
    std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext = nullptr;
    bool isDynamic = false;
    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        auto iter = instanceIdMap_.find(id);
        if (iter == instanceIdMap_.end()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d not existed.", id);
            return;
        }
        while (!iter->second.empty()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d, map size: %{public}zu.", id, iter->second.size());
            asyncContext = iter->second[0];
            if (asyncContext == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
                iter->second.erase(iter->second.begin());
                continue;
            }
            iter->second.erase(iter->second.begin());
            CheckDynamicRequest(asyncContext, isDynamic);
            if (isDynamic) {
                break;
            }
        }
        if (iter->second.empty()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d, map is empty", id);
            instanceIdMap_.erase(id);
        }
    }
    if (isDynamic) {
        (void)StartUIExtension(asyncContext);
    }
}

void RequestGlobalSwitchAsyncInstanceControl::CheckDynamicRequest(
    std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext, bool& isDynamic)
{
    isDynamic = asyncContext->isDynamic;
    if (!isDynamic) {
        LOGI(ATM_DOMAIN, ATM_TAG, "It does not need to request permission exsion");
        GlobalSwitchResultsCallbackUI(asyncContext->errorCode, asyncContext->switchStatus, asyncContext);
        return;
    }
}

napi_value NapiRequestGlobalSwitch::RequestGlobalSwitch(napi_env env, napi_callback_info info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "RequestGlobalSwitch begin.");
    // use handle to protect asyncContext
    std::shared_ptr<RequestGlobalSwitchAsyncContext> asyncContext =
        std::make_shared<RequestGlobalSwitchAsyncContext>(env);

    if (!ParseRequestGlobalSwitch(env, info, asyncContext)) {
        return nullptr;
    }
    auto asyncContextHandle = std::make_unique<RequestGlobalSwitchAsyncContextHandle>(asyncContext);
    if (asyncContextHandle->asyncContextPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
        return nullptr;
    }
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
        reinterpret_cast<void*>(asyncContextHandle.get()), &(asyncContextHandle->asyncContextPtr->work)));

    NAPI_CALL(env,
        napi_queue_async_work_with_qos(env, asyncContextHandle->asyncContextPtr->work, napi_qos_user_initiated));

    LOGD(ATM_DOMAIN, ATM_TAG, "RequestGlobalSwitch end.");
    asyncContextHandle.release();
    return result;
}

bool NapiRequestGlobalSwitch::ParseRequestGlobalSwitch(const napi_env& env,
    const napi_callback_info& cbInfo, std::shared_ptr<RequestGlobalSwitchAsyncContext>& asyncContext)
{
    size_t argc = MAX_PARAMS_TWO;
    napi_value argv[MAX_PARAMS_TWO] = { nullptr };
    napi_value thisVar = nullptr;

    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr) != napi_ok) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Napi_get_cb_info failed");
        return false;
    }
    if (argc < MAX_PARAMS_TWO) {
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
    LOGI(ATM_DOMAIN, ATM_TAG, "AsyncContext.uiAbilityFlag is: %{public}d.", asyncContext->uiAbilityFlag);

    // argv[1] : type
    if (!ParseInt32(env, argv[1], asyncContext->switchType)) {
        errMsg = GetParamErrorMsg("type", "SwitchType");
        NAPI_CALL_BASE(
            env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
#ifdef EVENTHANDLER_ENABLE
    asyncContext->handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
#endif
    return true;
}

void NapiRequestGlobalSwitch::RequestGlobalSwitchExecute(napi_env env, void* data)
{
    // asyncContext release in complete
    RequestGlobalSwitchAsyncContextHandle* asyncContextHandle =
        reinterpret_cast<RequestGlobalSwitchAsyncContextHandle*>(data);
    if ((asyncContextHandle == nullptr) || (asyncContextHandle->asyncContextPtr == nullptr)) {
        return;
    }
    if (asyncContextHandle->asyncContextPtr->uiAbilityFlag) {
        if ((asyncContextHandle->asyncContextPtr->abilityContext == nullptr) ||
            (asyncContextHandle->asyncContextPtr->abilityContext->GetApplicationInfo() == nullptr)) {
            return;
        }
        asyncContextHandle->asyncContextPtr->tokenId =
            asyncContextHandle->asyncContextPtr->abilityContext->GetApplicationInfo()->accessTokenId;
        asyncContextHandle->asyncContextPtr->bundleName =
            asyncContextHandle->asyncContextPtr->abilityContext->GetApplicationInfo()->bundleName;
    } else {
        if ((asyncContextHandle->asyncContextPtr->uiExtensionContext == nullptr) ||
            (asyncContextHandle->asyncContextPtr->uiExtensionContext->GetApplicationInfo() == nullptr)) {
            return;
        }
        asyncContextHandle->asyncContextPtr->tokenId =
            asyncContextHandle->asyncContextPtr->uiExtensionContext->GetApplicationInfo()->accessTokenId;
        asyncContextHandle->asyncContextPtr->bundleName =
            asyncContextHandle->asyncContextPtr->uiExtensionContext->GetApplicationInfo()->bundleName;
    }
    static AccessTokenID currToken = static_cast<AccessTokenID>(GetSelfTokenID());
    if (asyncContextHandle->asyncContextPtr->tokenId != currToken) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "The context(token=%{public}d) is not belong to the current application(currToken=%{public}d).",
            asyncContextHandle->asyncContextPtr->tokenId, currToken);
        asyncContextHandle->asyncContextPtr->result.errorCode = ERR_PARAM_INVALID;
        asyncContextHandle->asyncContextPtr->result.errorMsg =
            "The specified context does not belong to the current application.";
        return;
    }

    GetInstanceId(asyncContextHandle->asyncContextPtr);
    LOGI(ATM_DOMAIN, ATM_TAG, "Start to pop ui extension dialog");
    ReportHisysEventBehavior(*asyncContextHandle->asyncContextPtr);
    RequestGlobalSwitchAsyncInstanceControl::AddCallbackByInstanceId(asyncContextHandle->asyncContextPtr);
    if (asyncContextHandle->asyncContextPtr->result.errorCode != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Failed to pop uiextension dialog.");
    }
}

void NapiRequestGlobalSwitch::RequestGlobalSwitchComplete(napi_env env, napi_status status, void* data)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RequestGlobalSwitchComplete begin.");
    RequestGlobalSwitchAsyncContextHandle* asyncContextHandle =
        reinterpret_cast<RequestGlobalSwitchAsyncContextHandle*>(data);
    if (asyncContextHandle == nullptr || asyncContextHandle->asyncContextPtr == nullptr) {
        return;
    }
    std::unique_ptr<RequestGlobalSwitchAsyncContextHandle> callbackPtr {asyncContextHandle};

    // need pop dialog
    if (asyncContextHandle->asyncContextPtr->result.errorCode == RET_SUCCESS) {
        return;
    }
    // return error
    if (asyncContextHandle->asyncContextPtr->deferred != nullptr) {
        int32_t jsCode = GetJsErrorCode(asyncContextHandle->asyncContextPtr->result.errorCode);
        napi_value businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode));
        NAPI_CALL_RETURN_VOID(env,
            napi_reject_deferred(env, asyncContextHandle->asyncContextPtr->deferred, businessError));
        asyncContextHandle->asyncContextPtr->deferred = nullptr;
    } else {
        LOGI(ATM_DOMAIN, ATM_TAG, "Process completed, no need to return repeatedly.");
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS