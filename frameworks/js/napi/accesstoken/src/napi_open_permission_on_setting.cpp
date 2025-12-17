/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "napi_open_permission_on_setting.h"

#include "ability.h"
#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "napi_base_context.h"
#include "hisysevent.h"
#include "permission_map.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::map<int32_t, std::vector<std::shared_ptr<OpenPermOnSettingAsyncContext>>>
    OpenOnSettingAsyncInstanceControl::instanceIdMap_;
std::mutex OpenOnSettingAsyncInstanceControl::instanceIdMutex_;
namespace {
const std::string PERMISSION_KEY = "ohos.open.setting.permission";
const std::string RESULT_CODE_KEY = "ohos.open.setting.result_code";
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string UI_EXTENSION_TYPE = "sys/commonUI";

// result code from dialog
constexpr int32_t USER_REJECTED = -1;
constexpr int32_t USER_OPENED = 0;
constexpr int32_t ALREADY_GRANTED = 1;
constexpr int32_t PERM_IS_NOT_DECLARE = 2;
constexpr int32_t PERM_IS_NOT_SUPPORTED = 3;

std::mutex g_lockFlag;
} // namespace
static inline void ReportHisysEventBehavior(const OpenPermOnSettingAsyncContext& context)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQUEST_PERMISSIONS_FROM_USER",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "BUNDLENAME", context.bundleName,
        "UIEXTENSION_FLAG", true,
        "SCENE_CODE", context.contextType_,
        "TOKENID", context.tokenId,
        "EXTRA_INFO", context.permissionName
    );
}

static inline void ReportHisysEventError(
    const OpenPermOnSettingAsyncContext& context, int32_t errorCode, int32_t innerCode)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQ_PERM_FROM_USER_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "ERROR_CODE", errorCode,
        "CONTEXT_TOKEN", context.tokenId,
        "INNER_CODE", innerCode,
        "BUNDLENAME", context.bundleName,
        "SCENE_CODE", context.contextType_,
        "EXTRA_INFO", context.permissionName
    );
}

static int32_t TransferToJsErrorCode(int32_t errCode)
{
    int32_t jsCode = JS_OK;
    switch (errCode) {
        case ERR_OK:
            jsCode = JS_OK;
            break;
        case ERR_PARAM_INVALID:
            jsCode = JS_ERROR_PARAM_INVALID;
            break;
        case ERR_EXPECTED_PERMISSION_TYPE:
            jsCode = JS_ERROR_EXPECTED_PERMISSION_TYPE;
            break;
        // ability inner error
        default:
            jsCode = JS_ERROR_INNER;
            break;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "dialog error(%{public}d) jsCode(%{public}d).", errCode, jsCode);
    return jsCode;
}

static void ReturnPromiseResult(napi_env env, OpenPermOnSettingAsyncContext& context, napi_value result)
{
    if (context.deferred == nullptr) {
        return;
    }
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

static Ace::UIContent* GetUIContent(std::shared_ptr<OpenPermOnSettingAsyncContext> asyncContext)
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
    const napi_env &env, const napi_value &value, std::shared_ptr<OpenPermOnSettingAsyncContext>& asyncContext)
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

static void PermissionResultsCallbackUI(std::shared_ptr<OpenPermOnSettingAsyncContext>& data)
{
    auto* retCB = new (std::nothrow) OpenPermOnSettingResultCallback();
    if (retCB == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Insufficient memory for work!");
        return;
    }

    std::unique_ptr<OpenPermOnSettingResultCallback> callbackPtr {retCB};
    retCB->data = data;
    auto task = [retCB]() {
        std::shared_ptr<OpenPermOnSettingAsyncContext> asyncContext = retCB->data;
        if (asyncContext == nullptr) {
            delete retCB;
            return;
        }

        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(asyncContext->env, &scope);
        if (scope == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Napi_open_handle_scope failed");
            delete retCB;
            return;
        }

        napi_value requestResult;
        napi_create_int32(asyncContext->env, asyncContext->resultCode, &requestResult);

        ReturnPromiseResult(asyncContext->env, *asyncContext, requestResult);
        napi_close_handle_scope(asyncContext->env, scope);
        delete retCB;
    };
    if (napi_status::napi_ok != napi_send_event(data->env, task, napi_eprio_immediate, "PermissionResultsCallbackUI")) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionResultsCallbackUI: Failed to SendEvent");
    } else {
        callbackPtr.release();
    }
}

static void CloseModalUIExtensionMainThread(std::shared_ptr<OpenPermOnSettingAsyncContext>& asyncContext,
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

void OpenPermOnSettingUICallback::ReleaseHandler(int32_t code)
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
        this->reqContext_->result.errorCode = code;
    }
    OpenOnSettingAsyncInstanceControl::UpdateQueueData(this->reqContext_);
    OpenOnSettingAsyncInstanceControl::ExecCallback(this->reqContext_->instanceId);
    PermissionResultsCallbackUI(this->reqContext_);
}

OpenPermOnSettingUICallback::OpenPermOnSettingUICallback(
    const std::shared_ptr<OpenPermOnSettingAsyncContext>& reqContext)
{
    this->reqContext_ = reqContext;
    isOnResult_.exchange(false);
}

OpenPermOnSettingUICallback::~OpenPermOnSettingUICallback()
{}

void OpenPermOnSettingUICallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

/*
 * when UIExtensionAbility use terminateSelfWithResult
 */
void OpenPermOnSettingUICallback::OnResult(int32_t resultCode, const AAFwk::Want& result)
{
    if (this->reqContext_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Request context is null.");
        return;
    }
    isOnResult_.exchange(true);
    this->reqContext_->resultCode = result.GetIntParam(RESULT_CODE_KEY, 0);
    switch (this->reqContext_->resultCode) {
        case USER_REJECTED:
        case USER_OPENED:
        case ALREADY_GRANTED:
            this->reqContext_->result.errorCode = ERR_OK;
            break;
        case PERM_IS_NOT_DECLARE:
        case PERM_IS_NOT_SUPPORTED:
            this->reqContext_->result.errorCode = ERR_PARAM_INVALID;
            this->reqContext_->result.errorMsg = "The permission is invalid or not declared in the module.json file.";
            break;
        default:
            this->reqContext_->result.errorCode = RET_FAILED;
            break;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "ResultCode=%{public}d, errorCode=%{public}d",
        this->reqContext_->resultCode, this->reqContext_->result.errorCode);
    ReleaseHandler(0);
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void OpenPermOnSettingUICallback::OnReceive(const AAFwk::WantParams& receive)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Called!");
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void OpenPermOnSettingUICallback::OnRelease(int32_t releaseCode)
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
void OpenPermOnSettingUICallback::OnError(int32_t code, const std::string& name, const std::string& message)
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
void OpenPermOnSettingUICallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Connect to UIExtensionAbility successfully.");
}

/*
 * when UIExtensionComponent destructed
 */
void OpenPermOnSettingUICallback::OnDestroy()
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

static void CreateUIExtensionMainThread(std::shared_ptr<OpenPermOnSettingAsyncContext>& asyncContext,
    const AAFwk::Want& want, const Ace::ModalUIExtensionCallbacks& uiExtensionCallbacks,
    const std::shared_ptr<OpenPermOnSettingUICallback>& uiExtCallback)
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
        LOGI(ATM_DOMAIN, ATM_TAG, "Create end, sessionId: %{public}d, tokenId: %{public}d.",
            sessionId, asyncContext->tokenId);
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

static int32_t CreateUIExtension(const Want &want, std::shared_ptr<OpenPermOnSettingAsyncContext> asyncContext)
{
    auto uiExtCallback = std::make_shared<OpenPermOnSettingUICallback>(asyncContext);
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
        [uiExtCallback](int32_t code, const std::string &name, const std::string &message) {
            uiExtCallback->OnError(code, name, message);
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

static int32_t StartUIExtension(std::shared_ptr<OpenPermOnSettingAsyncContext> asyncContext)
{
    AAFwk::Want want;
    AccessTokenKit::GetPermissionManagerInfo(asyncContext->info);
    LOGI(ATM_DOMAIN, ATM_TAG, "bundleName: %{public}s, openSettingAbilityName: %{public}s, permissionName: %{public}s.",
        asyncContext->info.grantBundleName.c_str(), asyncContext->info.openSettingAbilityName.c_str(),
        asyncContext->permissionName.c_str());
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.openSettingAbilityName);
    want.SetParam(PERMISSION_KEY, asyncContext->permissionName);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);
    return CreateUIExtension(want, asyncContext);
}

static void GetInstanceId(std::shared_ptr<OpenPermOnSettingAsyncContext>& asyncContext)
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

void OpenOnSettingAsyncInstanceControl::AddCallbackByInstanceId(
    std::shared_ptr<OpenPermOnSettingAsyncContext>& asyncContext)
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

void OpenOnSettingAsyncInstanceControl::UpdateQueueData(
    const std::shared_ptr<OpenPermOnSettingAsyncContext>& reqContext)
{
    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        int32_t id = reqContext->instanceId;
        auto iter = instanceIdMap_.find(id);
        if (iter == instanceIdMap_.end()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d not existed.", id);
            return;
        }
        LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d", id);
        for (auto& asyncContext : iter->second) {
            if (asyncContext == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
                continue;
            }
            // repeated request
            if (asyncContext->permissionName == reqContext->permissionName) {
                asyncContext->result.errorCode = reqContext->result.errorCode;
                asyncContext->result.errorMsg = reqContext->result.errorMsg;
                asyncContext->resultCode = reqContext->resultCode;
                asyncContext->isDynamic = false;
            }
        }
    }
}

void OpenOnSettingAsyncInstanceControl::ExecCallback(int32_t id)
{
    std::shared_ptr<OpenPermOnSettingAsyncContext> asyncContext = nullptr;
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

void OpenOnSettingAsyncInstanceControl::CheckDynamicRequest(
    std::shared_ptr<OpenPermOnSettingAsyncContext>& asyncContext, bool& isDynamic)
{
    isDynamic = asyncContext->isDynamic;
    if (!isDynamic) {
        LOGI(ATM_DOMAIN, ATM_TAG, "It does not need to open permission exsion");
        PermissionResultsCallbackUI(asyncContext);
        return;
    }
}

napi_value NapiOpenPermissionOnSetting::OpenPermissionOnSetting(napi_env env, napi_callback_info info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "OpenPermissionOnSetting begin.");
    // use handle to protect asyncContext
    std::shared_ptr<OpenPermOnSettingAsyncContext> asyncContext =
        std::make_shared<OpenPermOnSettingAsyncContext>(env);

    if (!ParseOpenPermissionOnSetting(env, info, asyncContext)) {
        return nullptr;
    }
    auto asyncContextHandle = std::make_unique<OpenOnSettingAsyncContextHandle>(asyncContext);
    if (asyncContextHandle->asyncContextPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Async context is null.");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &(asyncContextHandle->asyncContextPtr->deferred), &result));

    napi_value resource = nullptr; // resource name
    NAPI_CALL(env, napi_create_string_utf8(env, "OpenPermissionOnSetting", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, OpenPermissionOnSettingExecute, OpenPermissionOnSettingComplete,
        reinterpret_cast<void*>(asyncContextHandle.get()), &(asyncContextHandle->asyncContextPtr->work)));

    NAPI_CALL(env,
        napi_queue_async_work_with_qos(env, asyncContextHandle->asyncContextPtr->work, napi_qos_user_initiated));

    LOGD(ATM_DOMAIN, ATM_TAG, "OpenPermissionOnSetting end.");
    asyncContextHandle.release();
    return result;
}

bool NapiOpenPermissionOnSetting::ParseOpenPermissionOnSetting(const napi_env& env,
    const napi_callback_info& cbInfo, std::shared_ptr<OpenPermOnSettingAsyncContext>& asyncContext)
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

    // argv[1] : permissionName
    if (!ParseString(env, argv[1], asyncContext->permissionName) ||
        (asyncContext->permissionName.empty())) {
        errMsg = GetParamErrorMsg("permission", "Permissions");
        NAPI_CALL_BASE(
            env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
#ifdef EVENTHANDLER_ENABLE
    asyncContext->handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
#endif
    return true;
}

bool NapiOpenPermissionOnSetting::CheckManualSettingPerm(
    std::shared_ptr<OpenPermOnSettingAsyncContext>& asyncContextPtr)
{
    PermissionBriefDef permissionBriefDef;
    if (!GetPermissionBriefDef(asyncContextPtr->permissionName, permissionBriefDef)) {
        asyncContextPtr->result.errorCode = ERR_PARAM_INVALID;
        asyncContextPtr->result.errorMsg = "The permission is invalid.";
        return true;
    }

    if (permissionBriefDef.grantMode != MANUAL_SETTINGS) {
        asyncContextPtr->result.errorCode = ERR_EXPECTED_PERMISSION_TYPE;
        asyncContextPtr->result.errorMsg = "The permission is not a manual_settings permission.";
        return true;
    }
    return false;
}

void NapiOpenPermissionOnSetting::OpenPermissionOnSettingExecute(napi_env env, void* data)
{
    // asyncContext release in complete
    OpenOnSettingAsyncContextHandle* asyncContextHandle =
        reinterpret_cast<OpenOnSettingAsyncContextHandle*>(data);
    if ((asyncContextHandle == nullptr) || (asyncContextHandle->asyncContextPtr == nullptr)) {
        return;
    }

    if (CheckManualSettingPerm(asyncContextHandle->asyncContextPtr)) {
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
            "The context is invalid because it does not belong to the application itself.";
        return;
    }

    GetInstanceId(asyncContextHandle->asyncContextPtr);
    LOGI(ATM_DOMAIN, ATM_TAG, "Start to pop ui extension dialog");
    ReportHisysEventBehavior(*asyncContextHandle->asyncContextPtr);
    OpenOnSettingAsyncInstanceControl::AddCallbackByInstanceId(asyncContextHandle->asyncContextPtr);
    if (asyncContextHandle->asyncContextPtr->result.errorCode != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Failed to pop uiextension dialog.");
    }
}

void NapiOpenPermissionOnSetting::OpenPermissionOnSettingComplete(napi_env env, napi_status status, void* data)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "OpenPermissionOnSettingComplete begin.");
    OpenOnSettingAsyncContextHandle* asyncContextHandle =
        reinterpret_cast<OpenOnSettingAsyncContextHandle*>(data);
    if (asyncContextHandle == nullptr || asyncContextHandle->asyncContextPtr == nullptr) {
        return;
    }
    std::unique_ptr<OpenOnSettingAsyncContextHandle> callbackPtr {asyncContextHandle};

    // need pop dialog
    if (asyncContextHandle->asyncContextPtr->result.errorCode == RET_SUCCESS) {
        return;
    }
    // return error
    if (asyncContextHandle->asyncContextPtr->deferred != nullptr) {
        int32_t jsCode = GetJsErrorCode(asyncContextHandle->asyncContextPtr->result.errorCode);
        napi_value businessError = GenerateBusinessError(env, jsCode,
            GetErrorMessage(jsCode, asyncContextHandle->asyncContextPtr->result.errorMsg));
        NAPI_CALL_RETURN_VOID(env,
            napi_reject_deferred(env, asyncContextHandle->asyncContextPtr->deferred, businessError));
    }
    asyncContextHandle->asyncContextPtr->deferred = nullptr;
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS