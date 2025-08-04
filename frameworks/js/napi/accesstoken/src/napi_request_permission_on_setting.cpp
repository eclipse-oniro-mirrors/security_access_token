/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "accesstoken_common_log.h"
#include "napi_base_context.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::map<int32_t, std::vector<std::shared_ptr<RequestPermOnSettingAsyncContext>>>
    RequestOnSettingAsyncInstanceControl::instanceIdMap_;
std::mutex RequestOnSettingAsyncInstanceControl::instanceIdMutex_;
namespace {
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
    LOGI(ATM_DOMAIN, ATM_TAG, "dialog error(%{public}d) jsCode(%{public}d).", errCode, jsCode);
    return jsCode;
}

static void ReturnPromiseResult(napi_env env, const RequestPermOnSettingAsyncContext& context, napi_value result)
{
    if (context.result.errorCode != RET_SUCCESS) {
        int32_t jsCode = TransferToJsErrorCode(context.result.errorCode);
        napi_value businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode, context.result.errorMsg));
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, context.deferred, businessError));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, context.deferred, result));
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

static void PermissionResultsCallbackUI(int32_t errorCode,
    const std::vector<int32_t> stateList, std::shared_ptr<RequestPermOnSettingAsyncContext>& data)
{
    auto* retCB = new (std::nothrow) PermissonOnSettingResultCallback();
    if (retCB == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Insufficient memory for work!");
        return;
    }

    std::unique_ptr<PermissonOnSettingResultCallback> callbackPtr {retCB};
    retCB->errorCode = errorCode;
    retCB->stateList = stateList;
    retCB->data = data;
    auto task = [retCB]() {
        std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext = retCB->data;
        if (asyncContext == nullptr) {
            delete retCB;
            return;
        }

        asyncContext->result.errorCode = retCB->errorCode;
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(asyncContext->env, &scope);
        if (scope == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Napi_open_handle_scope failed");
            delete retCB;
            return;
        }
        napi_value requestResult = WrapRequestResult(asyncContext->env, retCB->stateList);
        if ((asyncContext->result.errorCode == RET_SUCCESS) && (requestResult == nullptr)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Wrap requestResult failed");
            asyncContext->result.errorCode = RET_FAILED;
        }

        ReturnPromiseResult(asyncContext->env, *asyncContext, requestResult);
        napi_close_handle_scope(asyncContext->env, scope);
        delete retCB;
    };
    if (napi_status::napi_ok != napi_send_event(data->env, task, napi_eprio_immediate)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionResultsCallbackUI: Failed to SendEvent");
    } else {
        callbackPtr.release();
    }
}

static void CloseModalUIExtensionMainThread(std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext,
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

void PermissonOnSettingUICallback::ReleaseHandler(int32_t code)
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
    RequestOnSettingAsyncInstanceControl::UpdateQueueData(this->reqContext_);
    RequestOnSettingAsyncInstanceControl::ExecCallback(this->reqContext_->instanceId);
    PermissionResultsCallbackUI(this->reqContext_->errorCode, this->reqContext_->stateList, this->reqContext_);
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
    LOGI(ATM_DOMAIN, ATM_TAG, "ResultCode is %{public}d, errorCode=%{public}d, listSize=%{public}zu",
        resultCode, this->reqContext_->errorCode, this->reqContext_->stateList.size());
    ReleaseHandler(0);
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void PermissonOnSettingUICallback::OnReceive(const AAFwk::WantParams& receive)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Called!");
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void PermissonOnSettingUICallback::OnRelease(int32_t releaseCode)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ReleaseCode is %{public}d", releaseCode);

    ReleaseHandler(-1);
}

/*
 * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
 */
void PermissonOnSettingUICallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Code is %{public}d, name is %{public}s, message is %{public}s",
        code, name.c_str(), message.c_str());

    ReleaseHandler(-1);
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void PermissonOnSettingUICallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Connect to UIExtensionAbility successfully.");
}

/*
 * when UIExtensionComponent destructed
 */
void PermissonOnSettingUICallback::OnDestroy()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UIExtensionAbility destructed.");
    ReleaseHandler(-1);
}

static void CreateUIExtensionMainThread(std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext,
    const AAFwk::Want& want, const Ace::ModalUIExtensionCallbacks& uiExtensionCallbacks,
    const std::shared_ptr<PermissonOnSettingUICallback>& uiExtCallback)
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

static int32_t CreateUIExtension(const Want &want, std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext)
{
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

    CreateUIExtensionMainThread(asyncContext, want, uiExtensionCallbacks, uiExtCallback);
    if (asyncContext->result.errorCode == RET_FAILED) {
        return RET_FAILED;
    }
    return RET_SUCCESS;
}

static int32_t StartUIExtension(std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext)
{
    AAFwk::Want want;
    AccessTokenKit::GetPermissionManagerInfo(asyncContext->info);
    LOGI(ATM_DOMAIN, ATM_TAG, "bundleName: %{public}s, permStateAbilityName: %{public}s.",
        asyncContext->info.grantBundleName.c_str(), asyncContext->info.permStateAbilityName.c_str());
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.permStateAbilityName);
    want.SetParam(PERMISSION_KEY, asyncContext->permissionList);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);
    return CreateUIExtension(want, asyncContext);
}

static void GetInstanceId(std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    auto task = [asyncContext]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext);
        if (uiContent == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get ui content failed!");
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

void RequestOnSettingAsyncInstanceControl::AddCallbackByInstanceId(
    std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
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

bool static CheckPermList(std::vector<std::string> permList, std::vector<std::string> tmpPermList)
{
    if (permList.size() != tmpPermList.size()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Perm list size not equal, CurrentPermList size: %{public}zu.", tmpPermList.size());
        return false;
    }

    for (const auto& item : permList) {
        auto iter = std::find_if(tmpPermList.begin(), tmpPermList.end(), [item](const std::string& perm) {
            return item == perm;
        });
        if (iter == tmpPermList.end()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Different permission lists.");
            return false;
        }
    }
    return true;
}

void RequestOnSettingAsyncInstanceControl::UpdateQueueData(
    const std::shared_ptr<RequestPermOnSettingAsyncContext>& reqContext)
{
    if (reqContext->errorCode != RET_SUCCESS) {
        LOGI(ATM_DOMAIN, ATM_TAG, "The queue data does not need to be updated.");
        return;
    }
    for (const int32_t item : reqContext->stateList) {
        if (item != PERMISSION_GRANTED) {
            LOGI(ATM_DOMAIN, ATM_TAG, "The queue data does not need to be updated");
            return;
        }
    }

    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        int32_t id = reqContext->instanceId;
        auto iter = instanceIdMap_.find(id);
        if (iter == instanceIdMap_.end()) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d not existed.", id);
            return;
        }
        std::vector<std::string> permList = reqContext->permissionList;
        LOGI(ATM_DOMAIN, ATM_TAG, "Id: %{public}d, map size: %{public}zu.", id, iter->second.size());
        for (auto& asyncContext : iter->second) {
            if (asyncContext == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "AsyncContext is null.");
                continue;
            }
            std::vector<std::string> tmpPermList = asyncContext->permissionList;
            
            if (CheckPermList(permList, tmpPermList)) {
                asyncContext->errorCode = reqContext->errorCode;
                asyncContext->stateList = reqContext->stateList;
                asyncContext->isDynamic = false;
            }
        }
    }
}

void RequestOnSettingAsyncInstanceControl::ExecCallback(int32_t id)
{
    std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext = nullptr;
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

void RequestOnSettingAsyncInstanceControl::CheckDynamicRequest(
    std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext, bool& isDynamic)
{
    isDynamic = asyncContext->isDynamic;
    if (!isDynamic) {
        LOGI(ATM_DOMAIN, ATM_TAG, "It does not need to request permission exsion");
        PermissionResultsCallbackUI(asyncContext->errorCode, asyncContext->stateList, asyncContext);
        return;
    }
}

napi_value NapiRequestPermissionOnSetting::RequestPermissionOnSetting(napi_env env, napi_callback_info info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "RequestPermissionOnSetting begin.");
    // use handle to protect asyncContext
    std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext =
        std::make_shared<RequestPermOnSettingAsyncContext>(env);

    if (!ParseRequestPermissionOnSetting(env, info, asyncContext)) {
        return nullptr;
    }
    auto asyncContextHandle = std::make_unique<RequestOnSettingAsyncContextHandle>(asyncContext);
    if (asyncContextHandle->asyncContextPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Async context is null.");
        return nullptr;
    }
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

    LOGD(ATM_DOMAIN, ATM_TAG, "RequestPermissionOnSetting end.");
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Napi_get_cb_info failed");
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
    LOGI(ATM_DOMAIN, ATM_TAG, "AsyncContext.uiAbilityFlag is: %{public}d.", asyncContext->uiAbilityFlag);

    // argv[1] : permissionList
    if (!ParseStringArray(env, argv[1], asyncContext->permissionList) ||
        (asyncContext->permissionList.empty())) {
        errMsg = GetParamErrorMsg("permissionList", "Array<Permissions>");
        NAPI_CALL_BASE(
            env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
#ifdef EVENTHANDLER_ENABLE
    asyncContext->handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
#endif
    return true;
}

void NapiRequestPermissionOnSetting::RequestPermissionOnSettingExecute(napi_env env, void* data)
{
    // asyncContext release in complete
    RequestOnSettingAsyncContextHandle* asyncContextHandle =
        reinterpret_cast<RequestOnSettingAsyncContextHandle*>(data);
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
    } else {
        if ((asyncContextHandle->asyncContextPtr->uiExtensionContext == nullptr) ||
            (asyncContextHandle->asyncContextPtr->uiExtensionContext->GetApplicationInfo() == nullptr)) {
            return;
        }
        asyncContextHandle->asyncContextPtr->tokenId =
            asyncContextHandle->asyncContextPtr->uiExtensionContext->GetApplicationInfo()->accessTokenId;
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

    RequestOnSettingAsyncInstanceControl::AddCallbackByInstanceId(asyncContextHandle->asyncContextPtr);
    if (asyncContextHandle->asyncContextPtr->result.errorCode != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Failed to pop uiextension dialog.");
    }
}

void NapiRequestPermissionOnSetting::RequestPermissionOnSettingComplete(napi_env env, napi_status status, void* data)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "RequestPermissionOnSettingComplete begin.");
    RequestOnSettingAsyncContextHandle* asyncContextHandle =
        reinterpret_cast<RequestOnSettingAsyncContextHandle*>(data);
    if (asyncContextHandle == nullptr || asyncContextHandle->asyncContextPtr == nullptr) {
        return;
    }
    std::unique_ptr<RequestOnSettingAsyncContextHandle> callbackPtr {asyncContextHandle};

    // need pop dialog
    if (asyncContextHandle->asyncContextPtr->result.errorCode == RET_SUCCESS) {
        return;
    }
    // return error
    if (asyncContextHandle->asyncContextPtr->deferred != nullptr) {
        int32_t jsCode = NapiContextCommon::GetJsErrorCode(asyncContextHandle->asyncContextPtr->result.errorCode);
        napi_value businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode));
        NAPI_CALL_RETURN_VOID(env,
            napi_reject_deferred(env, asyncContextHandle->asyncContextPtr->deferred, businessError));
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS