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
#include "napi_request_permission.h"

#include "ability.h"
#include "ability_manager_client.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "hisysevent.h"
#include "napi_base_context.h"
#include "napi_hisysevent_adapter.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::mutex g_lockFlag;
std::map<int32_t, std::vector<std::shared_ptr<RequestAsyncContext>>> RequestAsyncInstanceControl::instanceIdMap_;
std::mutex RequestAsyncInstanceControl::instanceIdMutex_;
namespace {
const std::string PERMISSION_KEY = "ohos.user.grant.permission";
const std::string STATE_KEY = "ohos.user.grant.permission.state";
const std::string RESULT_KEY = "ohos.user.grant.permission.result";
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string UI_EXTENSION_TYPE = "sys/commonUI";
const std::string ORI_PERMISSION_MANAGER_BUNDLE_NAME = "com.ohos.permissionmanager";
const std::string TOKEN_KEY = "ohos.ability.params.token";
const std::string CALLBACK_KEY = "ohos.ability.params.callback";

const std::string WINDOW_RECTANGLE_LEFT_KEY = "ohos.ability.params.request.left";
const std::string WINDOW_RECTANGLE_TOP_KEY = "ohos.ability.params.request.top";
const std::string WINDOW_RECTANGLE_HEIGHT_KEY = "ohos.ability.params.request.height";
const std::string WINDOW_RECTANGLE_WIDTH_KEY = "ohos.ability.params.request.width";
const std::string REQUEST_TOKEN_KEY = "ohos.ability.params.request.token";

static void ReturnPromiseResult(napi_env env, int32_t contextResult, napi_deferred deferred, napi_value result)
{
    if (contextResult != RET_SUCCESS) {
        int32_t jsCode = NapiContextCommon::GetJsErrorCode(contextResult);
        napi_value businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode));
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, deferred, businessError));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, deferred, result));
    }
}

static void ReturnCallbackResult(napi_env env, int32_t contextResult, napi_ref &callbackRef, napi_value result)
{
    napi_value businessError = GetNapiNull(env);
    if (contextResult != RET_SUCCESS) {
        int32_t jsCode = NapiContextCommon::GetJsErrorCode(contextResult);
        businessError = GenerateBusinessError(env, jsCode, GetErrorMessage(jsCode));
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
} // namespace

static napi_value WrapVoidToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

static Ace::UIContent* GetUIContent(std::shared_ptr<RequestAsyncContext> asyncContext)
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

static void GetInstanceId(std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    auto task = [asyncContext]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext);
        if (uiContent == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get ui content failed!");
            HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQ_PERM_FROM_USER_ERROR",
                HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", GET_UI_CONTENT_FAILED);
            return;
        }
        asyncContext->uiContentFlag = true;
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
    LOGI(ATM_DOMAIN, ATM_TAG, "Instance id: %{public}d, uiContentFlag: %{public}d",
        asyncContext->instanceId, asyncContext->uiContentFlag);
}

static void CreateUIExtensionMainThread(std::shared_ptr<RequestAsyncContext>& asyncContext, const AAFwk::Want& want,
    const Ace::ModalUIExtensionCallbacks& uiExtensionCallbacks,
    const std::shared_ptr<UIExtensionCallback>& uiExtCallback)
{
    auto task = [asyncContext, want, uiExtensionCallbacks, uiExtCallback]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext);
        if (uiContent == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get ui content failed!");
            asyncContext->result = RET_FAILED;
            asyncContext->uiExtensionFlag = false;
            return;
        }

        Ace::ModalUIExtensionConfig config;
        config.isProhibitBack = true;
        int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);

        LOGI(ATM_DOMAIN, ATM_TAG, "Create end, sessionId: %{public}d, tokenId: %{public}d, permNum: %{public}zu",
            sessionId, asyncContext->tokenId, asyncContext->permissionList.size());
        if (sessionId == 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Create component failed, sessionId is 0");
            asyncContext->result = RET_FAILED;
            asyncContext->uiExtensionFlag = false;
            HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQ_PERM_FROM_USER_ERROR",
                HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", CREATE_MODAL_UI_FAILED);
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
    LOGI(ATM_DOMAIN, ATM_TAG, "Instance id: %{public}d", asyncContext->instanceId);
}

static void CloseModalUIExtensionMainThread(std::shared_ptr<RequestAsyncContext>& asyncContext, int32_t sessionId)
{
    auto task = [asyncContext, sessionId]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext);
        if (uiContent == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get ui content failed!");
            asyncContext->result = RET_FAILED;
            return;
        }
        uiContent->CloseModalUIExtension(sessionId);
        LOGI(ATM_DOMAIN, ATM_TAG, "Close end, sessionId: %{public}d", sessionId);
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
    LOGI(ATM_DOMAIN, ATM_TAG, "Instance id: %{public}d", asyncContext->instanceId);
}

static napi_value GetContext(
    const napi_env &env, const napi_value &value, std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, value, stageMode);
    if (status != napi_ok || !stageMode) {
        LOGE(ATM_DOMAIN, ATM_TAG, "It is not a stage mode");
        return nullptr;
    } else {
        auto context = AbilityRuntime::GetStageModeContext(env, value);
        if (context == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get context failed");
            return nullptr;
        }
        asyncContext->abilityContext =
            AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
        if ((asyncContext->abilityContext != nullptr) &&
            (asyncContext->abilityContext->GetApplicationInfo() != nullptr)) {
            asyncContext->uiAbilityFlag = true;
            asyncContext->tokenId = asyncContext->abilityContext->GetApplicationInfo()->accessTokenId;
            asyncContext->bundleName = asyncContext->abilityContext->GetApplicationInfo()->bundleName;
        } else {
            LOGW(ATM_DOMAIN, ATM_TAG, "Convert to ability context failed");
            asyncContext->uiExtensionContext =
                AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(context);
            if ((asyncContext->uiExtensionContext == nullptr) ||
                (asyncContext->uiExtensionContext->GetApplicationInfo() == nullptr)) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Convert to ui extension context failed");
                return nullptr;
            }
            asyncContext->tokenId = asyncContext->uiExtensionContext->GetApplicationInfo()->accessTokenId;
            asyncContext->bundleName = asyncContext->uiExtensionContext->GetApplicationInfo()->bundleName;
        }
        return WrapVoidToJS(env);
    }
}

static napi_value WrapRequestResult(const napi_env& env, const std::vector<std::string>& permissions,
    const std::vector<int>& grantResults, const std::vector<bool>& dialogShownResults,
    const std::vector<int>& errorReasons)
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

    napi_value objDialogShown;
    NAPI_CALL(env, napi_create_array(env, &objDialogShown));
    for (size_t i = 0; i < dialogShownResults.size(); i++) {
        napi_value nDialogShown = nullptr;
        NAPI_CALL(env, napi_get_boolean(env, dialogShownResults[i], &nDialogShown));
        NAPI_CALL(env, napi_set_element(env, objDialogShown, i, nDialogShown));
    }
    NAPI_CALL(env, napi_set_named_property(env, result, "dialogShownResults", objDialogShown));

    napi_value objErrorReason;
    NAPI_CALL(env, napi_create_array(env, &objErrorReason));
    for (size_t i = 0; i < grantResults.size(); i++) {
        napi_value nErrorReason = nullptr;
        NAPI_CALL(env, napi_create_int32(env, errorReasons[i], &nErrorReason));
        NAPI_CALL(env, napi_set_element(env, objErrorReason, i, nErrorReason));
    }
    NAPI_CALL(env, napi_set_named_property(env, result, "errorReasons", objErrorReason));

    return result;
}

static void UpdateGrantPermissionResultOnly(const std::vector<std::string>& permissions,
    const std::vector<int>& grantResults, std::shared_ptr<RequestAsyncContext>& data, std::vector<int>& newGrantResults)
{
    uint32_t size = permissions.size();

    for (uint32_t i = 0; i < size; i++) {
        int result = data->permissionsState[i];
        if (data->permissionsState[i] == DYNAMIC_OPER) {
            result = data->result == RET_SUCCESS ? grantResults[i] : INVALID_OPER;
        }
        newGrantResults.emplace_back(result);
    }
}

static void RequestResultsHandler(const std::vector<std::string>& permissionList,
    const std::vector<int32_t>& permissionStates, std::shared_ptr<RequestAsyncContext>& data)
{
    auto* retCB = new (std::nothrow) ResultCallback();
    if (retCB == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Insufficient memory for work!");
        return;
    }
    std::vector<int> newGrantResults;
    UpdateGrantPermissionResultOnly(permissionList, permissionStates, data, newGrantResults);

    std::unique_ptr<ResultCallback> callbackPtr {retCB};
    retCB->permissions = permissionList;
    retCB->grantResults = newGrantResults;
    retCB->dialogShownResults = data->dialogShownResults;
    retCB->errorReasons = data->errorReasons;
    retCB->data = data;
    auto task = [retCB]() {
        int32_t result = JsErrorCode::JS_OK;
        if ((retCB->data->result != RET_SUCCESS) || (retCB->grantResults.empty())) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Result is: %{public}d", retCB->data->result);
            result = RET_FAILED;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(retCB->data->env, &scope);
        if (scope == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Napi_open_handle_scope failed");
            delete retCB;
            return;
        }
        napi_value requestResult = WrapRequestResult(
            retCB->data->env, retCB->permissions, retCB->grantResults, retCB->dialogShownResults, retCB->errorReasons);
        if (requestResult == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Wrap requestResult failed");
            result = RET_FAILED;
        }

        if (retCB->data->deferred != nullptr) {
            ReturnPromiseResult(retCB->data->env, result, retCB->data->deferred, requestResult);
        } else {
            ReturnCallbackResult(retCB->data->env, result, retCB->data->callbackRef, requestResult);
        }
        napi_close_handle_scope(retCB->data->env, scope);
        delete retCB;
    };
    if (napi_status::napi_ok != napi_send_event(data->env, task, napi_eprio_immediate)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "RequestResultsHandler: Failed to SendEvent");
    } else {
        callbackPtr.release();
    }
}

void AuthorizationResult::GrantResultsCallback(const std::vector<std::string>& permissionList,
    const std::vector<int>& grantResults)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Called.");
    std::shared_ptr<RequestAsyncContext> asyncContext = data_;
    if (asyncContext == nullptr) {
        return;
    }
    RequestResultsHandler(permissionList, grantResults, asyncContext);
}

void AuthorizationResult::WindowShownCallback()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Called.");

    std::shared_ptr<RequestAsyncContext> asyncContext = data_;
    if (asyncContext == nullptr) {
        return;
    }

    Ace::UIContent* uiContent = GetUIContent(asyncContext);
    // get uiContent failed when request or when callback called
    if ((uiContent == nullptr) || !(asyncContext->uiContentFlag)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get ui content failed!");
        return;
    }
    RequestAsyncInstanceControl::ExecCallback(asyncContext->instanceId);
    LOGD(ATM_DOMAIN, ATM_TAG, "OnRequestPermissionsFromUser async callback is called end");
}

static void CreateServiceExtension(std::shared_ptr<RequestAsyncContext> asyncContext)
{
    if ((asyncContext == nullptr) || (asyncContext->abilityContext == nullptr)) {
        return;
    }
    if (!asyncContext->uiAbilityFlag) {
        LOGE(ATM_DOMAIN, ATM_TAG, "UIExtension ability can not pop service ablility window!");
        asyncContext->needDynamicRequest = false;
        asyncContext->result = RET_FAILED;
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQ_PERM_FROM_USER_ERROR",
            HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", ABILITY_FLAG_ERROR);
        return;
    }
    sptr<IRemoteObject> remoteObject = new (std::nothrow) AccessToken::AuthorizationResult(asyncContext);
    if (remoteObject == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Create window failed!");
        asyncContext->needDynamicRequest = false;
        asyncContext->result = RET_FAILED;
        return;
    }
    AAFwk::Want want;
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.grantServiceAbilityName);
    want.SetParam(PERMISSION_KEY, asyncContext->permissionList);
    want.SetParam(STATE_KEY, asyncContext->permissionsState);
    want.SetParam(TOKEN_KEY, asyncContext->abilityContext->GetToken());
    want.SetParam(CALLBACK_KEY, remoteObject);

    int32_t left;
    int32_t top;
    int32_t width;
    int32_t height;
    asyncContext->abilityContext->GetWindowRect(left, top, width, height);
    want.SetParam(WINDOW_RECTANGLE_LEFT_KEY, left);
    want.SetParam(WINDOW_RECTANGLE_TOP_KEY, top);
    want.SetParam(WINDOW_RECTANGLE_WIDTH_KEY, width);
    want.SetParam(WINDOW_RECTANGLE_HEIGHT_KEY, height);
    want.SetParam(REQUEST_TOKEN_KEY, asyncContext->abilityContext->GetToken());
    int32_t ret = AAFwk::AbilityManagerClient::GetInstance()->RequestDialogService(
        want, asyncContext->abilityContext->GetToken());

    LOGI(ATM_DOMAIN, ATM_TAG, "Request end, ret: %{public}d, tokenId: %{public}d, permNum: %{public}zu",
        ret, asyncContext->tokenId, asyncContext->permissionList.size());
}

bool NapiRequestPermission::IsDynamicRequest(std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    std::vector<PermissionListState> permList;
    for (const auto& permission : asyncContext->permissionList) {
        PermissionListState permState;
        permState.permissionName = permission;
        permState.state = INVALID_OPER;
        permState.errorReason = SERVICE_ABNORMAL;
        permList.emplace_back(permState);
    }
    auto ret = AccessTokenKit::GetSelfPermissionsState(permList, asyncContext->info);
    if (ret == FORBIDDEN_OPER) { // if app is under control, change state from default -1 to 2
        for (auto& perm : permList) {
            perm.state = INVALID_OPER;
            perm.errorReason = PRIVACY_STATEMENT_NOT_AGREED;
        }
    }
    LOGI(ATM_DOMAIN, ATM_TAG,
        "TokenID: %{public}d, bundle: %{public}s, uiExAbility: %{public}s, serExAbility: %{public}s.",
        asyncContext->tokenId, asyncContext->info.grantBundleName.c_str(),
        asyncContext->info.grantAbilityName.c_str(), asyncContext->info.grantServiceAbilityName.c_str());

    for (const auto& permState : permList) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Permission: %{public}s: state: %{public}d, errorReason: %{public}d",
            permState.permissionName.c_str(), permState.state, permState.errorReason);
        asyncContext->permissionsState.emplace_back(permState.state);
        asyncContext->dialogShownResults.emplace_back(permState.state == TypePermissionOper::DYNAMIC_OPER);
        asyncContext->errorReasons.emplace_back(permState.errorReason);
    }
    if (permList.size() != asyncContext->permissionList.size()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Returned permList size: %{public}zu.", permList.size());
        return false;
    }
    return ret == TypePermissionOper::DYNAMIC_OPER;
}

void UIExtensionCallback::ReleaseHandler(int32_t code)
{
    {
        std::lock_guard<std::mutex> lock(g_lockFlag);
        if (this->reqContext_->releaseFlag) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Callback has executed.");
            return;
        }
        this->reqContext_->releaseFlag = true;
    }
    CloseModalUIExtensionMainThread(this->reqContext_, this->sessionId_);
    this->reqContext_->result = code;
    RequestAsyncInstanceControl::ExecCallback(this->reqContext_->instanceId);
    RequestResultsHandler(this->reqContext_->permissionList, this->reqContext_->permissionsState, this->reqContext_);
}

UIExtensionCallback::UIExtensionCallback(const std::shared_ptr<RequestAsyncContext>& reqContext)
{
    this->reqContext_ = reqContext;
    isOnResult_.exchange(false);
}

UIExtensionCallback::~UIExtensionCallback()
{}

void UIExtensionCallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

/*
 * when UIExtensionAbility use terminateSelfWithResult
 */
void UIExtensionCallback::OnResult(int32_t resultCode, const AAFwk::Want& result)
{
    isOnResult_.exchange(true);
    LOGI(ATM_DOMAIN, ATM_TAG, "ResultCode is %{public}d", resultCode);
    this->reqContext_->permissionList = result.GetStringArrayParam(PERMISSION_KEY);
    this->reqContext_->permissionsState = result.GetIntArrayParam(RESULT_KEY);
    ReleaseHandler(0);
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void UIExtensionCallback::OnReceive(const AAFwk::WantParams& receive)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Called!");
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void UIExtensionCallback::OnRelease(int32_t releaseCode)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ReleaseCode is %{public}d", releaseCode);
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQ_PERM_FROM_USER_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", TRIGGER_RELEASE, "INNER_CODE", releaseCode);
    ReleaseHandler(-1);
}

/*
 * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
 */
void UIExtensionCallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Code is %{public}d, name is %{public}s, message is %{public}s",
        code, name.c_str(), message.c_str());
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQ_PERM_FROM_USER_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", TRIGGER_ONERROR, "INNER_CODE", code);
    ReleaseHandler(-1);
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void UIExtensionCallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Connect to UIExtensionAbility successfully.");
}

/*
 * when UIExtensionComponent destructed
 */
void UIExtensionCallback::OnDestroy()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UIExtensionAbility destructed.");
    if (isOnResult_.load() == false) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQ_PERM_FROM_USER_ERROR",
            HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", TRIGGER_DESTROY);
    }
    ReleaseHandler(-1);
}

static void CreateUIExtension(std::shared_ptr<RequestAsyncContext> asyncContext)
{
    AAFwk::Want want;
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.grantAbilityName);
    want.SetParam(PERMISSION_KEY, asyncContext->permissionList);
    want.SetParam(STATE_KEY, asyncContext->permissionsState);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);

    auto uiExtCallback = std::make_shared<UIExtensionCallback>(asyncContext);
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
}


napi_value NapiRequestPermission::RequestPermissionsFromUser(napi_env env, napi_callback_info info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "RequestPermissionsFromUser begin.");
    // use handle to protect asyncContext
    std::shared_ptr<RequestAsyncContext> asyncContext = std::make_shared<RequestAsyncContext>(env);

    if (!ParseRequestPermissionFromUser(env, info, asyncContext)) {
        return nullptr;
    }
    auto asyncContextHandle = std::make_unique<RequestAsyncContextHandle>(asyncContext);
    napi_value result = nullptr;
    if (asyncContextHandle->asyncContextPtr->callbackRef == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &(asyncContextHandle->asyncContextPtr->deferred), &result));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }

    napi_value resource = nullptr; // resource name
    NAPI_CALL(env, napi_create_string_utf8(env, "RequestPermissionsFromUser", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, RequestPermissionsFromUserExecute, RequestPermissionsFromUserComplete,
        reinterpret_cast<void *>(asyncContextHandle.get()), &(asyncContextHandle->asyncContextPtr->work)));

    NAPI_CALL(env,
        napi_queue_async_work_with_qos(env, asyncContextHandle->asyncContextPtr->work, napi_qos_user_initiated));

    LOGD(ATM_DOMAIN, ATM_TAG, "RequestPermissionsFromUser end.");
    asyncContextHandle.release();
    return result;
}

bool NapiRequestPermission::ParseRequestPermissionFromUser(const napi_env& env,
    const napi_callback_info& cbInfo, std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    size_t argc = NapiContextCommon::MAX_PARAMS_THREE;
    napi_value argv[NapiContextCommon::MAX_PARAMS_THREE] = { nullptr };
    napi_value thisVar = nullptr;

    if (napi_get_cb_info(env, cbInfo, &argc, argv, &thisVar, nullptr) != napi_ok) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Napi_get_cb_info failed");
        return false;
    }
    if (argc < NapiContextCommon::MAX_PARAMS_THREE - 1) {
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

    if (argc == NapiContextCommon::MAX_PARAMS_THREE) {
        // argv[2] : callback
        if (!IsUndefinedOrNull(env, argv[2]) && !ParseCallback(env, argv[2], asyncContext->callbackRef)) {
            errMsg = GetParamErrorMsg("callback", "Callback<PermissionRequestResult>");
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg));
            return false;
        }
    }
#ifdef EVENTHANDLER_ENABLE
    asyncContext->handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
#endif
    return true;
}

void NapiRequestPermission::RequestPermissionsFromUserExecute(napi_env env, void* data)
{
    // asyncContext release in complete
    RequestAsyncContextHandle* asyncContextHandle = reinterpret_cast<RequestAsyncContextHandle*>(data);
    static AccessTokenID selfTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    if (asyncContextHandle->asyncContextPtr->tokenId != selfTokenID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "The context tokenID: %{public}d, selfTokenID: %{public}d.",
            asyncContextHandle->asyncContextPtr->tokenId, selfTokenID);
        asyncContextHandle->asyncContextPtr->result = RET_FAILED;
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQ_PERM_FROM_USER_ERROR",
            HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", TOKENID_INCONSISTENCY,
            "SELF_TOKEN", selfTokenID, "CONTEXT_TOKEN", asyncContextHandle->asyncContextPtr->tokenId);
        return;
    }

    if (!IsDynamicRequest(asyncContextHandle->asyncContextPtr)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "It does not need to request permission");
        asyncContextHandle->asyncContextPtr->needDynamicRequest = false;
        return;
    }
    GetInstanceId(asyncContextHandle->asyncContextPtr);
    // service extension dialog
    if (asyncContextHandle->asyncContextPtr->info.grantBundleName == ORI_PERMISSION_MANAGER_BUNDLE_NAME) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Pop service extension dialog, uiContentFlag=%{public}d",
            asyncContextHandle->asyncContextPtr->uiContentFlag);
        if (asyncContextHandle->asyncContextPtr->uiContentFlag) {
            RequestAsyncInstanceControl::AddCallbackByInstanceId(asyncContextHandle->asyncContextPtr);
        } else {
            CreateServiceExtension(asyncContextHandle->asyncContextPtr);
        }
    } else if (asyncContextHandle->asyncContextPtr->instanceId == -1) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Pop service extension dialog, instanceId is -1.");
        CreateServiceExtension(asyncContextHandle->asyncContextPtr);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQUEST_PERMISSIONS_FROM_USER",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "BUNDLENAME", asyncContextHandle->asyncContextPtr->bundleName,
            "UIEXTENSION_FLAG", false);
    } else {
        LOGI(ATM_DOMAIN, ATM_TAG, "Pop ui extension dialog");
        asyncContextHandle->asyncContextPtr->uiExtensionFlag = true;
        RequestAsyncInstanceControl::AddCallbackByInstanceId(asyncContextHandle->asyncContextPtr);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQUEST_PERMISSIONS_FROM_USER",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
            "BUNDLENAME", asyncContextHandle->asyncContextPtr->bundleName,
            "UIEXTENSION_FLAG", asyncContextHandle->asyncContextPtr->uiExtensionFlag);
        if (!asyncContextHandle->asyncContextPtr->uiExtensionFlag) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Pop uiextension dialog fail, start to pop service extension dialog.");
            RequestAsyncInstanceControl::AddCallbackByInstanceId(asyncContextHandle->asyncContextPtr);
        }
    }
}

void NapiRequestPermission::RequestPermissionsFromUserComplete(napi_env env, napi_status status, void* data)
{
    RequestAsyncContextHandle* asyncContextHandle = reinterpret_cast<RequestAsyncContextHandle*>(data);
    std::unique_ptr<RequestAsyncContextHandle> callbackPtr {asyncContextHandle};

    if (asyncContextHandle->asyncContextPtr->needDynamicRequest) {
        return;
    }
    if ((asyncContextHandle->asyncContextPtr->permissionsState.empty()) &&
        (asyncContextHandle->asyncContextPtr->result == JsErrorCode::JS_OK)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GrantResults empty");
        asyncContextHandle->asyncContextPtr->result = RET_FAILED;
    }
    napi_value requestResult = WrapRequestResult(env, asyncContextHandle->asyncContextPtr->permissionList,
        asyncContextHandle->asyncContextPtr->permissionsState, asyncContextHandle->asyncContextPtr->dialogShownResults,
        asyncContextHandle->asyncContextPtr->errorReasons);
    if (requestResult == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Wrap requestResult failed");
        if (asyncContextHandle->asyncContextPtr->result == JsErrorCode::JS_OK) {
            asyncContextHandle->asyncContextPtr->result = RET_FAILED;
        }
    } else {
        asyncContextHandle->asyncContextPtr->requestResult = requestResult;
    }
    if (asyncContextHandle->asyncContextPtr->deferred != nullptr) {
        ReturnPromiseResult(env, asyncContextHandle->asyncContextPtr->result,
            asyncContextHandle->asyncContextPtr->deferred, asyncContextHandle->asyncContextPtr->requestResult);
    } else {
        ReturnCallbackResult(env, asyncContextHandle->asyncContextPtr->result,
            asyncContextHandle->asyncContextPtr->callbackRef, asyncContextHandle->asyncContextPtr->requestResult);
    }
}

napi_value NapiRequestPermission::GetPermissionsStatus(napi_env env, napi_callback_info info)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "GetPermissionsStatus begin.");

    auto* asyncContext = new (std::nothrow) RequestAsyncContext(env);
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "New struct fail.");
        return nullptr;
    }

    std::unique_ptr<RequestAsyncContext> context {asyncContext};
    if (!ParseInputToGetQueryResult(env, info, *asyncContext)) {
        return nullptr;
    }

    napi_value result = nullptr;
    napi_create_promise(env, &(asyncContext->deferred), &result); // create delay promise object

    napi_value resource = nullptr; // resource name
    napi_create_string_utf8(env, "GetPermissionsStatus", NAPI_AUTO_LENGTH, &resource);

    napi_create_async_work(
        env, nullptr, resource, GetPermissionsStatusExecute, GetPermissionsStatusComplete,
        reinterpret_cast<void *>(asyncContext), &(asyncContext->work));
    // add async work handle to the napi queue and wait for result
    napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_default);

    LOGD(ATM_DOMAIN, ATM_TAG, "GetPermissionsStatus end.");
    context.release();
    return result;
}

bool NapiRequestPermission::ParseInputToGetQueryResult(const napi_env& env, const napi_callback_info& info,
    RequestAsyncContext& asyncContext)
{
    size_t argc = NapiContextCommon::MAX_PARAMS_TWO;
    napi_value argv[NapiContextCommon::MAX_PARAMS_TWO] = {nullptr};
    napi_value thatVar = nullptr;

    void *data = nullptr;
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, &thatVar, &data), false);
    // 1: can request permissions minnum argc
    if (argc < NapiContextCommon::MAX_PARAMS_TWO - 1) {
        NAPI_CALL_BASE(env, napi_throw(env,
            GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, "Parameter is missing.")), false);
        return false;
    }

    std::string errMsg;
    asyncContext.env = env;
    // the first parameter of argv
    if (!ParseUint32(env, argv[0], asyncContext.tokenId)) {
        errMsg = GetParamErrorMsg("tokenId", "number");
        NAPI_CALL_BASE(env,
            napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }

    // the second parameter of argv
    if (!ParseStringArray(env, argv[1], asyncContext.permissionList)) {
        errMsg = GetParamErrorMsg("permissions", "Array<Permissions>");
        NAPI_CALL_BASE(
            env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID = %{public}d, permissionList size = %{public}zu", asyncContext.tokenId,
        asyncContext.permissionList.size());
    return true;
}

void NapiRequestPermission::GetPermissionsStatusExecute(napi_env env, void *data)
{
    RequestAsyncContext* asyncContext = reinterpret_cast<RequestAsyncContext*>(data);

    std::vector<PermissionListState> permList;
    for (const auto& permission : asyncContext->permissionList) {
        LOGD(ATM_DOMAIN, ATM_TAG, "Permission: %{public}s.", permission.c_str());
        PermissionListState permState;
        permState.permissionName = permission;
        permState.state = INVALID_OPER;
        permList.emplace_back(permState);
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "PermList size: %{public}zu, asyncContext->permissionList size: %{public}zu.",
        permList.size(), asyncContext->permissionList.size());

    asyncContext->result = AccessTokenKit::GetPermissionsStatus(asyncContext->tokenId, permList);
    for (const auto& permState : permList) {
        LOGD(ATM_DOMAIN, ATM_TAG, "Permission: %{public}s", permState.permissionName.c_str());
        asyncContext->permissionQueryResults.emplace_back(permState.state);
    }
}

void NapiRequestPermission::GetPermissionsStatusComplete(napi_env env, napi_status status, void *data)
{
    RequestAsyncContext* asyncContext = reinterpret_cast<RequestAsyncContext*>(data);
    std::unique_ptr<RequestAsyncContext> callbackPtr {asyncContext};

    if ((asyncContext->permissionQueryResults.empty()) && asyncContext->result == JsErrorCode::JS_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionQueryResults empty");
        asyncContext->result = RET_FAILED;
    }
    napi_value result;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result));

    for (size_t i = 0; i < asyncContext->permissionQueryResults.size(); i++) {
        napi_value nPermissionQueryResult = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
            asyncContext->permissionQueryResults[i], &nPermissionQueryResult));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, i, nPermissionQueryResult));
    }
    ReturnPromiseResult(env, asyncContext->result, asyncContext->deferred, result);
}

void RequestAsyncInstanceControl::CheckDynamicRequest(
    std::shared_ptr<RequestAsyncContext>& asyncContext, bool& isDynamic)
{
    asyncContext->permissionsState.clear();
    asyncContext->dialogShownResults.clear();
    asyncContext->errorReasons.clear();
    if (!NapiRequestPermission::IsDynamicRequest(asyncContext)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "It does not need to request permission exsion");
        RequestResultsHandler(asyncContext->permissionList, asyncContext->permissionsState, asyncContext);
        return;
    }
    isDynamic = true;
}

void RequestAsyncInstanceControl::AddCallbackByInstanceId(std::shared_ptr<RequestAsyncContext>& asyncContext)
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

    if (asyncContext->uiExtensionFlag) {
        CreateUIExtension(asyncContext);
    } else {
        CreateServiceExtension(asyncContext);
    }
}

void RequestAsyncInstanceControl::ExecCallback(int32_t id)
{
    std::shared_ptr<RequestAsyncContext> asyncContext = nullptr;
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
        if (asyncContext->uiExtensionFlag) {
            CreateUIExtension(asyncContext);
        } else {
            CreateServiceExtension(asyncContext);
        }
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS