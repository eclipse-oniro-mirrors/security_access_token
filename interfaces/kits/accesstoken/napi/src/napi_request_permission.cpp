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
#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "napi_base_context.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::mutex g_lockForPermRequestCallbacks;
std::map<int32_t, std::vector<std::shared_ptr<RequestAsyncContext>>> RequestAsyncInstanceControl::instanceIdMap_;
std::mutex RequestAsyncInstanceControl::instanceIdMutex_;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "NapiRequestPermission"
};
const std::string PERMISSION_KEY = "ohos.user.grant.permission";
const std::string STATE_KEY = "ohos.user.grant.permission.state";
const std::string RESULT_KEY = "ohos.user.grant.permission.result";
const std::string EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
const std::string UI_EXTENSION_TYPE = "sys/commonUI";
const std::string ORI_PERMISSION_MANAGER_BUNDLE_NAME = "com.ohos.permissionmanager";
const std::string ORI_PERMISSION_MANAGER_ABILITY_NAME = "com.ohos.permissionmanager.GrantAbility";
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

static napi_value GetContext(
    const napi_env &env, const napi_value &value, std::shared_ptr<RequestAsyncContext>& asyncContext)
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
        asyncContext->abilityContext =
            AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
        if (asyncContext->abilityContext != nullptr) {
            asyncContext->uiAbilityFlag = true;
        } else {
            ACCESSTOKEN_LOG_WARN(LABEL, "convert to ability context failed");
            asyncContext->uiExtensionContext =
                AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(context);
            if (asyncContext->uiExtensionContext == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "convert to ui extension context failed");
                return nullptr;
            }
        }
        return WrapVoidToJS(env);
    }
}

static napi_value WrapRequestResult(const napi_env& env, const std::vector<std::string>& permissions,
    const std::vector<int>& grantResults, const std::vector<bool>& dialogShownResults)
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

    return result;
}

static void ResultCallbackJSThreadWorker(uv_work_t* work, int32_t status)
{
    (void)status;
    if (work == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "uv_queue_work_with_qos input work is nullptr");
        return;
    }
    std::unique_ptr<uv_work_t> uvWorkPtr {work};
    ResultCallback *retCB = reinterpret_cast<ResultCallback*>(work->data);
    if (retCB == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "retCB is nullptr");
        return;
    }
    std::unique_ptr<ResultCallback> callbackPtr {retCB};

    std::shared_ptr<RequestAsyncContext> asyncContext = retCB->data;
    if (asyncContext == nullptr) {
        return;
    }

    int32_t result = JsErrorCode::JS_OK;
    if (retCB->grantResults.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "grantResults empty");
        result = RET_FAILED;
    }
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(asyncContext->env, &scope);
    if (scope == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_open_handle_scope failed");
        return;
    }
    napi_value requestResult = WrapRequestResult(
        asyncContext->env, retCB->permissions, retCB->grantResults, retCB->dialogShownResults);
    if (requestResult == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "wrap requestResult failed");
        result = RET_FAILED;
    }

    if (asyncContext->deferred != nullptr) {
        ReturnPromiseResult(asyncContext->env, result, asyncContext->deferred, requestResult);
    } else {
        ReturnCallbackResult(asyncContext->env, result, asyncContext->callbackRef, requestResult);
    }
    napi_close_handle_scope(asyncContext->env, scope);
}

static void UpdateGrantPermissionResultOnly(const std::vector<std::string>& permissions,
    const std::vector<int>& grantResults, const std::vector<int>& permissionsState, std::vector<int>& newGrantResults)
{
    uint32_t size = permissions.size();

    for (uint32_t i = 0; i < size; i++) {
        int result = permissionsState[i] == DYNAMIC_OPER ? grantResults[i] : permissionsState[i];
        newGrantResults.emplace_back(result);
    }
}

void AuthorizationResult::GrantResultsCallback(const std::vector<std::string>& permissions,
    const std::vector<int>& grantResults)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called.");

    auto* retCB = new (std::nothrow) ResultCallback();
    if (retCB == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "insufficient memory for work!");
        return;
    }

    std::unique_ptr<ResultCallback> callbackPtr {retCB};

    std::shared_ptr<RequestAsyncContext> asyncContext = data_;
    if (asyncContext == nullptr) {
        return;
    }

    // only permissions which need to grant change the result, other keey as GetSelfPermissionsState result
    std::vector<int> newGrantResults;
    UpdateGrantPermissionResultOnly(permissions, grantResults, asyncContext->permissionsState, newGrantResults);

    retCB->permissions = permissions;
    retCB->grantResults = newGrantResults;
    retCB->dialogShownResults = asyncContext->dialogShownResults;
    retCB->requestCode = requestCode_;
    retCB->data = data_;

    uv_loop_s* loop = nullptr;
    NAPI_CALL_RETURN_VOID(asyncContext->env,
        napi_get_uv_event_loop(asyncContext->env, &loop));
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
    NAPI_CALL_RETURN_VOID(asyncContext->env, uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {}, ResultCallbackJSThreadWorker, uv_qos_user_initiated));

    uvWorkPtr.release();
    callbackPtr.release();
}

void AuthorizationResult::WindowShownCallback()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called.");

    std::shared_ptr<RequestAsyncContext> asyncContext = data_;
    if (asyncContext == nullptr) {
        return;
    }

    Ace::UIContent* uiContent = nullptr;
    if (asyncContext->uiAbilityFlag) {
        uiContent = asyncContext->abilityContext->GetUIContent();
    } else {
        uiContent = asyncContext->uiExtensionContext->GetUIContent();
    }
    // get uiContent failed when request or when callback called
    if ((uiContent == nullptr) || !(asyncContext->uiContentFlag)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get ui content failed!");
        return;
    }
    int32_t instanceId = uiContent->GetInstanceId();
    RequestAsyncInstanceControl::ExecCallback(instanceId);
    ACCESSTOKEN_LOG_DEBUG(LABEL, "OnRequestPermissionsFromUser async callback is called end");
}

static void CreateServiceExtension(std::shared_ptr<RequestAsyncContext> asyncContext)
{
    sptr<IRemoteObject> remoteObject = new (std::nothrow) AccessToken::AuthorizationResult(
        curRequestCode_, asyncContext);
    if (remoteObject == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Create window failed!");
        asyncContext->needDynamicRequest = false;
        asyncContext->result = RET_FAILED;
        return;
    }
    AAFwk::Want want;
    want.SetElementName(ORI_PERMISSION_MANAGER_BUNDLE_NAME, ORI_PERMISSION_MANAGER_ABILITY_NAME);
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

    std::lock_guard<std::mutex> lock(g_lockForPermRequestCallbacks);
    curRequestCode_ = (curRequestCode_ == INT_MAX) ? 0 : (curRequestCode_ + 1);
    ACCESSTOKEN_LOG_INFO(LABEL, "Request end, ret: %{public}d, tokenId: %{public}d, permNum: %{public}zu",
        ret, asyncContext->tokenId, asyncContext->permissionList.size());
}

static void StartServiceExtension(std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    Ace::UIContent* uiContent = nullptr;
    int64_t beginTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (asyncContext->uiAbilityFlag) {
        while (true) {
            uiContent = asyncContext->abilityContext->GetUIContent();
            int64_t curTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            if ((uiContent != nullptr) || (curTime - beginTime > NapiContextCommon::MAX_WAIT_TIME)) {
                break;
            }
        }
    } else {
        while (true) {
            uiContent = asyncContext->uiExtensionContext->GetUIContent();
            int64_t curTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            if ((uiContent != nullptr) || (curTime - beginTime > NapiContextCommon::MAX_WAIT_TIME)) {
                break;
            }
        }
    }
    if (uiContent == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get ui content failed!");
        CreateServiceExtension(asyncContext);
        return;
    }
    asyncContext->uiContentFlag = true;
    int32_t instanceId = uiContent->GetInstanceId();
    RequestAsyncInstanceControl::AddCallbackByInstanceId(instanceId, asyncContext);
}

bool NapiRequestPermission::IsDynamicRequest(std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    std::vector<PermissionListState> permList;
    for (const auto& permission : asyncContext->permissionList) {
        PermissionListState permState;
        permState.permissionName = permission;
        permState.state = INVALID_OPER;
        permList.emplace_back(permState);
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: %{public}d.", asyncContext->tokenId);
    auto ret = AccessTokenKit::GetSelfPermissionsState(permList, asyncContext->info);
    if (ret == FORBIDDEN_OPER) { // if app is under control, change state from default -1 to 2
        for (auto& perm : permList) {
            perm.state = INVALID_OPER;
        }
    }

    for (const auto& permState : permList) {
        ACCESSTOKEN_LOG_INFO(LABEL, "permission: %{public}s: state: %{public}u",
            permState.permissionName.c_str(), permState.state);
        asyncContext->permissionsState.emplace_back(permState.state);
        asyncContext->dialogShownResults.emplace_back(permState.state == TypePermissionOper::DYNAMIC_OPER);
    }
    if (permList.size() != asyncContext->permissionList.size()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Returned permList size: %{public}zu.", permList.size());
        return false;
    }
    if (ret != TypePermissionOper::DYNAMIC_OPER) {
        return false;
    }

    return true;
}

static void GrantResultsCallbackUI(const std::vector<std::string>& permissionList,
    const std::vector<int32_t>& permissionStates, std::shared_ptr<RequestAsyncContext>& data)
{
    auto* retCB = new (std::nothrow) ResultCallback();
    if (retCB == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "insufficient memory for work!");
        return;
    }

    // only permissions which need to grant change the result, other keey as GetSelfPermissionsState result
    std::vector<int> newGrantResults;
    UpdateGrantPermissionResultOnly(permissionList, permissionStates, data->permissionsState, newGrantResults);

    std::unique_ptr<ResultCallback> callbackPtr {retCB};
    retCB->permissions = permissionList;
    retCB->grantResults = newGrantResults;
    retCB->dialogShownResults = data->dialogShownResults;
    retCB->data = data;

    uv_loop_s* loop = nullptr;
    NAPI_CALL_RETURN_VOID(data->env, napi_get_uv_event_loop(data->env, &loop));
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
    NAPI_CALL_RETURN_VOID(data->env, uv_queue_work_with_qos(
        loop, work, [](uv_work_t* work) {}, ResultCallbackJSThreadWorker, uv_qos_user_initiated));

    uvWorkPtr.release();
    callbackPtr.release();
}

void UIExtensionCallback::ReleaseOrErrorHandle(int32_t code)
{
    this->reqContext_->releaseFlag = true;
    Ace::UIContent* uiContent = nullptr;
    if (this->reqContext_->uiAbilityFlag) {
        uiContent = this->reqContext_->abilityContext->GetUIContent();
    } else {
        uiContent = this->reqContext_->uiExtensionContext->GetUIContent();
    }
    if (uiContent == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get ui content failed!");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "close uiextension component");
    uiContent->CloseModalUIExtension(this->sessionId_);
    int32_t instanceId = uiContent->GetInstanceId();
    RequestAsyncInstanceControl::ExecCallback(instanceId);
    if (code == 0) {
        return; // code is 0 means request has return by OnResult
    }

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(this->reqContext_->env, &scope);
    if (scope == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_open_handle_scope failed");
        return;
    }

    napi_value result = GetNapiNull(this->reqContext_->env);
    if (this->reqContext_->deferred != nullptr) {
        ReturnPromiseResult(this->reqContext_->env, code, this->reqContext_->deferred, result);
    } else {
        ReturnCallbackResult(this->reqContext_->env, code, this->reqContext_->callbackRef, result);
    }
    napi_close_handle_scope(this->reqContext_->env, scope);
}

UIExtensionCallback::UIExtensionCallback(const std::shared_ptr<RequestAsyncContext>& reqContext)
{
    this->reqContext_ = reqContext;
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
    ACCESSTOKEN_LOG_INFO(LABEL, "resultCode is %{public}d", resultCode);
    std::vector<std::string> permissionList = result.GetStringArrayParam(PERMISSION_KEY);
    std::vector<int32_t> permissionStates = result.GetIntArrayParam(RESULT_KEY);

    GrantResultsCallbackUI(permissionList, permissionStates, this->reqContext_);
}

/*
 * when UIExtensionAbility send message to UIExtensionComponent
 */
void UIExtensionCallback::OnReceive(const AAFwk::WantParams& receive)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called!");
}

/*
 * when UIExtensionAbility disconnect or use terminate or process die
 * releaseCode is 0 when process normal exit
 */
void UIExtensionCallback::OnRelease(int32_t releaseCode)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "releaseCode is %{public}d", releaseCode);

    ReleaseOrErrorHandle(releaseCode);
}

/*
 * when UIExtensionComponent init or turn to background or destroy UIExtensionAbility occur error
 */
void UIExtensionCallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "code is %{public}d, name is %{public}s, message is %{public}s",
        code, name.c_str(), message.c_str());

    ReleaseOrErrorHandle(code);
}

/*
 * when UIExtensionComponent connect to UIExtensionAbility, ModalUIExtensionProxy will init,
 * UIExtensionComponent can send message to UIExtensionAbility by ModalUIExtensionProxy
 */
void UIExtensionCallback::OnRemoteReady(const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "connect to UIExtensionAbility successfully.");
}

/*
 * when UIExtensionComponent destructed
 */
void UIExtensionCallback::OnDestroy()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "UIExtensionAbility destructed.");
    if (this->reqContext_->releaseFlag) {
        return;
    }
    Ace::UIContent* uiContent = nullptr;
    if (this->reqContext_->uiAbilityFlag) {
        uiContent = this->reqContext_->abilityContext->GetUIContent();
    } else {
        uiContent = this->reqContext_->uiExtensionContext->GetUIContent();
    }
    if (uiContent == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get ui content failed!");
        return;
    }

    int32_t instanceId = uiContent->GetInstanceId();
    RequestAsyncInstanceControl::ExecCallback(instanceId);
}

static void StartUIExtension(std::shared_ptr<RequestAsyncContext> asyncContext)
{
    Ace::UIContent* uiContent = nullptr;
    int64_t beginTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (asyncContext->uiAbilityFlag) {
        while (true) {
            uiContent = asyncContext->abilityContext->GetUIContent();
            int64_t curTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            if ((uiContent != nullptr) || (curTime - beginTime > NapiContextCommon::MAX_WAIT_TIME)) {
                break;
            }
        }
    } else {
        while (true) {
            uiContent = asyncContext->uiExtensionContext->GetUIContent();
            int64_t curTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            if ((uiContent != nullptr) || (curTime - beginTime > NapiContextCommon::MAX_WAIT_TIME)) {
                break;
            }
        }
    }

    if (uiContent == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get ui content failed!");
        asyncContext->result = RET_FAILED;
        return;
    }
    int32_t instanceId = uiContent->GetInstanceId();
    RequestAsyncInstanceControl::AddCallbackByInstanceId(instanceId, asyncContext);
}

static void CreateUIExtension(std::shared_ptr<RequestAsyncContext> asyncContext)
{
    AAFwk::Want want;
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.grantAbilityName);
    want.SetParam(PERMISSION_KEY, asyncContext->permissionList);
    want.SetParam(STATE_KEY, asyncContext->permissionsState);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);

    Ace::UIContent* uiContent = nullptr;
    if (asyncContext->uiAbilityFlag) {
        uiContent = asyncContext->abilityContext->GetUIContent();
    } else {
        uiContent = asyncContext->uiExtensionContext->GetUIContent();
    }
    if (uiContent == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get ui content failed!");
        asyncContext->result = RET_FAILED;
        return;
    }
    auto uiExtCallback = std::make_shared<UIExtensionCallback>(asyncContext);
    Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        std::bind(&UIExtensionCallback::OnRelease, uiExtCallback, std::placeholders::_1),
        std::bind(&UIExtensionCallback::OnResult, uiExtCallback, std::placeholders::_1, std::placeholders::_2),
        std::bind(&UIExtensionCallback::OnReceive, uiExtCallback, std::placeholders::_1),
        std::bind(&UIExtensionCallback::OnError, uiExtCallback, std::placeholders::_1, std::placeholders::_2,
            std::placeholders::_2),
        std::bind(&UIExtensionCallback::OnRemoteReady, uiExtCallback, std::placeholders::_1),
        std::bind(&UIExtensionCallback::OnDestroy, uiExtCallback),
    };

    Ace::ModalUIExtensionConfig config;
    config.isProhibitBack = true;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
    ACCESSTOKEN_LOG_INFO(LABEL, "Create end, sessionId: %{public}d, tokenId: %{public}d, permNum: %{public}zu",
        sessionId, asyncContext->tokenId, asyncContext->permissionList.size());
    if (sessionId == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "create component failed, sessionId is 0");
        asyncContext->result = RET_FAILED;
        return;
    }
    uiExtCallback->SetSessionId(sessionId);
}


napi_value NapiRequestPermission::RequestPermissionsFromUser(napi_env env, napi_callback_info info)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "RequestPermissionsFromUser begin.");
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

    ACCESSTOKEN_LOG_DEBUG(LABEL, "RequestPermissionsFromUser end.");
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "napi_get_cb_info failed");
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
    ACCESSTOKEN_LOG_INFO(LABEL, "asyncContext.uiAbilityFlag is: %{public}d.", asyncContext->uiAbilityFlag);

    // argv[1] : permissionList
    if (!ParseStringArray(env, argv[1], asyncContext->permissionList) ||
        (asyncContext->permissionList.empty())) {
        errMsg = GetParamErrorMsg("permissions", "Array<string>");
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

    return true;
}

void NapiRequestPermission::RequestPermissionsFromUserExecute(napi_env env, void* data)
{
    // asyncContext release in complete
    RequestAsyncContextHandle* asyncContextHandle = reinterpret_cast<RequestAsyncContextHandle*>(data);
    if (asyncContextHandle->asyncContextPtr->uiAbilityFlag) {
        asyncContextHandle->asyncContextPtr->tokenId =
            asyncContextHandle->asyncContextPtr->abilityContext->GetApplicationInfo()->accessTokenId;
    } else {
        asyncContextHandle->asyncContextPtr->tokenId =
            asyncContextHandle->asyncContextPtr->uiExtensionContext->GetApplicationInfo()->accessTokenId;
    }
    if (asyncContextHandle->asyncContextPtr->tokenId != static_cast<AccessTokenID>(GetSelfTokenID())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "The context is not belong to the current application.");
        asyncContextHandle->asyncContextPtr->result = ERR_PARAM_INVALID;
        return;
    }

    if (!IsDynamicRequest(asyncContextHandle->asyncContextPtr)) {
        ACCESSTOKEN_LOG_INFO(LABEL, "it does not need to request permission");
        asyncContextHandle->asyncContextPtr->needDynamicRequest = false;
        return;
    }
    // service extension dialog
    if (asyncContextHandle->asyncContextPtr->info.grantBundleName == ORI_PERMISSION_MANAGER_BUNDLE_NAME) {
        ACCESSTOKEN_LOG_INFO(LABEL, "pop service extension dialog");
        StartServiceExtension(asyncContextHandle->asyncContextPtr);
    } else {
        ACCESSTOKEN_LOG_INFO(LABEL, "pop ui extension dialog");
        asyncContextHandle->asyncContextPtr->uiExtensionFlag = true;
        StartUIExtension(asyncContextHandle->asyncContextPtr);
        if (asyncContextHandle->asyncContextPtr->result != JsErrorCode::JS_OK) {
            ACCESSTOKEN_LOG_WARN(LABEL, "pop uiextension dialog fail, start to pop service extension dialog");
            asyncContextHandle->asyncContextPtr->uiExtensionFlag = false;
            StartServiceExtension(asyncContextHandle->asyncContextPtr);
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "grantResults empty");
        asyncContextHandle->asyncContextPtr->result = RET_FAILED;
    }
    napi_value requestResult = WrapRequestResult(env, asyncContextHandle->asyncContextPtr->permissionList,
        asyncContextHandle->asyncContextPtr->permissionsState, asyncContextHandle->asyncContextPtr->dialogShownResults);
    if (requestResult == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "wrap requestResult failed");
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
    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetPermissionsStatus begin.");

    auto* asyncContext = new (std::nothrow) RequestAsyncContext(env);
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "new struct fail.");
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

    ACCESSTOKEN_LOG_DEBUG(LABEL, "GetPermissionsStatus end.");
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
        errMsg = GetParamErrorMsg("permissions", "Array<string>");
        NAPI_CALL_BASE(
            env, napi_throw(env, GenerateBusinessError(env, JsErrorCode::JS_ERROR_PARAM_ILLEGAL, errMsg)), false);
        return false;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID = %{public}d, permissionList size = %{public}zu", asyncContext.tokenId,
        asyncContext.permissionList.size());
    return true;
}

void NapiRequestPermission::GetPermissionsStatusExecute(napi_env env, void *data)
{
    RequestAsyncContext* asyncContext = reinterpret_cast<RequestAsyncContext*>(data);

    std::vector<PermissionListState> permList;
    for (const auto& permission : asyncContext->permissionList) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "permission: %{public}s.", permission.c_str());
        PermissionListState permState;
        permState.permissionName = permission;
        permState.state = INVALID_OPER;
        permList.emplace_back(permState);
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "permList size: %{public}zu, asyncContext->permissionList size: %{public}zu.",
        permList.size(), asyncContext->permissionList.size());

    asyncContext->result = AccessTokenKit::GetPermissionsStatus(asyncContext->tokenId, permList);
    for (const auto& permState : permList) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "permission: %{public}s", permState.permissionName.c_str());
        asyncContext->permissionQueryResults.emplace_back(permState.state);
    }
}

void NapiRequestPermission::GetPermissionsStatusComplete(napi_env env, napi_status status, void *data)
{
    RequestAsyncContext* asyncContext = reinterpret_cast<RequestAsyncContext*>(data);
    std::unique_ptr<RequestAsyncContext> callbackPtr {asyncContext};

    if ((asyncContext->permissionQueryResults.empty()) && asyncContext->result == JsErrorCode::JS_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permissionQueryResults empty");
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
    if (!NapiRequestPermission::IsDynamicRequest(asyncContext)) {
        ACCESSTOKEN_LOG_INFO(LABEL, "it does not need to request permission exsion");
        auto* retCB = new (std::nothrow) ResultCallback();
        if (retCB == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "insufficient memory for work!");
            return;
        }
        std::unique_ptr<ResultCallback> callbackPtr {retCB};
        retCB->permissions = asyncContext->permissionList;
        retCB->grantResults = asyncContext->permissionsState;
        retCB->dialogShownResults = asyncContext->dialogShownResults;
        retCB->data = asyncContext;

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
        NAPI_CALL_RETURN_VOID(asyncContext->env, uv_queue_work_with_qos(
            loop, work, [](uv_work_t* work) {}, ResultCallbackJSThreadWorker, uv_qos_user_initiated));

        uvWorkPtr.release();
        callbackPtr.release();
        return;
    }
    isDynamic = true;
}

void RequestAsyncInstanceControl::AddCallbackByInstanceId(
    int32_t id, std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "instance id: %{public}d", id);
    std::lock_guard<std::mutex> lock(instanceIdMutex_);
    auto iter = instanceIdMap_.find(id);
    // id is existed mean a pop window is showing, add context to waiting queue
    if (iter != instanceIdMap_.end()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "instance id: %{public}d has existed.", id);
        instanceIdMap_[id].emplace_back(asyncContext);
        return;
    }
    // make sure id is in map to indicate a pop-up window is showing and remove asyncContext after window shown
    instanceIdMap_[id].emplace_back(asyncContext);
    if (asyncContext->uiExtensionFlag) {
        CreateUIExtension(asyncContext);
    } else {
        CreateServiceExtension(asyncContext);
    }
    instanceIdMap_[id].erase(instanceIdMap_[id].begin());
}

void RequestAsyncInstanceControl::ExecCallback(int32_t id)
{
    std::lock_guard<std::mutex> lock(instanceIdMutex_);
    auto iter = instanceIdMap_.find(id);
    if (iter == instanceIdMap_.end()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "instance id: %{public}d not existed.", id);
        return;
    }
    while (!iter->second.empty()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Instance id map size: %{public}zu.", iter->second.size());
        auto asyncContext = iter->second[0];
        iter->second.erase(iter->second.begin());
        bool isDynamic = false;
        CheckDynamicRequest(asyncContext, isDynamic);
        if (isDynamic) {
            if (asyncContext->uiExtensionFlag) {
                CreateUIExtension(asyncContext);
            } else {
                CreateServiceExtension(asyncContext);
            }
            break;
        }
    }
    if (iter->second.empty()) {
        instanceIdMap_.erase(id);
        return;
    }
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS