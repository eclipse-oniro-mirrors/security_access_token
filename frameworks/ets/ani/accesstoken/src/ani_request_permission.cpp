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
#include "ani_request_permission.h"

#include <atomic>
#include <map>
#include <mutex>
#include <thread>

#include "ability_manager_client.h"
#include "accesstoken_kit.h"
#include "accesstoken_common_log.h"
#include "ani_common.h"
#include "ani_hisysevent_adapter.h"
#include "hisysevent.h"
#include "refbase.h"
#include "token_setproc.h"
#include "want.h"
#include "window.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
#define SETTER_METHOD_NAME(property) "" #property
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
std::shared_ptr<RequestInstanceControl> g_requestInstanceControl = nullptr;
std::mutex g_requestInstanceControlLock;
}

static std::shared_ptr<RequestInstanceControl> GetRequestInstanceControl()
{
    std::lock_guard<std::mutex> lock(g_requestInstanceControlLock);
    if (g_requestInstanceControl == nullptr) {
        g_requestInstanceControl = std::make_shared<RequestInstanceControl>();
    }
    return g_requestInstanceControl;
}

RequestAsyncContext::RequestAsyncContext(ani_vm* vm, ani_env* env)
    : RequestAsyncContextBase(vm, env, REQUEST_PERMISSIONS_FROM_USER)
{}

RequestAsyncContext::~RequestAsyncContext()
{
    Clear();
}

static void CreateServiceExtensionWithWindowId(std::shared_ptr<RequestAsyncContext> asyncContext)
{
    sptr<Rosen::Window> window = OHOS::Rosen::Window::GetWindowWithId(asyncContext->windowId);
    if (window == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetWindowWithId failed, windowId: %{public}d", asyncContext->windowId);
        asyncContext->needDynamicRequest_ = false;
        asyncContext->result_.errorCode = STS_ERROR_PARAM_INVALID;
        asyncContext->result_.errorMsg = "Cannot find window by windowId.";
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQ_PERM_FROM_USER_ERROR",
            HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", GET_UI_CONTENT_FAILED);
        return;
    }
    OHOS::sptr<IRemoteObject> remoteObject = new (std::nothrow) AuthorizationResult(asyncContext);
    if (remoteObject == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Create window failed!");
        asyncContext->needDynamicRequest_ = false;
        asyncContext->result_.errorCode = RET_FAILED;
        return;
    }
    OHOS::AAFwk::Want want;
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.grantServiceAbilityName);
    want.SetParam(PERMISSION_KEY, asyncContext->permissionList);
    want.SetParam(STATE_KEY, asyncContext->permissionsState);
    want.SetParam(CALLBACK_KEY, remoteObject);

    if (window->GetContext() == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetContext failed!");
        asyncContext->needDynamicRequest_ = false;
        asyncContext->result_.errorCode = RET_FAILED;
        return;
    }
    want.SetParam(TOKEN_KEY, window->GetContext()->GetToken());
    
    Rosen::Rect windowRect = window->GetRect();

    int32_t left = windowRect.posX_;
    int32_t top = windowRect.posY_;
    int32_t width = static_cast<int32_t>(windowRect.width_);
    int32_t height = static_cast<int32_t>(windowRect.height_);
    want.SetParam(WINDOW_RECTANGLE_LEFT_KEY, left);
    want.SetParam(WINDOW_RECTANGLE_TOP_KEY, top);
    want.SetParam(WINDOW_RECTANGLE_WIDTH_KEY, width);
    want.SetParam(WINDOW_RECTANGLE_HEIGHT_KEY, height);
    want.SetParam(REQUEST_TOKEN_KEY, window->GetContext()->GetToken());

    int32_t ret = AAFwk::AbilityManagerClient::GetInstance()->RequestDialogService(
        want, window->GetContext()->GetToken());
    if (ret != ERR_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "RequestDialogService failed!");
        asyncContext->needDynamicRequest_ = false;
        asyncContext->result_.errorCode = RET_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Request end, ret: %{public}d, tokenId: %{public}d, permNum: %{public}zu",
        ret, asyncContext->tokenId, asyncContext->permissionList.size());
}

static void CreateServiceExtension(std::shared_ptr<RequestAsyncContext> asyncContext)
{
    if (asyncContext->isWithWindowId) {
        CreateServiceExtensionWithWindowId(asyncContext);
        return;
    }
    auto abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(
        asyncContext->stageContext_);
    if (abilityContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Convert to AbilityContext failed. " \
            "UIExtension ability can not pop service ablility window!");
        asyncContext->needDynamicRequest_ = false;
        asyncContext->result_.errorCode = RET_FAILED;
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQ_PERM_FROM_USER_ERROR",
            HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", ABILITY_FLAG_ERROR);
        return;
    }
    OHOS::sptr<IRemoteObject> remoteObject = new (std::nothrow) AuthorizationResult(asyncContext);
    if (remoteObject == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Create window failed!");
        asyncContext->needDynamicRequest_ = false;
        asyncContext->result_.errorCode = RET_FAILED;
        return;
    }
    OHOS::AAFwk::Want want;
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.grantServiceAbilityName);
    want.SetParam(PERMISSION_KEY, asyncContext->permissionList);
    want.SetParam(STATE_KEY, asyncContext->permissionsState);
    want.SetParam(TOKEN_KEY, abilityContext->GetToken());
    want.SetParam(CALLBACK_KEY, remoteObject);

    int32_t left = 0;
    int32_t top = 0;
    int32_t width = 0;
    int32_t height = 0;
    abilityContext->GetWindowRect(left, top, width, height);
    want.SetParam(WINDOW_RECTANGLE_LEFT_KEY, left);
    want.SetParam(WINDOW_RECTANGLE_TOP_KEY, top);
    want.SetParam(WINDOW_RECTANGLE_WIDTH_KEY, width);
    want.SetParam(WINDOW_RECTANGLE_HEIGHT_KEY, height);
    want.SetParam(REQUEST_TOKEN_KEY, abilityContext->GetToken());
    int32_t ret = OHOS::AAFwk::AbilityManagerClient::GetInstance()->RequestDialogService(
        want, abilityContext->GetToken());
    if (ret != ERR_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "RequestDialogService failed!");
        asyncContext->needDynamicRequest_ = false;
        asyncContext->result_.errorCode = RET_FAILED;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Request end, ret: %{public}d, tokenId: %{public}d, permNum: %{public}zu", ret,
        asyncContext->tokenId, asyncContext->permissionList.size());
}

void RequestAsyncContext::StartExtensionAbility(std::shared_ptr<RequestAsyncContextBase> asyncContext)
{
    if (asyncContext == nullptr) {
        LOGI(ATM_DOMAIN, ATM_TAG, "asyncContext is nullptr.");
        return;
    }
    if (asyncContext->isWithWindowId) {
        CreateServiceExtensionWithWindowId(std::static_pointer_cast<RequestAsyncContext>(asyncContext));
        return;
    }

    if (uiExtensionFlag) {
        OHOS::AAFwk::Want want;
        want.SetElementName(this->info.grantBundleName, this->info.grantAbilityName);
        want.SetParam(PERMISSION_KEY, this->permissionList);
        want.SetParam(STATE_KEY, this->permissionsState);
        want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);
        CreateUIExtension(want,
            std::static_pointer_cast<RequestAsyncContext>(asyncContext),
            GetRequestInstanceControl());
    } else {
        CreateServiceExtension(std::static_pointer_cast<RequestAsyncContext>(asyncContext));
    }
}

template<typename valueType>
static inline bool CallSetter(ani_env* env, ani_class cls, ani_object object, const char* setterName, valueType value)
{
    ani_status status = ANI_ERROR;
    ani_field fieldValue;
    if ((status = env->Class_FindField(cls, setterName, &fieldValue)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Class_FindField Fail %{public}u, name: %{public}s.", status, setterName);
        return false;
    }
    if ((status = env->Object_SetField_Ref(object, fieldValue, value)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Object_SetField_Ref Fail %{public}u, name: %{public}s.", status, setterName);
        return false;
    }
    return true;
}

ani_object RequestAsyncContext::WrapResult(ani_env* env)
{
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "env is nullptr");
        return nullptr;
    }
    if ((status = env->FindClass("security.PermissionRequestResult.PermissionRequestResult", &cls)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "FindClass status %{public}u.", status);
        return nullptr;
    }
    if (cls == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "null cls");
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &method)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Class_FindMethod status %{public}u.", status);
        return nullptr;
    }
    ani_object aObject = nullptr;
    if ((status = env->Object_New(cls, method, &aObject)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Object_New status %{public}u ", status);
        return nullptr;
    }
    auto state = this->needDynamicRequest_ ? this->grantResults : this->permissionsState;
    ani_ref aniPerms = CreateAniArrayString(env, permissionList);
    ani_ref aniAuthRes = CreateAniArrayInt(env, state);
    ani_ref aniDiasShownRes = CreateAniArrayBool(env, dialogShownResults);
    ani_ref aniErrorReasons = CreateAniArrayInt(env, errorReasons);
    if (aniPerms == nullptr || aniAuthRes == nullptr || aniDiasShownRes == nullptr || aniErrorReasons == nullptr ||
        !CallSetter(env, cls, aObject, SETTER_METHOD_NAME(permissions), aniPerms) ||
        !CallSetter(env, cls, aObject, SETTER_METHOD_NAME(authResults), aniAuthRes) ||
        !CallSetter(env, cls, aObject, SETTER_METHOD_NAME(dialogShownResults), aniDiasShownRes) ||
        !CallSetter(env, cls, aObject, SETTER_METHOD_NAME(errorReasons), aniErrorReasons)) {
        aObject = nullptr;
    }
    DeleteReference(env, aniPerms);
    DeleteReference(env, aniAuthRes);
    DeleteReference(env, aniDiasShownRes);
    DeleteReference(env, aniErrorReasons);
    return aObject;
}

void RequestAsyncContext::HandleResult(const std::vector<int32_t>& grantResults)
{
    if (permissionsState.size() != grantResults.size()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Size of permissionsState(%{public}zu) and " \
            "grantResults(%{public}zu) is not euqal",
            permissionsState.size(), grantResults.size());
        return;
    }
    std::vector<int32_t> newGrantResults;
    size_t size = grantResults.size();
    for (size_t i = 0; i < size; i++) {
        int32_t result = static_cast<int32_t>(this->permissionsState[i]);
        if (this->permissionsState[i] == AccessToken::DYNAMIC_OPER) {
            result = this->result_.errorCode == AccessToken::RET_SUCCESS ?
                grantResults[i] : AccessToken::INVALID_OPER;
        }
        newGrantResults.emplace_back(result);
    }

    if (newGrantResults.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GrantResults empty");
        result_.errorCode = RET_FAILED;
    }
    this->grantResults.assign(newGrantResults.begin(), newGrantResults.end());
}

bool RequestAsyncContext::IsDynamicRequest()
{
    std::vector<AccessToken::PermissionListState> permList;
    for (const auto& permission : this->permissionList) {
        AccessToken::PermissionListState permState;
        permState.permissionName = permission;
        permState.errorReason = SERVICE_ABNORMAL;
        permState.state = AccessToken::INVALID_OPER;
        permList.emplace_back(permState);
    }
    auto ret = AccessToken::AccessTokenKit::GetSelfPermissionsState(permList, this->info);
    for (const auto& permState : permList) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Permission: %{public}s: state: %{public}d, errorReason: %{public}d",
            permState.permissionName.c_str(), permState.state, permState.errorReason);
        this->permissionsState.emplace_back(permState.state);
        this->dialogShownResults.emplace_back(permState.state == AccessToken::TypePermissionOper::DYNAMIC_OPER);
        this->errorReasons.emplace_back(permState.errorReason);
    }
    if (permList.size() != this->permissionList.size()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "permList.size: %{public}zu, permissionList.size: %{public}zu", permList.size(),
            this->permissionList.size());
        return false;
    }
    return ret == AccessToken::TypePermissionOper::DYNAMIC_OPER;
}

bool RequestAsyncContext::CheckDynamicRequest()
{
    permissionsState.clear();
    dialogShownResults.clear();
    if (!IsDynamicRequest()) {
        HandleResult(this->permissionsState);
        FinishCallback();
        return false;
    }
    return true;
}

void RequestAsyncContext::ProcessUIExtensionCallback(const OHOS::AAFwk::Want& result)
{
    this->permissionList = result.GetStringArrayParam(PERMISSION_KEY);
    this->permissionsState = result.GetIntArrayParam(RESULT_KEY);
    HandleResult(this->permissionsState);
}

int32_t RequestAsyncContext::ConvertErrorCode(int32_t code)
{
    return BusinessErrorAni::GetStsErrorCode(result_.errorCode);
}

bool RequestAsyncContext::NoNeedUpdate()
{
    return true;
}

static void RequestPermissionsFromUserProcess(std::shared_ptr<RequestAsyncContext> asyncContext)
{
    if (!asyncContext->IsDynamicRequest()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "It does not need to request permission");
        asyncContext->needDynamicRequest_ = false;
        if ((asyncContext->permissionsState.empty()) && (asyncContext->result_.errorCode == RET_SUCCESS)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "GrantResults empty");
            asyncContext->result_.errorCode = RET_FAILED;
        }
        return;
    }

    asyncContext->GetInstanceId();
    if (asyncContext->info.grantBundleName == ORI_PERMISSION_MANAGER_BUNDLE_NAME) {
        LOGI(ATM_DOMAIN, ATM_TAG,
            "Pop service extension dialog, uiContentFlag=%{public}d", asyncContext->uiContentFlag);
        if (asyncContext->uiContentFlag) {
            GetRequestInstanceControl()->AddCallbackByInstanceId(asyncContext);
        } else {
            CreateServiceExtension(asyncContext);
        }
    } else if (asyncContext->instanceId == -1) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Pop service extension dialog, instanceId is -1.");
        CreateServiceExtension(asyncContext);
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQUEST_PERMISSIONS_FROM_USER",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "BUNDLENAME", asyncContext->bundleName.c_str(),
            "UIEXTENSION_FLAG", false);
    } else {
        LOGI(ATM_DOMAIN, ATM_TAG, "Pop ui extension dialog");
        asyncContext->uiExtensionFlag = true;
        GetRequestInstanceControl()->AddCallbackByInstanceId(asyncContext);
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQUEST_PERMISSIONS_FROM_USER",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "BUNDLENAME", asyncContext->bundleName, "UIEXTENSION_FLAG",
            false);
        if (!asyncContext->uiExtensionFlag) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Pop uiextension dialog fail, start to pop service extension dialog.");
            GetRequestInstanceControl()->AddCallbackByInstanceId(asyncContext);
        }
    }
}

static bool ParseParameter(ani_env* env, ani_object aniContext, ani_array aniPermissionList,
    ani_object callback, std::shared_ptr<RequestAsyncContext> asyncContext)
{
    if (!asyncContext->FillInfoFromContext(aniContext)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "FillInfoFromContext failed.");
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("context", "UIAbility or UIExtension Context"));
        return false;
    }
    asyncContext->permissionList = ParseAniStringVector(env, aniPermissionList);
    if (!AniParseCallback(env, reinterpret_cast<ani_ref>(callback), asyncContext->callbackRef_)) {
        return false;
    }
    return true;
}

void RequestPermissionsFromUserExecute([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_object aniContext, ani_array aniPermissionList, ani_object callback)
{
    if (env == nullptr || aniPermissionList == nullptr || callback == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "env or aniPermissionList or callback is null.");
        return;
    }
    ani_vm* vm;
    ani_status status = env->GetVM(&vm);
    if (status != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetVM failed, error=%{public}u.", status);
        return;
    }
    std::shared_ptr<RequestAsyncContext> asyncContext = std::make_shared<RequestAsyncContext>(vm, env);
    if (!ParseParameter(env, aniContext, aniPermissionList, callback, asyncContext)) {
        return;
    }

    static AccessTokenID selfTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    if (selfTokenID != asyncContext->tokenId) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "The context tokenID: %{public}d, selfTokenID: %{public}d.", asyncContext->tokenId, selfTokenID);

        ani_ref undefRef = nullptr;
        env->GetUndefined(&undefRef);
        ani_object result = reinterpret_cast<ani_object>(undefRef);
        ani_object error = BusinessErrorAni::CreateError(env, STS_ERROR_INNER, GetErrorMessage(STS_ERROR_INNER,
            "The specified context does not belong to the current application."));
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQ_PERM_FROM_USER_ERROR",
            HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", TOKENID_INCONSISTENCY,
            "SELF_TOKEN", selfTokenID, "CONTEXT_TOKEN", asyncContext->tokenId);
        (void)ExecuteAsyncCallback(env, callback, error, result);
        return;
    }
    RequestPermissionsFromUserProcess(asyncContext);
    if (asyncContext->needDynamicRequest_) {
        return;
    }
    asyncContext->FinishCallback();
    LOGI(ATM_DOMAIN, ATM_TAG, "uiExtensionFlag: %{public}d, uiContentFlag: %{public}d",
        asyncContext->uiExtensionFlag, asyncContext->uiContentFlag);
}

void RequestPermissionsFromUserWithWindowIdExecute([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_object aniContext, ani_int aniWindowId, ani_array aniPermissionList, ani_object callback)
{
    if (env == nullptr || aniPermissionList == nullptr || callback == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "env or aniPermissionList or callback is null.");
        return;
    }
    ani_vm* vm;
    ani_status status = env->GetVM(&vm);
    if (status != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetVM failed, error=%{public}u.", status);
        return;
    }
    std::shared_ptr<RequestAsyncContext> asyncContext = std::make_shared<RequestAsyncContext>(vm, env);
    asyncContext->windowId = static_cast<AccessTokenID>(aniWindowId);
    asyncContext->isWithWindowId = true;
    if (!ParseParameter(env, aniContext, aniPermissionList, callback, asyncContext)) {
        return;
    }

    static AccessTokenID selfTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    if (selfTokenID != asyncContext->tokenId) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "The context tokenID: %{public}d, selfTokenID: %{public}d.", asyncContext->tokenId, selfTokenID);

        ani_ref undefRef = nullptr;
        env->GetUndefined(&undefRef);
        ani_object result = reinterpret_cast<ani_object>(undefRef);
        ani_object error = BusinessErrorAni::CreateError(env, STS_ERROR_INNER, GetErrorMessage(STS_ERROR_INNER,
            "The specified context does not belong to the current application."));
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQ_PERM_FROM_USER_ERROR",
            HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", TOKENID_INCONSISTENCY,
            "SELF_TOKEN", selfTokenID, "CONTEXT_TOKEN", asyncContext->tokenId);
        (void)ExecuteAsyncCallback(env, callback, error, result);
        return;
    }
    RequestPermissionsFromUserProcess(asyncContext);
    if (asyncContext->needDynamicRequest_) {
        return;
    }
    asyncContext->FinishCallback();
    LOGI(ATM_DOMAIN, ATM_TAG, "uiExtensionFlag: %{public}d, uiContentFlag: %{public}d",
        asyncContext->uiExtensionFlag, asyncContext->uiContentFlag);
}


AuthorizationResult::AuthorizationResult(std::shared_ptr<RequestAsyncContext> data) : data_(data)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "AuthorizationResult");
}

AuthorizationResult::~AuthorizationResult()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "~AuthorizationResult");
}

void AuthorizationResult::GrantResultsCallback(
    const std::vector<std::string>& permissionList, const std::vector<int32_t>& grantResults)
{
    std::shared_ptr<RequestAsyncContext> asyncContext = data_;
    if (asyncContext == nullptr) {
        return;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantResultsCallback");
    asyncContext->HandleResult(grantResults);
    asyncContext->FinishCallback();
}

void AuthorizationResult::WindowShownCallback()
{
    std::shared_ptr<RequestAsyncContext> asyncContext = data_;
    if (asyncContext == nullptr) {
        return;
    }
    OHOS::Ace::UIContent* uiContent = GetUIContent(
        asyncContext->stageContext_, asyncContext->windowId, asyncContext->isWithWindowId);
    if ((uiContent == nullptr) || !(asyncContext->uiContentFlag)) {
        return;
    }
    GetRequestInstanceControl()->ExecCallback(asyncContext->instanceId);
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS