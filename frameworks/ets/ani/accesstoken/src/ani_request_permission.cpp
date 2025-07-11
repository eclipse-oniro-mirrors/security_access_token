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
#include "accesstoken_log.h"
#include "hisysevent.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::map<int32_t, std::vector<std::shared_ptr<RequestAsyncContext>>> RequestAsyncInstanceControl::instanceIdMap_;
std::mutex RequestAsyncInstanceControl::instanceIdMutex_;
namespace {
#define SETTER_METHOD_NAME(property) "" #property
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AniRequestPermissionFromUser" };
std::mutex g_lockFlag;
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
}
RequestAsyncContext::~RequestAsyncContext()
{
    if (vm == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "VM is nullptr.");
        return;
    }
    bool isSameThread = IsCurrentThread(threadId);
    ani_env* curEnv = isSameThread ? env : GetCurrentEnv(vm);
    if (curEnv == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetCurrentEnv failed.");
        return;
    }

    if (callbackRef != nullptr) {
        curEnv->GlobalReference_Delete(callbackRef);
        callbackRef = nullptr;
    }
}

template<typename valueType>
static inline bool CallSetter(ani_env* env, ani_class cls, ani_object object, const char* setterName, valueType value)
{
    ani_status status = ANI_ERROR;
    ani_field fieldValue;
    if (env->Class_FindField(cls, setterName, &fieldValue) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Class_FindField Fail %{public}d, name: %{public}s.",
            static_cast<int32_t>(status), setterName);
        return false;
    }
    if ((status = env->Object_SetField_Ref(object, fieldValue, value)) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_SetField_Ref Fail %{public}d, name: %{public}s.",
            static_cast<int32_t>(status), setterName);
        return false;
    }
    return true;
}

static ani_object WrapResult(ani_env* env, std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass("Lsecurity/PermissionRequestResult/PermissionRequestResult;", &cls)) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FindClass status %{public}d ", static_cast<int32_t>(status));
        return nullptr;
    }
    if (cls == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "null cls");
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Class_FindMethod status %{public}d ", static_cast<int32_t>(status));
        return nullptr;
    }
    ani_object aObject = nullptr;
    if ((status = env->Object_New(cls, method, &aObject)) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_New status %{public}d ", static_cast<int32_t>(status));
        return nullptr;
    }
    auto state = asyncContext->needDynamicRequest ? asyncContext->grantResults : asyncContext->permissionsState;
    ani_ref aniPerms = CreateAniArrayString(env, asyncContext->permissionList);
    ani_ref aniAuthRes = CreateAniArrayInt(env, state);
    ani_ref aniDiasShownRes = CreateAniArrayBool(env, asyncContext->dialogShownResults);
    ani_ref aniErrorReasons = CreateAniArrayInt(env, asyncContext->errorReasons);
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

static void UpdateGrantPermissionResultOnly(const std::vector<std::string>& permissions,
    const std::vector<int32_t>& grantResults,
    std::shared_ptr<RequestAsyncContext>& data,
    std::vector<int32_t>& newGrantResults)
{
    size_t size = permissions.size();
    for (size_t i = 0; i < size; i++) {
        int32_t result = static_cast<int32_t>(data->permissionsState[i]);
        if (data->permissionsState[i] == AccessToken::DYNAMIC_OPER) {
            result = data->result.errorCode == AccessToken::RET_SUCCESS ? grantResults[i] : AccessToken::INVALID_OPER;
        }
        newGrantResults.emplace_back(result);
    }
}

static bool IsDynamicRequest(std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "asyncContext nullptr");
        return false;
    }
    std::vector<AccessToken::PermissionListState> permList;
    for (const auto& permission : asyncContext->permissionList) {
        AccessToken::PermissionListState permState;
        permState.permissionName = permission;
        permState.errorReason = SERVICE_ABNORMAL;
        permState.state = AccessToken::INVALID_OPER;
        permList.emplace_back(permState);
    }
    auto ret = AccessToken::AccessTokenKit::GetSelfPermissionsState(permList, asyncContext->info);
    ACCESSTOKEN_LOG_INFO(LABEL,
        "TokenID: %{public}d, bundle: %{public}s, uiExAbility: %{public}s, serExAbility: %{public}s.",
        asyncContext->tokenId, asyncContext->info.grantBundleName.c_str(), asyncContext->info.grantAbilityName.c_str(),
        asyncContext->info.grantServiceAbilityName.c_str());
    if (ret == AccessToken::FORBIDDEN_OPER) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FORBIDDEN_OPER");
        for (auto& perm : permList) {
            perm.state = AccessToken::INVALID_OPER;
            perm.errorReason = PRIVACY_STATEMENT_NOT_AGREED;
        }
    }
    for (const auto& permState : permList) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Permission: %{public}s: state: %{public}d, errorReason: %{public}d",
            permState.permissionName.c_str(), permState.state, permState.errorReason);
        asyncContext->permissionsState.emplace_back(permState.state);
        asyncContext->dialogShownResults.emplace_back(permState.state == AccessToken::TypePermissionOper::DYNAMIC_OPER);
        asyncContext->errorReasons.emplace_back(permState.errorReason);
    }
    if (permList.size() != asyncContext->permissionList.size()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permList.size: %{public}zu, permissionList.size: %{public}zu", permList.size(),
            asyncContext->permissionList.size());
        return false;
    }
    return ret == AccessToken::TypePermissionOper::DYNAMIC_OPER;
}

static void CreateUIExtensionMainThread(std::shared_ptr<RequestAsyncContext>& asyncContext,
    const OHOS::AAFwk::Want& want, const OHOS::Ace::ModalUIExtensionCallbacks& uiExtensionCallbacks,
    const std::shared_ptr<UIExtensionCallback>& uiExtCallback)
{
    auto task = [asyncContext, want, uiExtensionCallbacks, uiExtCallback]() {
        OHOS::Ace::UIContent* uiContent = GetUIContent(asyncContext->abilityContext,
            asyncContext->uiExtensionContext, asyncContext->uiAbilityFlag);
        if (uiContent == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Get ui content failed!");
            asyncContext->result.errorCode = AccessToken::RET_FAILED;
            asyncContext->uiExtensionFlag = false;
            asyncContext->loadlock.unlock();
            return;
        }

        OHOS::Ace::ModalUIExtensionConfig config;
        config.isProhibitBack = true;
        int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
        if (sessionId == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Create component failed, sessionId is 0");
            asyncContext->result.errorCode = AccessToken::RET_FAILED;
            asyncContext->uiExtensionFlag = false;
            asyncContext->loadlock.unlock();
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

static void CreateServiceExtension(std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    if (!asyncContext->uiAbilityFlag) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UIExtension ability can not pop service ablility window!");
        asyncContext->needDynamicRequest = false;
        asyncContext->result.errorCode = RET_FAILED;
        return;
    }
    OHOS::sptr<IRemoteObject> remoteObject = new (std::nothrow) AuthorizationResult(asyncContext);
    if (remoteObject == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Create window failed!");
        asyncContext->needDynamicRequest = false;
        asyncContext->result.errorCode = RET_FAILED;
        return;
    }
    OHOS::AAFwk::Want want;
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.grantServiceAbilityName);
    want.SetParam(PERMISSION_KEY, asyncContext->permissionList);
    want.SetParam(STATE_KEY, asyncContext->permissionsState);
    want.SetParam(TOKEN_KEY, asyncContext->abilityContext->GetToken());
    want.SetParam(CALLBACK_KEY, remoteObject);

    int32_t left = 0;
    int32_t top = 0;
    int32_t width = 0;
    int32_t height = 0;
    asyncContext->abilityContext->GetWindowRect(left, top, width, height);
    want.SetParam(WINDOW_RECTANGLE_LEFT_KEY, left);
    want.SetParam(WINDOW_RECTANGLE_TOP_KEY, top);
    want.SetParam(WINDOW_RECTANGLE_WIDTH_KEY, width);
    want.SetParam(WINDOW_RECTANGLE_HEIGHT_KEY, height);
    want.SetParam(REQUEST_TOKEN_KEY, asyncContext->abilityContext->GetToken());
    int32_t ret = OHOS::AAFwk::AbilityManagerClient::GetInstance()->RequestDialogService(
        want, asyncContext->abilityContext->GetToken());
    ACCESSTOKEN_LOG_INFO(LABEL, "Request end, ret: %{public}d, tokenId: %{public}d, permNum: %{public}zu", ret,
        asyncContext->tokenId, asyncContext->permissionList.size());
}

static void CreateUIExtension(std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    OHOS::AAFwk::Want want;
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.grantAbilityName);
    want.SetParam(PERMISSION_KEY, asyncContext->permissionList);
    want.SetParam(STATE_KEY, asyncContext->permissionsState);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);

    auto uiExtCallback = std::make_shared<UIExtensionCallback>(asyncContext);
    OHOS::Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) { uiExtCallback->OnRelease(releaseCode); },
        [uiExtCallback](
            int32_t resultCode, const OHOS::AAFwk::Want& result) { uiExtCallback->OnResult(resultCode, result); },
        [uiExtCallback](const OHOS::AAFwk::WantParams& receive) { uiExtCallback->OnReceive(receive); },
        [uiExtCallback](int32_t code, const std::string& name, [[maybe_unused]] const std::string& message) {
            uiExtCallback->OnError(code, name, name);
        },
        [uiExtCallback](const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy);
        },
        [uiExtCallback]() { uiExtCallback->OnDestroy(); },
    };
    CreateUIExtensionMainThread(asyncContext, want, uiExtensionCallbacks, uiExtCallback);
}

static void GetInstanceId(std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    auto task = [asyncContext]() {
        OHOS::Ace::UIContent* uiContent = GetUIContent(asyncContext->abilityContext,
            asyncContext->uiExtensionContext, asyncContext->uiAbilityFlag);
        if (uiContent == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Get ui content failed!");
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
}

static void RequestResultsHandler(const std::vector<std::string>& permissionList,
    const std::vector<int32_t>& permissionStates, std::shared_ptr<RequestAsyncContext>& data)
{
    std::vector<int32_t> newGrantResults;
    UpdateGrantPermissionResultOnly(permissionList, permissionStates, data, newGrantResults);
    if (newGrantResults.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GrantResults empty");
        data->result.errorCode = RET_FAILED;
    }
    data->grantResults.assign(newGrantResults.begin(), newGrantResults.end());

    bool isSameThread = IsCurrentThread(data->threadId);
    ani_env* env = isSameThread ? data->env : GetCurrentEnv(data->vm);
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetCurrentEnv failed.");
        return;
    }
    int32_t stsCode = BusinessErrorAni::GetStsErrorCode(data->result.errorCode);
    ani_object error = BusinessErrorAni::CreateError(env, stsCode, GetErrorMessage(stsCode, data->result.errorMsg));
    ani_object result = WrapResult(env, data);
    ExecuteAsyncCallback(env, reinterpret_cast<ani_object>(data->callbackRef), error, result);
    if (!isSameThread && data->vm->DetachCurrentThread() != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "DetachCurrentThread failed!");
    }
}

static ani_status ConvertContext(
    ani_env* env, const ani_object& aniContext, std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, aniContext);
    if (context == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetStageModeContext failed");
        return ANI_ERROR;
    }
    asyncContext->abilityContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (asyncContext->abilityContext != nullptr) {
        auto abilityInfo = asyncContext->abilityContext->GetApplicationInfo();
        if (abilityInfo == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GetApplicationInfo failed");
            return ANI_ERROR;
        }
        asyncContext->uiAbilityFlag = true;
        asyncContext->tokenId = abilityInfo->accessTokenId;
        asyncContext->bundleName = abilityInfo->bundleName;
    } else {
        asyncContext->uiExtensionContext =
            OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::UIExtensionContext>(context);
        if (asyncContext->uiExtensionContext == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertTo UIExtensionContext failed");
            return ANI_ERROR;
        }
        auto uiExtensionInfo = asyncContext->uiExtensionContext->GetApplicationInfo();
        if (uiExtensionInfo == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GetApplicationInfo failed");
            return ANI_ERROR;
        }
        asyncContext->tokenId = uiExtensionInfo->accessTokenId;
        asyncContext->bundleName = uiExtensionInfo->bundleName;
    }
    return ANI_OK;
}

static void RequestPermissionsFromUserProcess(std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    if (!IsDynamicRequest(asyncContext)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "It does not need to request permission");
        asyncContext->needDynamicRequest = false;
        if ((asyncContext->permissionsState.empty()) && (asyncContext->result.errorCode == RET_SUCCESS)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GrantResults empty");
            asyncContext->result.errorCode = RET_FAILED;
        }
        return;
    }

    GetInstanceId(asyncContext);
    if (asyncContext->info.grantBundleName == ORI_PERMISSION_MANAGER_BUNDLE_NAME) {
        ACCESSTOKEN_LOG_INFO(
            LABEL, "Pop service extension dialog, uiContentFlag=%{public}d", asyncContext->uiContentFlag);
        if (asyncContext->uiContentFlag) {
            RequestAsyncInstanceControl::AddCallbackByInstanceId(asyncContext);
        } else {
            CreateServiceExtension(asyncContext);
        }
    } else if (asyncContext->instanceId == -1) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Pop service extension dialog, instanceId is -1.");
        CreateServiceExtension(asyncContext);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQUEST_PERMISSIONS_FROM_USER",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "BUNDLENAME", asyncContext->bundleName.c_str(),
            "UIEXTENSION_FLAG", false);
    } else {
        ACCESSTOKEN_LOG_INFO(LABEL, "Pop ui extension dialog");
        asyncContext->uiExtensionFlag = true;
        RequestAsyncInstanceControl::AddCallbackByInstanceId(asyncContext);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQUEST_PERMISSIONS_FROM_USER",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "BUNDLENAME", asyncContext->bundleName, "UIEXTENSION_FLAG",
            false);
        if (!asyncContext->uiExtensionFlag) {
            ACCESSTOKEN_LOG_WARN(LABEL, "Pop uiextension dialog fail, start to pop service extension dialog.");
            RequestAsyncInstanceControl::AddCallbackByInstanceId(asyncContext);
        }
    }
}

static bool ParseRequestPermissionFromUser(ani_env* env, ani_object aniContext, ani_array_ref aniPermissionList,
    ani_object callback, std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    ani_vm* vm;
    ani_status status = env->GetVM(&vm);
    if (status != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetVM failed, error=%{public}d.", static_cast<int32_t>(status));
        return false;
    }
    asyncContext->vm = vm;
    asyncContext->env = env;
    asyncContext->callback = callback;
    asyncContext->threadId = std::this_thread::get_id();

    status = ConvertContext(env, aniContext, asyncContext);
    if (status != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertContext failed, error=%{public}d.", static_cast<int32_t>(status));
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("context", "UIAbility or UIExtension Context"));
        return false;
    }
    asyncContext->permissionList = ParseAniStringVector(env, aniPermissionList);
    if (!AniParseCallback(env, reinterpret_cast<ani_ref>(callback), asyncContext->callbackRef)) {
        return false;
    }
#ifdef EVENTHANDLER_ENABLE
    asyncContext->handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
#endif
    return true;
}

void RequestPermissionsFromUserExecute([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_object aniContext, ani_array_ref aniPermissionList, ani_object callback)
{
    if (env == nullptr || aniPermissionList == nullptr || callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Parenv or aniPermissionList or callback is null.");
        return;
    }
    std::shared_ptr<RequestAsyncContext> asyncContext = std::make_shared<RequestAsyncContext>();
    if (!ParseRequestPermissionFromUser(env, aniContext, aniPermissionList, callback, asyncContext)) {
        return;
    }

    static AccessTokenID selfTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    if (selfTokenID != asyncContext->tokenId) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "The context tokenID: %{public}d, selfTokenID: %{public}d.", asyncContext->tokenId, selfTokenID);

        ani_ref nullRef = nullptr;
        env->GetNull(&nullRef);
        ani_object result = reinterpret_cast<ani_object>(nullRef);
        ani_object error = BusinessErrorAni::CreateError(env, STS_ERROR_INNER, GetErrorMessage(STS_ERROR_INNER,
            "The specified context does not belong to the current application."));
        ExecuteAsyncCallback(env, callback, error, result);
        return;
    }
    RequestPermissionsFromUserProcess(asyncContext);
    if (asyncContext->needDynamicRequest) {
        return;
    }

    int32_t stsCode = BusinessErrorAni::GetStsErrorCode(asyncContext->result.errorCode);
    ani_object error = BusinessErrorAni::CreateError(
        env, stsCode, GetErrorMessage(stsCode, asyncContext->result.errorMsg));
    ani_object result = WrapResult(env, asyncContext);
    ExecuteAsyncCallback(env, callback, error, result);
    ACCESSTOKEN_LOG_INFO(LABEL, "uiExtensionFlag: %{public}d, uiContentFlag: %{public}d, uiAbilityFlag: %{public}d ",
        asyncContext->uiExtensionFlag, asyncContext->uiContentFlag, asyncContext->uiAbilityFlag);
}

static void CloseModalUIExtensionMainThread(std::shared_ptr<RequestAsyncContext>& asyncContext, int32_t sessionId)
{
    auto task = [asyncContext, sessionId]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext->abilityContext,
            asyncContext->uiExtensionContext, asyncContext->uiAbilityFlag);
        if (uiContent == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Get ui content failed!");
            asyncContext->result.errorCode = RET_FAILED;
            return;
        }
        uiContent->CloseModalUIExtension(sessionId);
        ACCESSTOKEN_LOG_INFO(LABEL, "Close end, sessionId: %{public}d", sessionId);
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
    ACCESSTOKEN_LOG_INFO(LABEL, "Instance id: %{public}d", asyncContext->instanceId);
}

void RequestAsyncInstanceControl::ExecCallback(int32_t id)
{
    std::shared_ptr<RequestAsyncContext> asyncContext = nullptr;
    bool isDynamic = false;
    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        auto iter = RequestAsyncInstanceControl::instanceIdMap_.find(id);
        if (iter == RequestAsyncInstanceControl::instanceIdMap_.end()) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Id: %{public}d not existed.", id);
            return;
        }
        while (!iter->second.empty()) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Id: %{public}d, map size: %{public}zu.", id, iter->second.size());
            asyncContext = iter->second[0];
            iter->second.erase(iter->second.begin());
            CheckDynamicRequest(asyncContext, isDynamic);
            if (isDynamic) {
                break;
            }
        }
        if (iter->second.empty()) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Id: %{public}d, map is empty", id);
            RequestAsyncInstanceControl::instanceIdMap_.erase(id);
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

void RequestAsyncInstanceControl::CheckDynamicRequest(
    std::shared_ptr<RequestAsyncContext>& asyncContext, bool& isDynamic)
{
    asyncContext->permissionsState.clear();
    asyncContext->dialogShownResults.clear();
    if (!IsDynamicRequest(asyncContext)) {
        RequestResultsHandler(asyncContext->permissionList, asyncContext->permissionsState, asyncContext);
        return;
    }
    isDynamic = true;
}

void RequestAsyncInstanceControl::AddCallbackByInstanceId(std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        auto iter = RequestAsyncInstanceControl::instanceIdMap_.find(asyncContext->instanceId);
        if (iter != RequestAsyncInstanceControl::instanceIdMap_.end()) {
            RequestAsyncInstanceControl::instanceIdMap_[asyncContext->instanceId].emplace_back(asyncContext);
            return;
        }
        RequestAsyncInstanceControl::instanceIdMap_[asyncContext->instanceId] = {};
    }
    if (asyncContext->uiExtensionFlag) {
        CreateUIExtension(asyncContext);
    } else {
        CreateServiceExtension(asyncContext);
    }
    return;
}

UIExtensionCallback::UIExtensionCallback(const std::shared_ptr<RequestAsyncContext>& reqContext)
{
    this->reqContext_ = reqContext;
}

UIExtensionCallback::~UIExtensionCallback() {}

void UIExtensionCallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

void UIExtensionCallback::ReleaseHandler(int32_t code)
{
    {
        std::lock_guard<std::mutex> lock(g_lockFlag);
        if (this->reqContext_->releaseFlag) {
            ACCESSTOKEN_LOG_WARN(LABEL, "Callback has executed.");
            return;
        }
        this->reqContext_->releaseFlag = true;
    }
    CloseModalUIExtensionMainThread(this->reqContext_, this->sessionId_);
    this->reqContext_->result.errorCode = code;
    ACCESSTOKEN_LOG_ERROR(LABEL, "ReleaseHandler errorCode: %{public}d",
        this->reqContext_->result.errorCode);
    RequestAsyncInstanceControl::ExecCallback(this->reqContext_->instanceId);
    RequestResultsHandler(this->reqContext_->permissionList, this->reqContext_->permissionsState, this->reqContext_);
}

void UIExtensionCallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ResultCode is %{public}d", resultCode);
    this->reqContext_->permissionList = result.GetStringArrayParam(PERMISSION_KEY);
    this->reqContext_->permissionsState = result.GetIntArrayParam(RESULT_KEY);
    ReleaseHandler(0);
}

void UIExtensionCallback::OnReceive(const OHOS::AAFwk::WantParams& receive)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Called!");
}

void UIExtensionCallback::OnRelease(int32_t releaseCode)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ReleaseCode is %{public}d", releaseCode);
    ReleaseHandler(-1);
}

void UIExtensionCallback::OnError(int32_t code, const std::string& name, const std::string& message)
{
    ACCESSTOKEN_LOG_INFO(
        LABEL, "Code is %{public}d, name is %{public}s, message is %{public}s", code, name.c_str(), message.c_str());

    ReleaseHandler(-1);
}

void UIExtensionCallback::OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Connect to UIExtensionAbility successfully.");
}

void UIExtensionCallback::OnDestroy()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "UIExtensionAbility destructed.");
    ReleaseHandler(-1);
}

void AuthorizationResult::GrantResultsCallback(
    const std::vector<std::string>& permissionList, const std::vector<int32_t>& grantResults)
{
    std::shared_ptr<RequestAsyncContext> asyncContext = data_;
    if (asyncContext == nullptr) {
        return;
    }
    ACCESSTOKEN_LOG_ERROR(LABEL, "GrantResultsCallback");
    RequestResultsHandler(permissionList, grantResults, asyncContext);
}

void AuthorizationResult::WindowShownCallback()
{
    std::shared_ptr<RequestAsyncContext> asyncContext = data_;
    if (asyncContext == nullptr) {
        return;
    }
    OHOS::Ace::UIContent* uiContent = GetUIContent(asyncContext->abilityContext,
        asyncContext->uiExtensionContext, asyncContext->uiAbilityFlag);
    if ((uiContent == nullptr) || !(asyncContext->uiContentFlag)) {
        return;
    }
    RequestAsyncInstanceControl::ExecCallback(asyncContext->instanceId);
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS