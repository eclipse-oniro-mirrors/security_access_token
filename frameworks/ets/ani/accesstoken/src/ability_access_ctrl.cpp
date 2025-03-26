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

#include "ability_access_ctrl.h"

#include <iostream>
#include <uv.h>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "ani_base_context.h"
#include "ani_error.h"
#include "parameter.h"
#include "permission_list_state.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::mutex g_lockFlag;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AniAbilityAccessCtrl" };
constexpr int32_t MAX_LENGTH = 256;

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

#define SETTER_METHOD_NAME(property) "" #property

static void UpdateGrantPermissionResultOnly(const std::vector<std::string> &permissions,
    const std::vector<int> &grantResults, std::shared_ptr<RequestAsyncContext> &data, std::vector<int> &newGrantResults)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "UpdateGrantPermissionResultOnly call");
    uint32_t size = permissions.size();

    for (uint32_t i = 0; i < size; i++) {
        int result = data->permissionsState[i];
        if (data->permissionsState[i] == AccessToken::DYNAMIC_OPER) {
            result = data->result == AccessToken::RET_SUCCESS ? grantResults[i] : AccessToken::INVALID_OPER;
        }
        newGrantResults.emplace_back(result);
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "UpdateGrantPermissionResultOnly end");
}

static bool IsDynamicRequest(std::shared_ptr<RequestAsyncContext> &asyncContext)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "IsDynamicRequest call");
    std::vector<AccessToken::PermissionListState> permList;
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "asyncContext nullptr");
        return false;
    }
    for (const auto &permission : asyncContext->permissionList) {
        AccessToken::PermissionListState permState;
        permState.permissionName = permission;
        permState.state = AccessToken::INVALID_OPER;
        permList.emplace_back(permState);
    }
    auto ret = AccessToken::AccessTokenKit::GetSelfPermissionsState(permList, asyncContext->info);
    if (ret == AccessToken::FORBIDDEN_OPER) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FORBIDDEN_OPER");
        for (auto &perm : permList) {
            perm.state = AccessToken::INVALID_OPER;
        }
    }
    for (const auto &permState : permList) {
        asyncContext->permissionsState.emplace_back(permState.state);
        asyncContext->dialogShownResults.emplace_back(permState.state == AccessToken::TypePermissionOper::DYNAMIC_OPER);
    }
    if (permList.size() != asyncContext->permissionList.size()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permList.size: %{public}zu, permissionList.size: %{public}zu", permList.size(),
            asyncContext->permissionList.size());
        return false;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "IsDynamicRequest end");
    return ret == AccessToken::TypePermissionOper::DYNAMIC_OPER;
}

static void RequestResultsHandler(const std::vector<std::string> &permissionList,
    const std::vector<int32_t> &permissionStates, std::shared_ptr<RequestAsyncContext> &data)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "RequestResultsHandler call");
    auto *retCB = new (std::nothrow) ResultCallback();
    if (retCB == nullptr) {
        return;
    }

    std::vector<int> newGrantResults;
    UpdateGrantPermissionResultOnly(permissionList, permissionStates, data, newGrantResults);

    std::unique_ptr<ResultCallback> callbackPtr { retCB };
    retCB->permissions = permissionList;
    retCB->grantResults = newGrantResults;
    retCB->dialogShownResults = data->dialogShownResults;
    retCB->data = data;

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "work is nullptr");
        return;
    }
    std::unique_ptr<uv_work_t> uvWorkPtr { work };

    uvWorkPtr.release();
    callbackPtr.release();
    ACCESSTOKEN_LOG_INFO(LABEL, "RequestResultsHandler end");
}

static OHOS::Ace::UIContent *GetUIContent(const std::shared_ptr<RequestAsyncContext> &asyncContext)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetUIContent call");
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "asyncContext nullptr");
        return nullptr;
    }
    OHOS::Ace::UIContent *uiContent = nullptr;
    if (asyncContext->uiAbilityFlag) {
        uiContent = asyncContext->abilityContext->GetUIContent();
    } else {
        uiContent = asyncContext->uiExtensionContext->GetUIContent();
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "GetUIContent end");
    return uiContent;
}

static void CreateUIExtensionMainThread(std::shared_ptr<RequestAsyncContext> &asyncContext,
    const OHOS::AAFwk::Want &want, const OHOS::Ace::ModalUIExtensionCallbacks &uiExtensionCallbacks,
    const std::shared_ptr<UIExtensionCallback> &uiExtCallback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "CreateUIExtensionMainThread call");
    auto task = [asyncContext, want, uiExtensionCallbacks, uiExtCallback]() {
        OHOS::Ace::UIContent *uiContent = GetUIContent(asyncContext);
        if (uiContent == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Get ui content failed!");
            asyncContext->result = AccessToken::RET_FAILED;
            asyncContext->uiExtensionFlag = false;
            return;
        }

        OHOS::Ace::ModalUIExtensionConfig config;
        config.isProhibitBack = true;
        int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
        if (sessionId == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Create component failed, sessionId is 0");
            asyncContext->result = AccessToken::RET_FAILED;
            asyncContext->uiExtensionFlag = false;
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

static void CreateServiceExtension(std::shared_ptr<RequestAsyncContext> &asyncContext)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "CreateServiceExtension call");
    if (!asyncContext->uiAbilityFlag) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UIExtension ability can not pop service ablility window!");
        asyncContext->needDynamicRequest = false;
        asyncContext->result = RET_FAILED;
        return;
    }
    OHOS::sptr<IRemoteObject> remoteObject = new (std::nothrow) AuthorizationResult(asyncContext);
    if (remoteObject == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Create window failed!");
        asyncContext->needDynamicRequest = false;
        asyncContext->result = RET_FAILED;
        return;
    }
    OHOS::AAFwk::Want want;
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
    int32_t ret = OHOS::AAFwk::AbilityManagerClient::GetInstance()->RequestDialogService(
        want, asyncContext->abilityContext->GetToken());
    ACCESSTOKEN_LOG_INFO(LABEL, "ret %{public}d, CreateServiceExtension end", ret);
}

static void CreateUIExtension(std::shared_ptr<RequestAsyncContext> &asyncContext)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "CreateUIExtension call");
    OHOS::AAFwk::Want want;
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.grantAbilityName);
    want.SetParam(PERMISSION_KEY, asyncContext->permissionList);
    want.SetParam(STATE_KEY, asyncContext->permissionsState);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);

    auto uiExtCallback = std::make_shared<UIExtensionCallback>(asyncContext);
    OHOS::Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) { uiExtCallback->OnRelease(releaseCode); },
        [uiExtCallback](
            int32_t resultCode, const OHOS::AAFwk::Want &result) { uiExtCallback->OnResult(resultCode, result); },
        [uiExtCallback](const OHOS::AAFwk::WantParams &receive) { uiExtCallback->OnReceive(receive); },
        [uiExtCallback](int32_t code, const std::string &name, [[maybe_unused]] const std::string &message) {
            uiExtCallback->OnError(code, name, name);
        },
        [uiExtCallback](const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy);
        },
        [uiExtCallback]() { uiExtCallback->OnDestroy(); },
    };
    CreateUIExtensionMainThread(asyncContext, want, uiExtensionCallbacks, uiExtCallback);
    ACCESSTOKEN_LOG_INFO(LABEL, "CreateUIExtension end");
}

static void GetInstanceId(std::shared_ptr<RequestAsyncContext> &asyncContext)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetInstanceId call");
    auto task = [asyncContext]() {
        OHOS::Ace::UIContent *uiContent = GetUIContent(asyncContext);
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

static ani_ref ConvertAniArrayString(ani_env *env, const std::vector<std::string> &cArray)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ConvertAniArrayString call");
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "env is nullptr");
        return nullptr;
    }
    ani_size length = cArray.size();
    ani_array_ref aArrayRef = nullptr;
    ani_class aStringcls = nullptr;
    if (env->FindClass("Lstd/core/String;", &aStringcls) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertAniArrayString FindClass String failed");
        return nullptr;
    }
    if (env->Array_New_Ref(aStringcls, length, nullptr, &aArrayRef) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertAniArrayString Array_New_Ref failed ");
        return nullptr;
    }
    ani_string aString = nullptr;
    for (ani_size i = 0; i < length; ++i) {
        env->String_NewUTF8(cArray[i].c_str(), cArray[i].size(), &aString);
        env->Array_Set_Ref(aArrayRef, i, aString);
    }
    ani_ref aRef = nullptr;
    if (env->GlobalReference_Create(aArrayRef, &aRef) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertAniArrayString GlobalReference_Create failed ");
        return nullptr;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "ConvertAniArrayString end");
    return aRef;
}

static ani_ref ConvertAniArrayInt(ani_env *env, const std::vector<int32_t> &cArray)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ConvertAniArrayInt call");
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "env is nullptr");
        return nullptr;
    }
    ani_size length = cArray.size();
    ani_array_int aArrayInt = nullptr;
    if (env->Array_New_Int(length, &aArrayInt) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertAniArrayInt Array_New_Ref failed ");
        return nullptr;
    }
    for (ani_size i = 0; i < length; ++i) {
        env->Array_SetRegion_Int(aArrayInt, i, length, &cArray[i]);
    }
    ani_ref aRef = nullptr;
    if (env->GlobalReference_Create(aArrayInt, &aRef) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertAniArrayInt GlobalReference_Create failed ");
        return nullptr;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "ConvertAniArrayInt end");
    return aRef;
}

static ani_ref ConvertAniArrayBool(ani_env *env, const std::vector<bool> &cArray)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ConvertAniArrayBool call");
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "env is nullptr");
        return nullptr;
    }
    ani_size length = cArray.size();
    ani_array_boolean aArrayBool = nullptr;
    if (env->Array_New_Boolean(length, &aArrayBool) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertAniArrayBool Array_New_Boolean failed ");
        return nullptr;
    }
    std::vector<ani_boolean> boolArray(length);
    for (ani_size i = 0; i < length; ++i) {
        boolArray[i] = cArray[i];
    }
    for (ani_size i = 0; i < length; ++i) {
        env->Array_SetRegion_Boolean(aArrayBool, i, length, &boolArray[i]);
    }
    ani_ref aRef = nullptr;
    if (env->GlobalReference_Create(aArrayBool, &aRef) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertAniArrayBool GlobalReference_Create failed ");
        return nullptr;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "ConvertAniArrayBool end");
    return aRef;
}

template<typename valueType>
static inline bool CallSetter(ani_env *env, ani_class cls, ani_object object, const char *setterName, valueType value)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "CallSetter call");
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "env is nullptr");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_field fieldValue;
    if (env->Class_FindField(cls, setterName, &fieldValue) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Class_FindField Fail %{public}d ", status);
        return false;
    }
    if ((status = env->Object_SetField_Ref(object, fieldValue, value)) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_SetField_Ref Fail %{public}d ", status);
        return false;
    }
    return true;
    ACCESSTOKEN_LOG_INFO(LABEL, "CallSetter end");
}

std::string ANIUtils_ANIStringToStdString(ani_env *env, ani_string ani_str)
{
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "env is nullptr");
        return "";
    }
    ani_size strSize;
    if (env->String_GetUTF8Size(ani_str, &strSize) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "String_GetUTF8Size error");
        return "";
    }

    std::vector<char> buffer(strSize + 1);
    char *utf8_buffer = buffer.data();

    ani_size bytes_written = 0;
    if (env->String_GetUTF8(ani_str, utf8_buffer, strSize + 1, &bytes_written) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "String_GetUTF8 error");
        return "";
    }

    utf8_buffer[bytes_written] = '\0';
    std::string content = std::string(utf8_buffer);
    ACCESSTOKEN_LOG_INFO(LABEL, "ANIUtils_ANIStringToStdString end");
    return content;
}

static void processArrayClass([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_object arrayObj,
    std::vector<std::string> &permissionLists)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "processArrayClass call");
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "env is nullptr");
        return;
    }
    ani_double length;
    if (ANI_OK != env->Object_GetPropertyByName_Double(arrayObj, "length", &length)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_CallMethodByName_Ref length Failed");
        return;
    }

    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref stringEntryRef;
        if (ANI_OK != env->Object_CallMethodByName_Ref(
            arrayObj, "$_get", "I:Lstd/core/Object;", &stringEntryRef, static_cast<ani_int>(i))) {
            BusinessErrorAni::ThrowParameterTypeError(
                env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL, "processArrayClass", "");
            ACCESSTOKEN_LOG_ERROR(LABEL, "Object_CallMethodByName_Ref _get Failed");
            return;
        }
        auto strEntryRef = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(stringEntryRef));
        if (strEntryRef.empty()) {
            BusinessErrorAni::ThrowParameterTypeError(
                env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL, "RequestPermissionsFromUserExecute", "");
            permissionLists.emplace_back(strEntryRef);
            return;
        } else {
            permissionLists.emplace_back(strEntryRef);
        }
        ACCESSTOKEN_LOG_INFO(LABEL, "processArrayClass end");
    }
}

static ani_object ConvertAniArray(ani_env *env, std::shared_ptr<RequestAsyncContext> &asyncContext)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ConvertAniArray call");
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "env is nullptr");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass("Lsecurity/PermissionRequestResult/PermissionRequestResult;", &cls)) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FindClass status %{public}d ", static_cast<int>(status));
        return nullptr;
    }
    if (cls == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "null cls");
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Class_FindMethod status %{public}d ", static_cast<int>(status));
        return nullptr;
    }
    ani_object aObject = nullptr;
    if ((status = env->Object_New(cls, method, &aObject)) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object_New status %{public}d ", static_cast<int>(status));
        return nullptr;
    }
    if (aObject == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "null aObject");
        return nullptr;
    }
    ani_ref strPermissions = ConvertAniArrayString(env, asyncContext->permissionList);
    ani_ref intAuthResults = ConvertAniArrayInt(env, asyncContext->permissionsState);
    ani_ref boolDialogShownResults = ConvertAniArrayBool(env, asyncContext->dialogShownResults);
    ani_ref intPermissionQueryResults = ConvertAniArrayInt(env, asyncContext->permissionQueryResults);
    bool errFalg = CallSetter(env, cls, aObject, SETTER_METHOD_NAME(permissions), strPermissions);
    errFalg = CallSetter(env, cls, aObject, SETTER_METHOD_NAME(authResults), intAuthResults);
    errFalg = CallSetter(env, cls, aObject, SETTER_METHOD_NAME(dialogShownResults), boolDialogShownResults);
    errFalg = CallSetter(env, cls, aObject, SETTER_METHOD_NAME(errorReasons), intPermissionQueryResults);
    if (!errFalg || strPermissions == nullptr || intAuthResults == nullptr || boolDialogShownResults == nullptr ||
        intPermissionQueryResults == nullptr) {
        BusinessErrorAni::ThrowParameterTypeError(env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL,
            "ConvertAniArray", GetParamErrorMsg("asyncContext", "ani_object"));
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "ConvertAniArray end");
    return aObject;
}

static ani_status ConvertContext(
    ani_env *env, const ani_object &aniContext, std::shared_ptr<RequestAsyncContext> &asyncContext)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ConvertContext call");
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "env is nullptr");
        return ANI_ERROR;
    }
    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, aniContext);
    if (context == nullptr) {
        BusinessErrorAni::ThrowParameterTypeError(env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL, "ConvertContext",
            GetParamErrorMsg("context", "UIAbility or UIExtension Context"));
        return ANI_ERROR;
    }
    asyncContext->abilityContext =
        OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (asyncContext->abilityContext == nullptr) {
        BusinessErrorAni::ThrowParameterTypeError(env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL, "ConvertContext",
            GetParamErrorMsg("context", "UIAbility or UIExtension Context"));
        return ANI_ERROR;
    }
    auto abilityInfo = asyncContext->abilityContext->GetApplicationInfo();
    if (abilityInfo == nullptr) {
        BusinessErrorAni::ThrowParameterTypeError(env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL, "ConvertContext",
            GetParamErrorMsg("context", "UIAbility or UIExtension Context"));
        return ANI_ERROR;
    }
    if (asyncContext->abilityContext != nullptr) {
        asyncContext->uiAbilityFlag = true;
        asyncContext->tokenId = abilityInfo->accessTokenId;
        asyncContext->bundleName = abilityInfo->bundleName;
    } else {
        asyncContext->uiExtensionContext =
            OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::UIExtensionContext>(context);
        if (asyncContext->uiExtensionContext == nullptr) {
            BusinessErrorAni::ThrowParameterTypeError(env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL, "ConvertContext",
                GetParamErrorMsg("context", "UIAbility or UIExtension Context"));
            return ANI_ERROR;
        }
        auto uiExtensionInfo = asyncContext->uiExtensionContext->GetApplicationInfo();
        if (uiExtensionInfo == nullptr) {
            BusinessErrorAni::ThrowParameterTypeError(env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL, "ConvertContext",
                GetParamErrorMsg("context", "UIAbility or UIExtension Context"));
            return ANI_ERROR;
        }
        asyncContext->tokenId = uiExtensionInfo->accessTokenId;
        asyncContext->bundleName = uiExtensionInfo->bundleName;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "ConvertContext end");
    return ANI_OK;
}

static ani_object RequestPermissionsFromUserExecute(
    [[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_object aniContext, ani_object permission)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "RequestPermissionsFromUserExecute call");
    if (permission == nullptr) {
        BusinessErrorAni::ThrowParameterTypeError(env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL,
            "RequestPermissionsFromUserExecute", GetParamErrorMsg("permissionList", "nullptr"));
        return nullptr;
    }
    std::shared_ptr<RequestAsyncContext> asyncContext = std::make_shared<RequestAsyncContext>();
    if (ConvertContext(env, aniContext, asyncContext) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertContext failed");
        return nullptr;
    }
    processArrayClass(env, object, permission, asyncContext->permissionList);
#ifdef EVENTHANDLER_ENABLE
    asyncContext->handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
#endif
    AccessTokenID selfTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    if (asyncContext->tokenId != selfTokenID) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID %{public}d selfTokenID %{public}d", asyncContext->tokenId, selfTokenID);
        asyncContext->result = RET_FAILED;
        return nullptr;
    }
    if (!IsDynamicRequest(asyncContext)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "It does not need to request permission");
        asyncContext->needDynamicRequest = false;
        return ConvertAniArray(env, asyncContext);
    }
    GetInstanceId(asyncContext);
    if (asyncContext->info.grantBundleName == ORI_PERMISSION_MANAGER_BUNDLE_NAME) {
        if (asyncContext->uiContentFlag) {
            RequestAsyncInstanceControl::AddCallbackByInstanceId(asyncContext);
        } else {
            CreateServiceExtension(asyncContext);
        }
    } else if (asyncContext->instanceId == -1) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Pop service extension dialog, instanceId is -1.");
        CreateServiceExtension(asyncContext);
    } else {
        asyncContext->uiExtensionFlag = true;
        RequestAsyncInstanceControl::AddCallbackByInstanceId(asyncContext);
        if (!asyncContext->uiExtensionFlag) {
            RequestAsyncInstanceControl::AddCallbackByInstanceId(asyncContext);
        }
    }
    ACCESSTOKEN_LOG_INFO(LABEL,"uiExtensionFlag: %{public}d, uiContentFlag: %{public}d, uiAbilityFlag: %{public}d ",
        asyncContext->uiExtensionFlag, asyncContext->uiContentFlag, asyncContext->uiAbilityFlag);
    return ConvertAniArray(env, asyncContext);
}

static void CloseModalUIExtensionMainThread(std::shared_ptr<RequestAsyncContext> &asyncContext, int32_t sessionId)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "CloseModalUIExtensionMainThread call");
    auto task = [asyncContext, sessionId]() {
        Ace::UIContent *uiContent = GetUIContent(asyncContext);
        if (uiContent == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Get ui content failed!");
            asyncContext->result = RET_FAILED;
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
    ACCESSTOKEN_LOG_INFO(LABEL, "ExecCallback call");
    std::shared_ptr<RequestAsyncContext> asyncContext = nullptr;
    bool isDynamic = false;
    {
        std::lock_guard<std::mutex> lock(instanceIdMutex_);
        auto iter = RequestAsyncInstanceControl::instanceIdMap_.find(id);
        if (iter == RequestAsyncInstanceControl::instanceIdMap_.end()) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "instanceIdMap_ empty");
            return;
        }
        while (!iter->second.empty()) {
            asyncContext = iter->second[0];
            iter->second.erase(iter->second.begin());
            CheckDynamicRequest(asyncContext, isDynamic);
            if (isDynamic) {
                break;
            }
        }
        if (iter->second.empty()) {
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
    ACCESSTOKEN_LOG_INFO(LABEL, "ExecCallback end");
}

void RequestAsyncInstanceControl::CheckDynamicRequest(
    std::shared_ptr<RequestAsyncContext> &asyncContext, bool &isDynamic)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "CheckDynamicRequest call");
    asyncContext->permissionsState.clear();
    asyncContext->dialogShownResults.clear();
    if (!IsDynamicRequest(asyncContext)) {
        RequestResultsHandler(asyncContext->permissionList, asyncContext->permissionsState, asyncContext);
        return;
    }
    isDynamic = true;
    ACCESSTOKEN_LOG_INFO(LABEL, "CheckDynamicRequest end");
}

void RequestAsyncInstanceControl::AddCallbackByInstanceId(std::shared_ptr<RequestAsyncContext> &asyncContext)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "AddCallbackByInstanceId call");
    std::lock_guard<std::mutex> lock(instanceIdMutex_);
    auto iter = RequestAsyncInstanceControl::instanceIdMap_.find(asyncContext->instanceId);
    if (iter != RequestAsyncInstanceControl::instanceIdMap_.end()) {
        RequestAsyncInstanceControl::instanceIdMap_[asyncContext->instanceId].emplace_back(asyncContext);
        return;
    }
    RequestAsyncInstanceControl::instanceIdMap_[asyncContext->instanceId] = {};
    if (asyncContext->uiExtensionFlag) {
        CreateUIExtension(asyncContext);
    } else {
        CreateServiceExtension(asyncContext);
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "AddCallbackByInstanceId end");
}

UIExtensionCallback::UIExtensionCallback(const std::shared_ptr<RequestAsyncContext> &reqContext)
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
    ACCESSTOKEN_LOG_INFO(LABEL, "ReleaseHandler call");
    {
        std::lock_guard<std::mutex> lock(g_lockFlag);
        if (this->reqContext_->releaseFlag) {
            ACCESSTOKEN_LOG_WARN(LABEL, "Callback has executed.");
            return;
        }
        this->reqContext_->releaseFlag = true;
    }
    CloseModalUIExtensionMainThread(this->reqContext_, this->sessionId_);
    this->reqContext_->result = code;
    RequestAsyncInstanceControl::ExecCallback(this->reqContext_->instanceId);
    RequestResultsHandler(this->reqContext_->permissionList, this->reqContext_->permissionsState, this->reqContext_);
    ACCESSTOKEN_LOG_INFO(LABEL, "ReleaseHandler end");
}

void UIExtensionCallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want &result)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ResultCode is %{public}d", resultCode);
    this->reqContext_->permissionList = result.GetStringArrayParam(PERMISSION_KEY);
    this->reqContext_->permissionsState = result.GetIntArrayParam(RESULT_KEY);
    ReleaseHandler(0);
}

void UIExtensionCallback::OnReceive(const OHOS::AAFwk::WantParams &receive)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Called!");
}

void UIExtensionCallback::OnRelease(int32_t releaseCode)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "ReleaseCode is %{public}d", releaseCode);
    ReleaseHandler(-1);
}

void UIExtensionCallback::OnError(int32_t code, const std::string &name, const std::string &message)
{
    ACCESSTOKEN_LOG_INFO(
        LABEL, "Code is %{public}d, name is %{public}s, message is %{public}s", code, name.c_str(), message.c_str());

    ReleaseHandler(-1);
}

void UIExtensionCallback::OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Connect to UIExtensionAbility successfully.");
}

void UIExtensionCallback::OnDestroy()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "UIExtensionAbility destructed.");
    ReleaseHandler(-1);
}

void AuthorizationResult::GrantResultsCallback(
    const std::vector<std::string> &permissionList, const std::vector<int> &grantResults)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GrantResultsCallback call");
    std::shared_ptr<RequestAsyncContext> asyncContext = data_;
    if (asyncContext == nullptr) {
        return;
    }
    RequestResultsHandler(permissionList, grantResults, asyncContext);
}

void AuthorizationResult::WindowShownCallback()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "WindowShownCallback call");
    std::shared_ptr<RequestAsyncContext> asyncContext = data_;
    if (asyncContext == nullptr) {
        return;
    }
    OHOS::Ace::UIContent *uiContent = GetUIContent(asyncContext);
    if ((uiContent == nullptr) || !(asyncContext->uiContentFlag)) {
        return;
    }
    RequestAsyncInstanceControl::ExecCallback(asyncContext->instanceId);
    ACCESSTOKEN_LOG_INFO(LABEL, "WindowShownCallback end");
}

static ani_object CreateAtManager([[maybe_unused]] ani_env *env)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "CreateAtManager call");
    ani_object atManagerObj = {};
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr env");
        return atManagerObj;
    }

    static const char *className = "L@ohos/abilityAccessCtrl/abilityAccessCtrl/AtManagerInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not found %{public}s", className);
        return atManagerObj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get ctor Failed %{public}s", className);
        return atManagerObj;
    }

    if (ANI_OK != env->Object_New(cls, ctor, &atManagerObj)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Create Object Failed %{public}s", className);
        return atManagerObj;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "CreateAtManager end");
    return atManagerObj;
}

static std::string GetPermParamValue()
{
    long long sysCommitId = GetSystemCommitId();
    if (sysCommitId == g_paramCache.sysCommitIdCache) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "SysCommitId = %{public}lld", sysCommitId);
        return g_paramCache.sysParamCache;
    }
    g_paramCache.sysCommitIdCache = sysCommitId;
    if (g_paramCache.handle == PARAM_DEFAULT_VALUE) {
        int32_t handle = static_cast<int32_t>(FindParameter(PERMISSION_STATUS_CHANGE_KEY));
        if (handle == PARAM_DEFAULT_VALUE) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "FindParameter failed");
            return "-1";
        }
        g_paramCache.handle = handle;
    }

    int32_t currCommitId = static_cast<int32_t>(GetParameterCommitId(g_paramCache.handle));
    if (currCommitId != g_paramCache.commitIdCache) {
        char value[AniContextCommon::VALUE_MAX_LEN] = { 0 };
        auto ret = GetParameterValue(g_paramCache.handle, value, AniContextCommon::VALUE_MAX_LEN - 1);
        if (ret < 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Return default value, ret=%{public}d", ret);
            return "-1";
        }
        std::string resStr(value);
        g_paramCache.sysParamCache = resStr;
        g_paramCache.commitIdCache = currCommitId;
    }
    return g_paramCache.sysParamCache;
}

static void UpdatePermissionCache(AtManagerAsyncContext *asyncContext)
{
    std::lock_guard<std::mutex> lock(g_lockCache);
    auto iter = g_cache.find(asyncContext->permissionName);
    if (iter != g_cache.end()) {
        std::string currPara = GetPermParamValue();
        if (currPara != iter->second.paramValue) {
            asyncContext->result =
                AccessToken::AccessTokenKit::VerifyAccessToken(asyncContext->tokenId, asyncContext->permissionName);
            iter->second.status = asyncContext->result;
            iter->second.paramValue = currPara;
            ACCESSTOKEN_LOG_DEBUG(LABEL, "Param changed currPara %{public}s", currPara.c_str());
        } else {
            asyncContext->result = iter->second.status;
        }
    } else {
        asyncContext->result =
            AccessToken::AccessTokenKit::VerifyAccessToken(asyncContext->tokenId, asyncContext->permissionName);
        g_cache[asyncContext->permissionName].status = asyncContext->result;
        g_cache[asyncContext->permissionName].paramValue = GetPermParamValue();
        ACCESSTOKEN_LOG_DEBUG(
            LABEL, "G_cacheParam set %{public}s", g_cache[asyncContext->permissionName].paramValue.c_str());
    }
}

static ani_int CheckAccessTokenSync(
    [[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_int tokenID, ani_string permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "CheckAccessTokenSync call ");
    static uint64_t selfTokenId = GetSelfTokenID();
    auto *asyncContext = new (std::nothrow) AtManagerAsyncContext();
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "New struct fail.");
        return AccessToken::PermissionState::PERMISSION_DENIED;
    }
    ani_status status = ANI_OK;
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr env");
        return AccessToken::PermissionState::PERMISSION_DENIED;
    }
    if (tokenID == 0) {
        BusinessErrorAni::ThrowParameterTypeError(
            env, STSErrorCode::STS_ERROR_PARAM_INVALID, "CheckAccessTokenSync", "");
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is 0");
        return AccessToken::PermissionState::PERMISSION_DENIED;
    }
    ani_size strSize;
    if ((status = env->String_GetUTF8Size(permissionName, &strSize)) != ANI_OK) {
        BusinessErrorAni::ThrowParameterTypeError(
            env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL, "CheckAccessTokenSync", "");
        ACCESSTOKEN_LOG_ERROR(LABEL, "String_GetUTF8Size result : %{public}d", status);
        return AccessToken::PermissionState::PERMISSION_DENIED;
    }
    std::string stdPermissionName = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(permissionName));
    if (stdPermissionName.empty() || stdPermissionName.length() > MAX_LENGTH) {
        BusinessErrorAni::ThrowParameterTypeError(
            env, STSErrorCode::STS_ERROR_PARAM_INVALID, "CheckAccessTokenSync", "");
        ACCESSTOKEN_LOG_ERROR(LABEL, "the max lenth :%{public}d", MAX_LENGTH);
        return AccessToken::PermissionState::PERMISSION_DENIED;
    }
    asyncContext->tokenId = tokenID;
    asyncContext->permissionName = stdPermissionName;
    if (asyncContext->tokenId != static_cast<AccessTokenID>(selfTokenId)) {
        asyncContext->result = AccessToken::AccessTokenKit::VerifyAccessToken(tokenID, stdPermissionName);
        ACCESSTOKEN_LOG_DEBUG(LABEL, "VerifyAccessTokenSync end.");
        return static_cast<ani_int>(asyncContext->result);
    }
    UpdatePermissionCache(asyncContext);
    ACCESSTOKEN_LOG_INFO(LABEL, "call CheckAccessTokenSync result : %{public}d", asyncContext->result);
    return static_cast<ani_int>(asyncContext->result);
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    if (vm == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr vm");
        return ANI_INVALID_ARGS;
    }
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Unsupported ANI_VERSION_1");
        return ANI_OUT_OF_MEMORY;
    }
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr env");
        return ANI_NOT_FOUND;
    }
    const char *spaceName = "L@ohos/abilityAccessCtrl/abilityAccessCtrl;";
    ani_namespace spc;
    if (ANI_OK != env->FindNamespace(spaceName, &spc)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not found %{public}s", spaceName);
        return ANI_NOT_FOUND;
    }
    std::array methods = {
        ani_native_function { "createAtManager", nullptr, reinterpret_cast<void *>(CreateAtManager) },
    };
    if (ANI_OK != env->Namespace_BindNativeFunctions(spc, methods.data(), methods.size())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Cannot bind native methods to %{public}s", spaceName);
        return ANI_ERROR;
    };
    const char *className = "L@ohos/abilityAccessCtrl/abilityAccessCtrl/AtManagerInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not found %{public}s", className);
        return ANI_ERROR;
    }
    std::array claMethods = {
        ani_native_function {
            "checkAccessTokenANI", "ILstd/core/String;:I", reinterpret_cast<void *>(CheckAccessTokenSync) },
        ani_native_function { "requestPermissionsFromUserExecute",
            "Lapplication/Context/Context;Lescompat/Array;:Lsecurity/PermissionRequestResult/PermissionRequestResult;",
            reinterpret_cast<void *>(RequestPermissionsFromUserExecute) },
    };
    if (ANI_OK != env->Class_BindNativeMethods(cls, claMethods.data(), claMethods.size())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Cannot bind native methods to %{public}s", className);
        return ANI_ERROR;
    };
    *result = ANI_VERSION_1;
    return ANI_OK;
}
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS