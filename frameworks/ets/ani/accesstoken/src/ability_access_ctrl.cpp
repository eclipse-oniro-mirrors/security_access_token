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
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "accesstoken_log.h"
#include "ani_base_context.h"
#include "ani_error.h"
#include "ani_utils.h"
#include "hisysevent.h"
#include "parameter.h"
#include "permission_list_state.h"
#include "permission_map.h"
#include "token_setproc.h"
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::mutex g_lockFlag;
std::mutex g_lockWindowFlag;
bool g_windowFlag = false;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AniAbilityAccessCtrl" };
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t REQUEST_REALDY_EXIST = 1;
const int32_t PERM_NOT_BELONG_TO_SAME_GROUP = 2;
const int32_t PERM_IS_NOT_DECLARE = 3;
const int32_t ALL_PERM_GRANTED = 4;
const int32_t PERM_REVOKE_BY_USER = 5;
std::condition_variable g_loadedCond;
std::mutex g_lockCache;

static constexpr const char* PERMISSION_STATUS_CHANGE_KEY = "accesstoken.permission.change";

const std::string PERMISSION_KEY = "ohos.user.grant.permission";
const std::string PERMISSION_SETTING_KEY = "ohos.user.setting.permission";
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
const std::string RESULT_ERROR_KEY = "ohos.user.setting.error_code";
const std::string PERMISSION_RESULT_KEY = "ohos.user.setting.permission.result";

#define SETTER_METHOD_NAME(property) "" #property
#define ANI_AUTO_SIZE SIZE_MAX

static void UpdateGrantPermissionResultOnly(const std::vector<std::string>& permissions,
    const std::vector<int>& grantResults, std::shared_ptr<RequestAsyncContext>& data, std::vector<int>& newGrantResults)
{
    size_t size = permissions.size();
    for (size_t i = 0; i < size; i++) {
        int result = static_cast<int>(data->permissionsState[i]);
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

static OHOS::Ace::UIContent* GetUIContent(const std::shared_ptr<AbilityRuntime::AbilityContext>& abilityContext,
    std::shared_ptr<AbilityRuntime::UIExtensionContext>& uiExtensionContext, bool uiAbilityFlag)
{
    OHOS::Ace::UIContent* uiContent = nullptr;
    if (uiAbilityFlag) {
        if (abilityContext == nullptr) {
            return nullptr;
        }
        uiContent = abilityContext->GetUIContent();
    } else {
        if (uiExtensionContext == nullptr) {
            return nullptr;
        }
        uiContent = uiExtensionContext->GetUIContent();
    }
    return uiContent;
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

static bool CreateServiceExtension(std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    if (!asyncContext->uiAbilityFlag) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UIExtension ability can not pop service ablility window!");
        asyncContext->needDynamicRequest = false;
        asyncContext->result.errorCode = RET_FAILED;
        return false;
    }
    OHOS::sptr<IRemoteObject> remoteObject = new (std::nothrow) AuthorizationResult(asyncContext);
    if (remoteObject == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Create window failed!");
        asyncContext->needDynamicRequest = false;
        asyncContext->result.errorCode = RET_FAILED;
        return false;
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
    ACCESSTOKEN_LOG_INFO(LABEL, "Request end, ret: %{public}d, tokenId: %{public}d, permNum: %{public}zu", ret,
        asyncContext->tokenId, asyncContext->permissionList.size());
    return true;
}

static bool CreateUIExtension(std::shared_ptr<RequestAsyncContext>& asyncContext)
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
    return true;
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

static ani_ref ConvertAniArrayString(ani_env* env, const std::vector<std::string>& cArray)
{
    ani_size length = cArray.size();
    ani_array_ref aArrayRef = nullptr;
    ani_class aStringcls = nullptr;
    if (env->FindClass("Lstd/core/String;", &aStringcls) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertAniArrayString FindClass String failed");
        return nullptr;
    }
    ani_ref undefinedRef = nullptr;
    if (ANI_OK != env->GetUndefined(&undefinedRef)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertAniArrayString GetUndefined failed");
        return nullptr;
    }
    if (env->Array_New_Ref(aStringcls, length, undefinedRef, &aArrayRef) != ANI_OK) {
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
    return aRef;
}

static ani_ref ConvertAniArrayInt(ani_env* env, const std::vector<int32_t>& cArray)
{
    ani_size length = cArray.size();
    ani_array_int aArrayInt = nullptr;
    if (env->Array_New_Int(length, &aArrayInt) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertAniArrayInt Array_New_Int failed ");
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
    return aRef;
}

static ani_ref ConvertAniArrayBool(ani_env* env, const std::vector<bool>& cArray)
{
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
    return aRef;
}

template<typename valueType>
static inline bool CallSetter(ani_env* env, ani_class cls, ani_object object, const char* setterName, valueType value)
{
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
}

std::string ANIUtils_ANIStringToStdString(ani_env* env, ani_string ani_str)
{
    ani_size strSize;
    if (env->String_GetUTF8Size(ani_str, &strSize) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "String_GetUTF8Size error");
        return "";
    }
    std::vector<char> buffer(strSize + 1);
    char* utf8_buffer = buffer.data();

    ani_size bytes_written = 0;
    if (env->String_GetUTF8(ani_str, utf8_buffer, strSize + 1, &bytes_written) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "String_GetUTF8 error");
        return "";
    }
    utf8_buffer[bytes_written] = '\0';
    std::string content = std::string(utf8_buffer);
    return content;
}

static bool ProcessArrayString([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_array_ref arrayObj, std::vector<std::string>& permissionList)
{
    ani_size length;
    if (ANI_OK != env->Array_GetLength(arrayObj, &length)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Array_GetLength FAILED");
        return false;
    }
    for (ani_size i = 0; i < length; i++) {
        ani_ref stringEntryRef;
        if (ANI_OK != env->Object_CallMethodByName_Ref(
            arrayObj, "$_get", "I:Lstd/core/Object;", &stringEntryRef, static_cast<ani_int>(i))) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Object_CallMethodByName_Ref _get Failed");
            return false;
        }
        auto strEntryRef = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(stringEntryRef));
        if (strEntryRef.empty()) {
            return false;
        } else {
            permissionList.emplace_back(strEntryRef);
        }
    }
    return true;
}

static ani_object WrapResult(ani_env* env, std::shared_ptr<RequestAsyncContext>& asyncContext)
{
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
    auto state = asyncContext->needDynamicRequest ? asyncContext->grantResults : asyncContext->permissionsState;
    ani_ref strPermissions = ConvertAniArrayString(env, asyncContext->permissionList);
    ani_ref intAuthResults = ConvertAniArrayInt(env, state);
    ani_ref boolDialogShownResults = ConvertAniArrayBool(env, asyncContext->dialogShownResults);
    ani_ref intPermissionQueryResults = ConvertAniArrayInt(env, asyncContext->permissionQueryResults);
    if (strPermissions == nullptr || intAuthResults == nullptr || boolDialogShownResults == nullptr ||
        intPermissionQueryResults == nullptr) {
        asyncContext->result.errorCode = RET_FAILED;
        return nullptr;
    }
    if (!CallSetter(env, cls, aObject, SETTER_METHOD_NAME(permissions), strPermissions) ||
        !CallSetter(env, cls, aObject, SETTER_METHOD_NAME(authResults), intAuthResults) ||
        !CallSetter(env, cls, aObject, SETTER_METHOD_NAME(dialogShownResults), boolDialogShownResults) ||
        !CallSetter(env, cls, aObject, SETTER_METHOD_NAME(errorReasons), intPermissionQueryResults)) {
        asyncContext->result.errorCode = RET_FAILED;
        return nullptr;
    }
    return aObject;
}

static ani_object DealWithResult(ani_env* env, std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    ani_object resultObj = nullptr;
    if (asyncContext->result.errorCode == RET_SUCCESS) {
        resultObj = WrapResult(env, asyncContext);
    }
    if (asyncContext->result.errorCode != RET_SUCCESS) {
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(asyncContext->result.errorCode);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode, asyncContext->result.errorMsg));
        return nullptr;
    }
    return resultObj;
}

static void RequestResultsHandler(const std::vector<std::string>& permissionList,
    const std::vector<int32_t>& permissionStates, std::shared_ptr<RequestAsyncContext>& data)
{
    if (data->result.errorCode != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Result is: %{public}d", data->result.errorCode);
        data->result.errorCode = RET_FAILED;
    }
    std::vector<int> newGrantResults;
    UpdateGrantPermissionResultOnly(permissionList, permissionStates, data, newGrantResults);
    if (newGrantResults.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GrantResults empty");
        data->result.errorCode = RET_FAILED;
    }
    data->grantResults.assign(newGrantResults.begin(), newGrantResults.end());
    data->loadlock.unlock();
    g_loadedCond.notify_all();
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

static bool ParseRequestPermissionFromUser(ani_env* env, ani_object aniContext, ani_array_ref permissionList,
    std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    if (ConvertContext(env, aniContext, asyncContext) != ANI_OK) {
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("context", "UIAbility or UIExtension Context"));
        return false;
    }
    if (!ProcessArrayString(env, nullptr, permissionList, asyncContext->permissionList)) {
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("permissionList", "Array<Permissions>"));
        return false;
    }
    return true;
}

static bool RequestPermissionsFromUserProcess([[maybe_unused]] ani_env* env,
    std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    if (!IsDynamicRequest(asyncContext)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "It does not need to request permission");
        asyncContext->needDynamicRequest = false;
        if ((asyncContext->permissionsState.empty()) && (asyncContext->result.errorCode == RET_SUCCESS)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GrantResults empty");
            asyncContext->result.errorCode = RET_FAILED;
        }
        return false;
    }
    GetInstanceId(asyncContext);
    asyncContext->loadlock.lock();
    bool lockFlag = false;
    if (asyncContext->info.grantBundleName == ORI_PERMISSION_MANAGER_BUNDLE_NAME) {
        ACCESSTOKEN_LOG_INFO(
            LABEL, "Pop service extension dialog, uiContentFlag=%{public}d", asyncContext->uiContentFlag);
        if (asyncContext->uiContentFlag) {
            lockFlag = RequestAsyncInstanceControl::AddCallbackByInstanceId(asyncContext);
        } else {
            lockFlag = CreateServiceExtension(asyncContext);
        }
    } else if (asyncContext->instanceId == -1) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Pop service extension dialog, instanceId is -1.");
        lockFlag = CreateServiceExtension(asyncContext);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQUEST_PERMISSIONS_FROM_USER",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "BUNDLENAME", asyncContext->bundleName.c_str(),
            "UIEXTENSION_FLAG", false);
    } else {
        ACCESSTOKEN_LOG_INFO(LABEL, "Pop ui extension dialog");
        asyncContext->uiExtensionFlag = true;
        lockFlag = RequestAsyncInstanceControl::AddCallbackByInstanceId(asyncContext);
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "REQUEST_PERMISSIONS_FROM_USER",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "BUNDLENAME", asyncContext->bundleName, "UIEXTENSION_FLAG",
            false);
        if (!asyncContext->uiExtensionFlag) {
            ACCESSTOKEN_LOG_WARN(LABEL, "Pop uiextension dialog fail, start to pop service extension dialog.");
            lockFlag = RequestAsyncInstanceControl::AddCallbackByInstanceId(asyncContext);
        }
    }
    if (!lockFlag) {
        asyncContext->loadlock.unlock();
    }
    return true;
}

static ani_object RequestPermissionsFromUserExecute([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_object aniContext, ani_array_ref permissionList)
{
    if (env == nullptr || permissionList == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permissionList or env null");
        return nullptr;
    }
    std::shared_ptr<RequestAsyncContext> asyncContext = std::make_shared<RequestAsyncContext>();
    if (!ParseRequestPermissionFromUser(env, aniContext, permissionList, asyncContext)) {
        return nullptr;
    }
#ifdef EVENTHANDLER_ENABLE
    asyncContext->handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
#endif
    static AccessTokenID selfTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    if (selfTokenID != asyncContext->tokenId) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "The context tokenID: %{public}d, selfTokenID: %{public}d.", asyncContext->tokenId, selfTokenID);
        std::string errMsg = GetErrorMessage(
            STS_ERROR_INNER, "The specified context does not belong to the current application.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_INNER, errMsg);
        return nullptr;
    }
    if (!RequestPermissionsFromUserProcess(env, asyncContext)) {
        return DealWithResult(env, asyncContext);
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "uiExtensionFlag: %{public}d, uiContentFlag: %{public}d, uiAbilityFlag: %{public}d ",
        asyncContext->uiExtensionFlag, asyncContext->uiContentFlag, asyncContext->uiAbilityFlag);
    asyncContext->loadlock.lock();
    auto resultObj = DealWithResult(env, asyncContext);
    asyncContext->loadlock.unlock();
    return resultObj;
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
    bool lockFlag = true;
    if (isDynamic) {
        if (asyncContext->uiExtensionFlag) {
            lockFlag = CreateUIExtension(asyncContext);
        } else {
            lockFlag = CreateServiceExtension(asyncContext);
        }
    }
    if (!lockFlag) {
        asyncContext->loadlock.unlock();
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

bool RequestAsyncInstanceControl::AddCallbackByInstanceId(std::shared_ptr<RequestAsyncContext>& asyncContext)
{
    std::lock_guard<std::mutex> lock(instanceIdMutex_);
    auto iter = RequestAsyncInstanceControl::instanceIdMap_.find(asyncContext->instanceId);
    if (iter != RequestAsyncInstanceControl::instanceIdMap_.end()) {
        RequestAsyncInstanceControl::instanceIdMap_[asyncContext->instanceId].emplace_back(asyncContext);
        return true;
    }
    RequestAsyncInstanceControl::instanceIdMap_[asyncContext->instanceId] = {};
    bool lockFlag = true;
    if (asyncContext->uiExtensionFlag) {
        lockFlag = CreateUIExtension(asyncContext);
    } else {
        lockFlag = CreateServiceExtension(asyncContext);
    }
    return lockFlag;
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
    const std::vector<std::string>& permissionList, const std::vector<int>& grantResults)
{
    std::shared_ptr<RequestAsyncContext> asyncContext = data_;
    if (asyncContext == nullptr) {
        return;
    }
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

static ani_object CreateAtManager([[maybe_unused]] ani_env* env)
{
    ani_object atManagerObj = {};
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr env");
        return atManagerObj;
    }

    static const char* className = "L@ohos/abilityAccessCtrl/abilityAccessCtrl/AtManagerInner;";
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

static void UpdatePermissionCache(AtManagerAsyncContext* asyncContext)
{
    std::lock_guard<std::mutex> lock(g_lockCache);
    auto iter = g_cache.find(asyncContext->permissionName);
    if (iter != g_cache.end()) {
        std::string currPara = GetPermParamValue();
        if (currPara != iter->second.paramValue) {
            asyncContext->grantStatus =
                AccessToken::AccessTokenKit::VerifyAccessToken(asyncContext->tokenId, asyncContext->permissionName);
            iter->second.status = asyncContext->grantStatus;
            iter->second.paramValue = currPara;
            ACCESSTOKEN_LOG_DEBUG(LABEL, "Param changed currPara %{public}s", currPara.c_str());
        } else {
            asyncContext->grantStatus = iter->second.status;
        }
    } else {
        asyncContext->grantStatus =
            AccessToken::AccessTokenKit::VerifyAccessToken(asyncContext->tokenId, asyncContext->permissionName);
        g_cache[asyncContext->permissionName].status = asyncContext->grantStatus;
        g_cache[asyncContext->permissionName].paramValue = GetPermParamValue();
        ACCESSTOKEN_LOG_DEBUG(
            LABEL, "G_cacheParam set %{public}s", g_cache[asyncContext->permissionName].paramValue.c_str());
    }
}

static ani_int CheckAccessTokenSync([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_int tokenID, ani_string permissionName)
{
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr env");
        return AccessToken::PermissionState::PERMISSION_DENIED;
    }
    if (tokenID == 0) {
        std::string errMsg = GetErrorMessage(STS_ERROR_PARAM_INVALID, "The tokenID is 0.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_INVALID, errMsg);
        return AccessToken::PermissionState::PERMISSION_DENIED;
    }
    std::string stdPermissionName = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(permissionName));
    if (stdPermissionName.empty() || stdPermissionName.length() > MAX_LENGTH) {
        std::string errMsg = GetErrorMessage(
            STS_ERROR_PARAM_INVALID, "The permissionName is empty or exceeds 256 characters.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_INVALID, errMsg);
        return AccessToken::PermissionState::PERMISSION_DENIED;
    }
    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext();
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "New struct fail.");
        return AccessToken::PermissionState::PERMISSION_DENIED;
    }
    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    asyncContext->tokenId = static_cast<AccessTokenID>(tokenID);
    asyncContext->permissionName = stdPermissionName;
    static uint64_t selfTokenId = GetSelfTokenID();
    if (asyncContext->tokenId != static_cast<AccessTokenID>(selfTokenId)) {
        asyncContext->grantStatus = AccessToken::AccessTokenKit::VerifyAccessToken(tokenID, stdPermissionName);
        return static_cast<ani_int>(asyncContext->grantStatus);
    }
    UpdatePermissionCache(asyncContext);
    ACCESSTOKEN_LOG_INFO(LABEL, "CheckAccessTokenSync result : %{public}d", asyncContext->grantStatus);
    return static_cast<ani_int>(asyncContext->grantStatus);
}

static ani_status GetContext(
    ani_env* env, const ani_object& aniContext, std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
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
    }
    return ANI_OK;
}

static bool ParseRequestPermissionOnSetting(ani_env* env, ani_object& aniContext, ani_array_ref& permissionList,
    std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    if (GetContext(env, aniContext, asyncContext) != ANI_OK) {
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("context", "UIAbility or UIExtension Context"));
        return false;
    }
    if (!ProcessArrayString(env, nullptr, permissionList, asyncContext->permissionList)) {
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("permissionList", "Array<string>"));
        return false;
    }
    return true;
}

static void StateToEnumIndex(int32_t state, ani_size& enumIndex)
{
    if (state == 0) {
        enumIndex = 1;
    } else {
        enumIndex = 0;
    }
}

static ani_ref ReturnResult(ani_env* env, std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    ani_class arrayCls = nullptr;
    if (env->FindClass("Lescompat/Array;", &arrayCls) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FindClass name Lescompat/Array failed!");
        return nullptr;
    }

    ani_method arrayCtor;
    if (env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FindClass <ctor> failed!");
        return nullptr;
    }

    ani_object arrayObj;
    if (env->Object_New(arrayCls, arrayCtor, &arrayObj, asyncContext->stateList.size()) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Object new failed!");
        return nullptr;
    }

    const char* enumDescriptor = "L@ohos/abilityAccessCtrl/abilityAccessCtrl/GrantStatus;";
    ani_enum enumType;
    if (env->FindEnum(enumDescriptor, &enumType) != ANI_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "FindClass name %{public}s failed!", enumDescriptor);
        return nullptr;
    }

    ani_size index = 0;
    for (const auto& state: asyncContext->stateList) {
        ani_enum_item enumItem;
        ani_size enumIndex = 0;
        StateToEnumIndex(state, enumIndex);
        if (env->Enum_GetEnumItemByIndex(enumType, enumIndex, &enumItem) != ANI_OK) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GetEnumItemByIndex value %{public}u failed!", state);
            break;
        }

        if (env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", index, enumItem) != ANI_OK) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Object_CallMethodByName_Void $_set failed!");
            break;
        }
        index++;
    }

    return arrayObj;
}

static int32_t TransferToStsErrorCode(int32_t errorCode)
{
    int32_t stsCode = STS_OK;
    switch (errorCode) {
        case RET_SUCCESS:
            stsCode = STS_OK;
            break;
        case REQUEST_REALDY_EXIST:
            stsCode = STS_ERROR_REQUEST_IS_ALREADY_EXIST;
            break;
        case PERM_NOT_BELONG_TO_SAME_GROUP:
            stsCode = STS_ERROR_PARAM_INVALID;
            break;
        case PERM_IS_NOT_DECLARE:
            stsCode = STS_ERROR_PARAM_INVALID;
            break;
        case ALL_PERM_GRANTED:
            stsCode = STS_ERROR_ALL_PERM_GRANTED;
            break;
        case PERM_REVOKE_BY_USER:
            stsCode = STS_ERROR_PERM_REVOKE_BY_USER;
            break;
        default:
            stsCode = STS_ERROR_INNER;
            break;
    }
    ACCESSTOKEN_LOG_ERROR(LABEL, "Dialog error(%{public}d) stsCode(%{public}d).", errorCode, stsCode);
    return stsCode;
}

static ani_ref RequestPermissionOnSettingComplete(
    ani_env* env, std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    if (asyncContext->result.errorCode == RET_SUCCESS) {
        ani_ref result = ReturnResult(env, asyncContext);
        if (result != nullptr) {
            return result;
        }
        asyncContext->result.errorCode = RET_FAILED;
    }

    int32_t stsCode = TransferToStsErrorCode(asyncContext->result.errorCode);
    BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
    return nullptr;
}

PermissonOnSettingUICallback::PermissonOnSettingUICallback(ani_env* env,
    const std::shared_ptr<RequestPermOnSettingAsyncContext>& reqContext)
{
    this->env_ = env;
    this->reqContext_ = reqContext;
}

PermissonOnSettingUICallback::~PermissonOnSettingUICallback()
{}

void PermissonOnSettingUICallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

static void CloseSettingModalUIExtensionMainThread(std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext,
    int32_t sessionId)
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
}

void PermissonOnSettingUICallback::ReleaseHandler(int32_t code)
{
    {
        std::lock_guard<std::mutex> lock(this->lockReleaseFlag);
        if (this->releaseFlag) {
            ACCESSTOKEN_LOG_WARN(LABEL, "Callback has executed.");
            return;
        }
        this->releaseFlag = true;
    }
    CloseSettingModalUIExtensionMainThread(this->reqContext_, this->sessionId_);
    if (code == -1) {
        this->reqContext_->result.errorCode = code;
    }
    this->reqContext_->loadlock.unlock();
    std::lock_guard<std::mutex> lock(g_lockWindowFlag);
    g_windowFlag = false;
}

/*
 * when UIExtensionAbility use terminateSelfWithResult
 */
void PermissonOnSettingUICallback::OnResult(int32_t resultCode, const AAFwk::Want& result)
{
    this->reqContext_->result.errorCode = result.GetIntParam(RESULT_ERROR_KEY, 0);
    this->reqContext_->stateList = result.GetIntArrayParam(PERMISSION_RESULT_KEY);
    ACCESSTOKEN_LOG_INFO(LABEL, "ResultCode is %{public}d, listSize=%{public}zu.",
        resultCode, this->reqContext_->stateList.size());
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

static void CreateSettingUIExtensionMainThread(std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext,
    const AAFwk::Want& want, const Ace::ModalUIExtensionCallbacks& uiExtensionCallbacks,
    const std::shared_ptr<PermissonOnSettingUICallback>& uiExtCallback)
{
    auto task = [asyncContext, want, uiExtensionCallbacks, uiExtCallback]() {
        Ace::UIContent* uiContent = GetUIContent(asyncContext->abilityContext,
            asyncContext->uiExtensionContext, asyncContext->uiAbilityFlag);
        if (uiContent == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to get ui content!");
            asyncContext->result.errorCode = RET_FAILED;
            return;
        }

        Ace::ModalUIExtensionConfig config;
        config.isProhibitBack = true;
        int32_t sessionId = uiContent->CreateModalUIExtension(want, uiExtensionCallbacks, config);
        ACCESSTOKEN_LOG_INFO(LABEL, "Create end, sessionId: %{public}d, tokenId: %{public}d.",
            sessionId, asyncContext->tokenId);
        if (sessionId == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to create component, sessionId is 0.");
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

static bool StartUIExtension(ani_env* env, std::shared_ptr<RequestPermOnSettingAsyncContext>& asyncContext)
{
    AccessTokenKit::GetPermissionManagerInfo(asyncContext->info);

    OHOS::AAFwk::Want want;
    want.SetElementName(asyncContext->info.grantBundleName, asyncContext->info.permStateAbilityName);
    want.SetParam(PERMISSION_SETTING_KEY, asyncContext->permissionList);
    want.SetParam(EXTENSION_TYPE_KEY, UI_EXTENSION_TYPE);

    auto uiExtCallback = std::make_shared<PermissonOnSettingUICallback>(env, asyncContext);
    Ace::ModalUIExtensionCallbacks uiExtensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) {
            uiExtCallback->OnRelease(releaseCode);
        },
        [uiExtCallback](int32_t resultCode, const AAFwk::Want& result) {
            uiExtCallback->OnResult(resultCode, result);
        },
        [uiExtCallback](const AAFwk::WantParams& receive) {
            uiExtCallback->OnReceive(receive);
        },
        [uiExtCallback](int32_t code, const std::string& name, [[maybe_unused]] const std::string& message) {
            uiExtCallback->OnError(code, name, name);
        },
        [uiExtCallback](const std::shared_ptr<Ace::ModalUIExtensionProxy>& uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy);
        },
        [uiExtCallback]() {
            uiExtCallback->OnDestroy();
        },
    };

    {
        std::lock_guard<std::mutex> lock(g_lockWindowFlag);
        if (g_windowFlag) {
            ACCESSTOKEN_LOG_WARN(LABEL, "The request already exists.");
            asyncContext->result.errorCode = REQUEST_REALDY_EXIST;
            asyncContext->result.errorMsg = "The specified context does not belong to the current application.";
            return false;
        }
        g_windowFlag = true;
    }
    CreateSettingUIExtensionMainThread(asyncContext, want, uiExtensionCallbacks, uiExtCallback);
    if (asyncContext->result.errorCode == RET_FAILED) {
        {
            std::lock_guard<std::mutex> lock(g_lockWindowFlag);
            g_windowFlag = false;
            return false;
        }
    }
    return true;
}

static ani_ref RequestPermissionOnSettingExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_object aniContext, ani_array_ref permissionList)
{
    if (env == nullptr || permissionList == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permissionList or env null");
        return nullptr;
    }

    std::shared_ptr<RequestPermOnSettingAsyncContext> asyncContext =
        std::make_shared<RequestPermOnSettingAsyncContext>();
    if (!ParseRequestPermissionOnSetting(env, aniContext, permissionList, asyncContext)) {
        return nullptr;
    }

    static AccessTokenID selfTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    if (selfTokenID != asyncContext->tokenId) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "The context tokenID %{public}d is not same with selfTokenID %{public}d.",
            asyncContext->tokenId, selfTokenID);
        std::string errMsg = GetErrorMessage(
            STS_ERROR_INNER, "The specified context does not belong to the current application.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_INNER, errMsg);
        return nullptr;
    }
    asyncContext->loadlock.lock();
    bool flag = StartUIExtension(env, asyncContext);
    if (!flag) {
        asyncContext->loadlock.unlock();
    }
    asyncContext->loadlock.lock();
    ani_ref result = RequestPermissionOnSettingComplete(env, asyncContext);
    asyncContext->loadlock.unlock();
    return result;
}

static bool IsPermissionFlagValid(uint32_t flag)
{
    return (flag == PermissionFlag::PERMISSION_USER_SET) || (flag == PermissionFlag::PERMISSION_USER_FIXED) ||
        (flag == PermissionFlag::PERMISSION_ALLOW_THIS_TIME);
};

static void GrantUserGrantedPermissionExecute([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_int tokenID, ani_string aniPermissionName, ani_int permissionFlags)
{
    if (env == nullptr) {
        return;
    }
    std::string permissionName;
    if (!AniParseString(env, aniPermissionName, permissionName)) {
        BusinessErrorAni::ThrowParameterTypeError(env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("permissionName", "Permissions"));
        return;
    }

    if (permissionName.empty() || permissionName.size() > MAX_LENGTH) {
        BusinessErrorAni::ThrowError(env, STSErrorCode::STS_ERROR_PARAM_INVALID,
            GetErrorMessage(STSErrorCode::STS_ERROR_PARAM_INVALID));
        return;
    }
    if (!IsPermissionFlagValid(static_cast<uint32_t>(permissionFlags))) {
        BusinessErrorAni::ThrowError(env, STSErrorCode::STS_ERROR_PARAM_INVALID,
            GetErrorMessage(STSErrorCode::STS_ERROR_PARAM_INVALID));
        return;
    }
    PermissionBriefDef def;
    if (!GetPermissionBriefDef(permissionName, def)) {
        BusinessErrorAni::ThrowError(env, STSErrorCode::STS_ERROR_PERMISSION_NOT_EXIST,
            GetErrorMessage(STSErrorCode::STS_ERROR_PERMISSION_NOT_EXIST));
        return;
    }
    
    if (def.grantMode != USER_GRANT || !GetPermissionBriefDef(permissionName, def)) {
        std::string errMsg = GetErrorMessage(STS_ERROR_PERMISSION_NOT_EXIST,
            "The specified permission does not exist or is not a user_grant permission.");
        BusinessErrorAni::ThrowError(
            env, STS_ERROR_PERMISSION_NOT_EXIST, GetErrorMessage(STS_ERROR_PERMISSION_NOT_EXIST));
        return;
    }

    int32_t res = AccessTokenKit::GrantPermission(tokenID, permissionName, permissionFlags);
    if (res != RET_SUCCESS) {
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(res);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
    }
}

static void RevokeUserGrantedPermissionExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_int tokenID, ani_string permissionName, ani_int permissionFlags)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "RevokeUserGrantedPermission begin.");
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "env null.");
        return;
    }

    std::string permissionNameString;
    if (!AniParseString(env, permissionName, permissionNameString)) {
        BusinessErrorAni::ThrowParameterTypeError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("permissionName", "Permissions"));
        return;
    }
    
    if (!IsPermissionFlagValid(static_cast<uint32_t> (permissionFlags))) {
        std::string errMsg = GetErrorMessage(STS_ERROR_PARAM_INVALID, "The permissionFlags is invalid.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_INVALID, errMsg);
        return;
    }

    if (permissionNameString.empty() || permissionNameString.size() > MAX_LENGTH) {
        std::string errMsg = GetErrorMessage(
            STS_ERROR_PARAM_INVALID, "The permissionName is empty or exceeds 256 characters.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_INVALID, errMsg);
        return;
    }
    PermissionBriefDef def;
    if (!GetPermissionBriefDef(permissionNameString, def) || def.grantMode != USER_GRANT) {
        std::string errMsg = GetErrorMessage(STS_ERROR_PERMISSION_NOT_EXIST,
            "The specified permission does not exist or is not a user_grant permission.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_PERMISSION_NOT_EXIST, errMsg);
        return;
    }

    int32_t ret = AccessTokenKit::RevokePermission(tokenID, permissionNameString, permissionFlags);
    if (ret != RET_SUCCESS) {
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(ret);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
    }
}

static ani_int GetVersionExecute([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "getVersionExecute begin.");
    uint32_t version = -1;
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "env null");
        return static_cast<ani_int>(version);
    }

    int32_t result = AccessTokenKit::GetVersion(version);
    if (result != RET_SUCCESS) {
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(result);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
        return static_cast<ani_int>(version);
    }
    return static_cast<ani_int>(version);
}

static ani_ref GetPermissionsStatusExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_int tokenID, ani_array_ref permissionList)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetPermissionsStatusExecute begin.");
    if ((env == nullptr) || (permissionList == nullptr)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permissionList or env null.");
        return nullptr;
    }
    std::vector<std::string> aniPermissionList;
    if (!AniParseStringArray(env, permissionList, aniPermissionList)) {
        BusinessErrorAni::ThrowParameterTypeError(
            env, STS_ERROR_PARAM_ILLEGAL, GetParamErrorMsg("permissionList", "Array<Permissions>"));
        return nullptr;
    }

    if (aniPermissionList.empty()) {
        std::string errMsg = GetErrorMessage(STS_ERROR_INNER, "The permissionList is empty.");
            BusinessErrorAni::ThrowError(env, STS_ERROR_INNER, GetErrorMessage(STS_ERROR_INNER));
        return nullptr;
    }

    std::vector<PermissionListState> permList;
    for (const auto& permission : aniPermissionList) {
        PermissionListState permState;
        permState.permissionName = permission;
        permState.state = INVALID_OPER;
        permList.emplace_back(permState);
    }

    int32_t result = RET_SUCCESS;
    std::vector<int32_t> permissionQueryResults;
    result = AccessTokenKit::GetPermissionsStatus(tokenID, permList);
    if (result != RET_SUCCESS) {
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(result);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
        return nullptr;
    }
    for (const auto& permState : permList) {
        permissionQueryResults.emplace_back(permState.state);
    }

    return ConvertAniArrayInt(env, permissionQueryResults);
}

static ani_int GetPermissionFlagsExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_int tokenID, ani_string aniPermissionName)
{
    uint32_t flag = PERMISSION_DEFAULT_FLAG;
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Env is null");
        return flag;
    }
    std::string permissionName;
    if (!AniParseString(env, aniPermissionName, permissionName)) {
        BusinessErrorAni::ThrowParameterTypeError(env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("permissionName", "Permissions"));
        return flag;
    }
    int32_t result = AccessTokenKit::GetPermissionFlag(tokenID, permissionName, flag);
    if (result != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "result =  %{public}d  errcode = %{public}d",
            result, BusinessErrorAni::GetStsErrorCode(result));
        BusinessErrorAni::ThrowError(env, BusinessErrorAni::GetStsErrorCode(result),
            GetErrorMessage(BusinessErrorAni::GetStsErrorCode(result)));
    }
    return flag;
}

static void SetPermissionRequestToggleStatusExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_string aniPermissionName, ani_int status)
{
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Env is null");
        return;
    }
    std::string permissionName;
    if (!AniParseString(env, aniPermissionName, permissionName)) {
        BusinessErrorAni::ThrowParameterTypeError(env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("permissionName", "Permissions"));
        return;
    }
    int32_t result = AccessTokenKit::SetPermissionRequestToggleStatus(permissionName, status, 0);
    if (result != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "result =  %{public}d  errcode = %{public}d",
            result, BusinessErrorAni::GetStsErrorCode(result));
        BusinessErrorAni::ThrowError(env, BusinessErrorAni::GetStsErrorCode(result),
            GetErrorMessage(BusinessErrorAni::GetStsErrorCode(result)));
    }
    return;
}

static ani_int GetPermissionRequestToggleStatusExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_string aniPermissionName)
{
    uint32_t flag = CLOSED;
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Env is null");
        return flag;
    }
    std::string permissionName;
    if (!AniParseString(env, aniPermissionName, permissionName)) {
        BusinessErrorAni::ThrowParameterTypeError(env, STSErrorCode::STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("permissionName", "Permissions"));
        return flag;
    }
    int32_t result = AccessTokenKit::GetPermissionRequestToggleStatus(permissionName, flag, 0);
    if (result != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "result =  %{public}d  errcode = %{public}d",
            result, BusinessErrorAni::GetStsErrorCode(result));
        BusinessErrorAni::ThrowError(env, BusinessErrorAni::GetStsErrorCode(result),
            GetErrorMessage(BusinessErrorAni::GetStsErrorCode(result)));
    }
    return flag;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    if (vm == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr vm");
        return ANI_INVALID_ARGS;
    }
    ani_env* env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Unsupported ANI_VERSION_1");
        return ANI_OUT_OF_MEMORY;
    }
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr env");
        return ANI_NOT_FOUND;
    }
    const char* spaceName = "L@ohos/abilityAccessCtrl/abilityAccessCtrl;";
    ani_namespace spc;
    if (ANI_OK != env->FindNamespace(spaceName, &spc)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not found %{public}s", spaceName);
        return ANI_NOT_FOUND;
    }
    std::array methods = {
        ani_native_function { "createAtManager", nullptr, reinterpret_cast<void*>(CreateAtManager) },
    };
    if (ANI_OK != env->Namespace_BindNativeFunctions(spc, methods.data(), methods.size())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Cannot bind native methods to %{public}s", spaceName);
        return ANI_ERROR;
    };
    const char* className = "L@ohos/abilityAccessCtrl/abilityAccessCtrl/AtManagerInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not found %{public}s", className);
        return ANI_ERROR;
    }
    std::array claMethods = {
        ani_native_function {
            "checkAccessTokenExecute", "ILstd/core/String;:I", reinterpret_cast<void*>(CheckAccessTokenSync) },
        ani_native_function { "requestPermissionsFromUserExecute",
            "Lapplication/Context/Context;Lescompat/Array;:Lsecurity/PermissionRequestResult/PermissionRequestResult;",
            reinterpret_cast<void*>(RequestPermissionsFromUserExecute) },
        ani_native_function { "requestPermissionOnSettingExecute",
            "Lapplication/Context/Context;Lescompat/Array;:Lescompat/Array;",
            reinterpret_cast<void*>(RequestPermissionOnSettingExecute) },
        ani_native_function { "grantUserGrantedPermissionExecute", nullptr,
            reinterpret_cast<void*>(GrantUserGrantedPermissionExecute) },
        ani_native_function { "revokeUserGrantedPermissionExecute",
            nullptr, reinterpret_cast<void*>(RevokeUserGrantedPermissionExecute) },
        ani_native_function { "getVersionExecute", nullptr, reinterpret_cast<void*>(GetVersionExecute) },
        ani_native_function { "getPermissionsStatusExecute",
            nullptr, reinterpret_cast<void*>(GetPermissionsStatusExecute) },
        ani_native_function{ "getPermissionFlagsExecute",
            nullptr, reinterpret_cast<void *>(GetPermissionFlagsExecute) },
        ani_native_function{ "setPermissionRequestToggleStatusExecute",
            nullptr, reinterpret_cast<void *>(SetPermissionRequestToggleStatusExecute) },
        ani_native_function{ "getPermissionRequestToggleStatusExecute",
            nullptr, reinterpret_cast<void *>(GetPermissionRequestToggleStatusExecute) },
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