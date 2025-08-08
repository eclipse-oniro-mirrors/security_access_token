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

#include "ani_ability_access_ctrl.h"

#include <iostream>
#include <map>
#include <mutex>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_kit.h"
#include "ani_request_global_switch_on_setting.h"
#include "ani_request_permission.h"
#include "ani_request_permission_on_setting.h"
#include "hisysevent.h"
#include "parameter.h"
#include "permission_list_state.h"
#include "permission_map.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t VALUE_MAX_LEN = 32;
std::mutex g_lockCache;
static PermissionParamCache g_paramCache;
std::map<std::string, PermissionStatusCache> g_cache;
static constexpr const char* PERMISSION_STATUS_CHANGE_KEY = "accesstoken.permission.change";
}
constexpr const char* PERM_STATE_CHANGE_FIELD_TOKEN_ID = "tokenID";
constexpr const char* PERM_STATE_CHANGE_FIELD_PERMISSION_NAME = "permissionName";
constexpr const char* PERM_STATE_CHANGE_FIELD_CHANGE = "change";
std::mutex g_lockForPermStateChangeRegisters;
std::vector<RegisterPermStateChangeInf*> g_permStateChangeRegisters;
static const char* REGISTER_PERMISSION_STATE_CHANGE_TYPE = "permissionStateChange";
static const char* REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE = "selfPermissionStateChange";

RegisterPermStateChangeScopePtr::RegisterPermStateChangeScopePtr(const PermStateChangeScope& subscribeInfo)
    : PermStateChangeCallbackCustomize(subscribeInfo)
{}

RegisterPermStateChangeScopePtr::~RegisterPermStateChangeScopePtr()
{
    if (vm_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Vm is null.");
        return;
    }
    bool isSameThread = (threadId_ == std::this_thread::get_id());
    ani_env* env = isSameThread ? env_ : GetCurrentEnv(vm_);
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Current env is null.");
    } else if (ref_ != nullptr) {
        env->GlobalReference_Delete(ref_);
    }
    ref_ = nullptr;

    if (!isSameThread) {
        vm_->DetachCurrentThread();
    }
}

void RegisterPermStateChangeScopePtr::SetEnv(ani_env* env)
{
    env_ = env;
}

void RegisterPermStateChangeScopePtr::SetCallbackRef(const ani_ref& ref)
{
    ref_ = ref;
}

void RegisterPermStateChangeScopePtr::SetValid(bool valid)
{
    std::lock_guard<std::mutex> lock(validMutex_);
    valid_ = valid;
}

void RegisterPermStateChangeScopePtr::SetVm(ani_vm* vm)
{
    vm_ = vm;
}

void RegisterPermStateChangeScopePtr::SetThreadId(const std::thread::id threadId)
{
    threadId_ = threadId;
}

static bool SetStringProperty(ani_env* env, ani_object& aniObject, const char* propertyName, const std::string in)
{
    ani_string aniString = CreateAniString(env, in);
    if (env->Object_SetPropertyByName_Ref(aniObject, propertyName, aniString) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Object_SetPropertyByName_Ref!");
        return false;
    }

    return true;
}

static void transPermStateChangeTypeToAniInt(const int32_t permStateChangeType, ani_size& index)
{
    index = static_cast<ani_size>(permStateChangeType);
    return;
}

static void ConvertPermStateChangeInfo(ani_env* env, const PermStateChangeInfo& result, ani_object& aniObject)
{
    // class implements from interface should use property, independent class use field
    aniObject = CreateClassObject(env, "@ohos.abilityAccessCtrl.abilityAccessCtrl.PermissionStateChangeInfoInner");
    if (aniObject == nullptr) {
        return;
    }

    // set tokenId: int32_t
    SetIntProperty(env, aniObject, PERM_STATE_CHANGE_FIELD_TOKEN_ID, static_cast<int32_t>(result.tokenID));

    // set permissionName: Permissions
    SetStringProperty(env, aniObject, PERM_STATE_CHANGE_FIELD_PERMISSION_NAME, result.permissionName);

    // set permStateChangeType: int32_t
    ani_size index;
    transPermStateChangeTypeToAniInt(result.permStateChangeType, index);
    const char* activeStatusDes = "@ohos.abilityAccessCtrl.abilityAccessCtrl.PermissionStateChangeType";
    SetEnumProperty(
        env, aniObject, activeStatusDes, PERM_STATE_CHANGE_FIELD_CHANGE, static_cast<int32_t>(index));
}

void RegisterPermStateChangeScopePtr::PermStateChangeCallback(PermStateChangeInfo& PermStateChangeInfo)
{
    if (vm_ == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Vm is null.");
        return;
    }

    ani_option interopEnabled {"--interop=disable", nullptr};
    ani_options aniArgs {1, &interopEnabled};
    ani_env* env;
    if (vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to AttachCurrentThread!");
        return;
    }
    ani_fn_object fnObj = reinterpret_cast<ani_fn_object>(ref_);
    if (fnObj == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Reinterpret_cast!");
        return;
    }

    ani_object aniObject;
    ConvertPermStateChangeInfo(env, PermStateChangeInfo, aniObject);

    std::vector<ani_ref> args;
    args.emplace_back(aniObject);
    ani_ref result;
    if (!AniFunctionalObjectCall(env, fnObj, args.size(), args.data(), result)) {
        return;
    }
    if (vm_->DetachCurrentThread() != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to DetachCurrentThread!");
        return;
    }
}

static ani_object CreateAtManager([[maybe_unused]] ani_env* env)
{
    ani_object atManagerObj = {};
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null");
        return atManagerObj;
    }

    static const char* className = "@ohos.abilityAccessCtrl.abilityAccessCtrl.AtManagerInner";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Not found %{public}s.", className);
        return atManagerObj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get ctor %{public}s.", className);
        return atManagerObj;
    }

    if (ANI_OK != env->Object_New(cls, ctor, &atManagerObj)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create Object %{public}s.", className);
        return atManagerObj;
    }
    return atManagerObj;
}

static std::string GetPermParamValue()
{
    long long sysCommitId = GetSystemCommitId();
    if (sysCommitId == g_paramCache.sysCommitIdCache) {
        LOGD(ATM_DOMAIN, ATM_TAG, "SysCommitId = %{public}lld.", sysCommitId);
        return g_paramCache.sysParamCache;
    }
    g_paramCache.sysCommitIdCache = sysCommitId;
    if (g_paramCache.handle == PARAM_DEFAULT_VALUE) {
        int32_t handle = static_cast<int32_t>(FindParameter(PERMISSION_STATUS_CHANGE_KEY));
        if (handle == PARAM_DEFAULT_VALUE) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindParameter.");
            return "-1";
        }
        g_paramCache.handle = handle;
    }

    int32_t currCommitId = static_cast<int32_t>(GetParameterCommitId(g_paramCache.handle));
    if (currCommitId != g_paramCache.commitIdCache) {
        char value[VALUE_MAX_LEN] = { 0 };
        auto ret = GetParameterValue(g_paramCache.handle, value, VALUE_MAX_LEN - 1);
        if (ret < 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Return default value, ret=%{public}d.", ret);
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
            LOGD(ATM_DOMAIN, ATM_TAG, "Param changed currPara %{public}s.", currPara.c_str());
        } else {
            asyncContext->grantStatus = iter->second.status;
        }
    } else {
        asyncContext->grantStatus =
            AccessToken::AccessTokenKit::VerifyAccessToken(asyncContext->tokenId, asyncContext->permissionName);
        g_cache[asyncContext->permissionName].status = asyncContext->grantStatus;
        g_cache[asyncContext->permissionName].paramValue = GetPermParamValue();
        LOGD(ATM_DOMAIN, ATM_TAG, "Success to set G_cacheParam(%{public}s).",
            g_cache[asyncContext->permissionName].paramValue.c_str());
    }
}

static ani_int CheckAccessTokenExecute([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_int aniTokenID, ani_string aniPermission)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return AccessToken::PermissionState::PERMISSION_DENIED;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    std::string permissionName = ParseAniString(env, static_cast<ani_string>(aniPermission));
    if ((!BusinessErrorAni::ValidateTokenIDdWithThrowError(env, tokenID)) ||
        (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId(%{public}u) or Permission(%{public}s) is invalid.",
            tokenID, permissionName.c_str());
        return AccessToken::PermissionState::PERMISSION_DENIED;
    }

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext();
    if (asyncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to alloc memory for asyncContext.");
        return AccessToken::PermissionState::PERMISSION_DENIED;
    }
    std::unique_ptr<AtManagerAsyncContext> context {asyncContext};
    asyncContext->tokenId = static_cast<AccessTokenID>(tokenID);
    asyncContext->permissionName = permissionName;
    static uint64_t selfTokenId = GetSelfTokenID();
    if (asyncContext->tokenId != static_cast<AccessTokenID>(selfTokenId)) {
        asyncContext->grantStatus = AccessToken::AccessTokenKit::VerifyAccessToken(tokenID, permissionName);
        return static_cast<ani_int>(asyncContext->grantStatus);
    }
    UpdatePermissionCache(asyncContext);
    LOGI(ATM_DOMAIN, ATM_TAG, "CheckAccessTokenExecute result : %{public}d.", asyncContext->grantStatus);
    return static_cast<ani_int>(asyncContext->grantStatus);
}

static void GrantUserGrantedPermissionExecute([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_int aniTokenID, ani_string aniPermission, ani_int aniFlags)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    std::string permissionName = ParseAniString(env, static_cast<ani_string>(aniPermission));
    uint32_t permissionFlags = static_cast<uint32_t>(aniFlags);
    if ((!BusinessErrorAni::ValidateTokenIDdWithThrowError(env, tokenID)) ||
        (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName)) ||
        (!BusinessErrorAni::ValidatePermissionFlagWithThrowError(env, permissionFlags))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId(%{public}u) or Permission(%{public}s)  or flags(%{public}u)is invalid.",
            tokenID, permissionName.c_str(), permissionFlags);
        return;
    }

    PermissionBriefDef def;
    if (!GetPermissionBriefDef(permissionName, def) || def.grantMode != USER_GRANT) {
        std::string errMsg = GetErrorMessage(STS_ERROR_PERMISSION_NOT_EXIST,
            "The specified permission does not exist or is not a user_grant permission.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_PERMISSION_NOT_EXIST, errMsg);
        return;
    }

    int32_t res = AccessTokenKit::GrantPermission(tokenID, permissionName, permissionFlags);
    if (res != RET_SUCCESS) {
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(res);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
    }
}

static void RevokeUserGrantedPermissionExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_int aniTokenID, ani_string aniPermission, ani_int aniFlags)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RevokeUserGrantedPermission begin.");
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    std::string permissionName = ParseAniString(env, static_cast<ani_string>(aniPermission));
    uint32_t permissionFlags = static_cast<uint32_t>(aniFlags);
    if ((!BusinessErrorAni::ValidateTokenIDdWithThrowError(env, tokenID)) ||
        (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName)) ||
        (!BusinessErrorAni::ValidatePermissionFlagWithThrowError(env, permissionFlags))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId(%{public}u) or Permission(%{public}s)  or flags(%{public}u)is invalid.",
            tokenID, permissionName.c_str(), permissionFlags);
        return;
    }

    PermissionBriefDef def;
    if (!GetPermissionBriefDef(permissionName, def) || def.grantMode != USER_GRANT) {
        std::string errMsg = GetErrorMessage(STS_ERROR_PERMISSION_NOT_EXIST,
            "The specified permission does not exist or is not a user_grant permission.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_PERMISSION_NOT_EXIST, errMsg);
        return;
    }

    int32_t ret = AccessTokenKit::RevokePermission(tokenID, permissionName, permissionFlags);
    if (ret != RET_SUCCESS) {
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(ret);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
    }
}

static ani_int GetVersionExecute([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetVersionExecute begin.");
    uint32_t version = -1;
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
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
    [[maybe_unused]] ani_object object, ani_int aniTokenID, ani_array_ref aniPermissionList)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionsStatusExecute begin.");
    if ((env == nullptr) || (aniPermissionList == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AniPermissionList or env is null.");
        return nullptr;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    if (!BusinessErrorAni::ValidateTokenIDdWithThrowError(env, tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId(%{public}u) is invalid.", tokenID);
        return nullptr;
    }
    std::vector<std::string> permissionList = ParseAniStringVector(env, aniPermissionList);
    if (permissionList.empty()) {
        BusinessErrorAni::ThrowError(
            env, STS_ERROR_INNER,  GetErrorMessage(STS_ERROR_INNER, "The permissionList is empty."));
        return nullptr;
    }

    std::vector<PermissionListState> permList;
    for (const auto& permission : permissionList) {
        PermissionListState permState;
        permState.permissionName = permission;
        permState.state = INVALID_OPER;
        permList.emplace_back(permState);
    }

    int32_t result = RET_SUCCESS;
    result = AccessTokenKit::GetPermissionsStatus(tokenID, permList);
    if (result != RET_SUCCESS) {
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(result);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
        return nullptr;
    }
    std::vector<int32_t> permissionQueryResults;
    for (const auto& permState : permList) {
        permissionQueryResults.emplace_back(permState.state);
    }

    return CreateAniArrayInt(env, permissionQueryResults);
}

static ani_int GetPermissionFlagsExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_int aniTokenID, ani_string aniPermissionName)
{
    uint32_t flag = PERMISSION_DEFAULT_FLAG;
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return flag;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    std::string permissionName = ParseAniString(env, static_cast<ani_string>(aniPermissionName));
    if ((!BusinessErrorAni::ValidateTokenIDdWithThrowError(env, tokenID)) ||
        (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId(%{public}u) or Permission(%{public}s) is invalid.",
            tokenID, permissionName.c_str());
        return flag;
    }

    int32_t result = AccessTokenKit::GetPermissionFlag(tokenID, permissionName, flag);
    if (result != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Result = %{public}d  errcode = %{public}d",
            result, BusinessErrorAni::GetStsErrorCode(result));
        BusinessErrorAni::ThrowError(
            env, BusinessErrorAni::GetStsErrorCode(result), GetErrorMessage(BusinessErrorAni::GetStsErrorCode(result)));
    }
    return flag;
}

static void SetPermissionRequestToggleStatusExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_string aniPermissionName, ani_int status)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return;
    }
    std::string permissionName = ParseAniString(env, static_cast<ani_string>(aniPermissionName));
    if (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid Permission(%{public}s).", permissionName.c_str());
        return;
    }
    int32_t result = AccessTokenKit::SetPermissionRequestToggleStatus(permissionName, status, 0);
    if (result != RET_SUCCESS) {
        BusinessErrorAni::ThrowError(
            env, BusinessErrorAni::GetStsErrorCode(result), GetErrorMessage(BusinessErrorAni::GetStsErrorCode(result)));
    }
    return;
}

static ani_int GetPermissionRequestToggleStatusExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_string aniPermissionName)
{
    uint32_t flag = CLOSED;
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return flag;
    }
    std::string permissionName = ParseAniString(env, static_cast<ani_string>(aniPermissionName));
    if (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid Permission(%{public}s).", permissionName.c_str());
        return flag;
    }

    int32_t result = AccessTokenKit::GetPermissionRequestToggleStatus(permissionName, flag, 0);
    if (result != RET_SUCCESS) {
        BusinessErrorAni::ThrowError(
            env, BusinessErrorAni::GetStsErrorCode(result), GetErrorMessage(BusinessErrorAni::GetStsErrorCode(result)));
    }
    return flag;
}

static void RequestAppPermOnSettingExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_int tokenID)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return;
    }

    int32_t result = AccessTokenKit::RequestAppPermOnSetting(static_cast<AccessTokenID>(tokenID));
    if (result != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Result=%{public}d, errcode=%{public}d.",
            result, BusinessErrorAni::GetStsErrorCode(result));
        BusinessErrorAni::ThrowError(env, BusinessErrorAni::GetStsErrorCode(result),
            GetErrorMessage(BusinessErrorAni::GetStsErrorCode(result)));
    }
}

static bool SetupPermissionSubscriber(
    RegisterPermStateChangeInf* context, const PermStateChangeScope& scopeInfo, const ani_ref& callback)
{
    ani_vm* vm;
    if (context->env->GetVM(&vm) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetVM!");
        return false;
    }

    auto sortedTokenIDs = scopeInfo.tokenIDs;
    auto sortedPermList = scopeInfo.permList;
    std::sort(sortedTokenIDs.begin(), sortedTokenIDs.end());
    std::sort(sortedPermList.begin(), sortedPermList.end());

    context->callbackRef = callback;
    context->scopeInfo.tokenIDs = sortedTokenIDs;
    context->scopeInfo.permList = sortedPermList;
    context->subscriber = std::make_shared<RegisterPermStateChangeScopePtr>(scopeInfo);
    context->subscriber->SetVm(vm);
    context->subscriber->SetEnv(context->env);
    context->subscriber->SetCallbackRef(callback);

    return true;
}

static bool ParseInputToRegister(const ani_string& aniType, const ani_array_ref& aniId, const ani_array_ref& aniArray,
    const ani_ref& aniCallback, RegisterPermStateChangeInf* context, bool isReg)
{
    std::string type = ParseAniString(context->env, aniType);
    if (type.empty()) {
        BusinessErrorAni::ThrowError(context->env, STS_ERROR_PARAM_INVALID, GetParamErrorMsg(
            "type", "permissionStateChange or selfPermissionStateChange"));
        return false;
    }
    if ((type != REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) && (type != REGISTER_PERMISSION_STATE_CHANGE_TYPE)) {
        BusinessErrorAni::ThrowError(
            context->env, STS_ERROR_PARAM_INVALID, GetParamErrorMsg("type", "type is invalid"));
        return false;
    }

    context->permStateChangeType = type;
    context->threadId = std::this_thread::get_id();

    PermStateChangeScope scopeInfo;
    std::string errMsg;
    if (type == REGISTER_PERMISSION_STATE_CHANGE_TYPE) {
        if (!AniParseAccessTokenIDArray(context->env, aniId, scopeInfo.tokenIDs)) {
            BusinessErrorAni::ThrowError(
                context->env, STS_ERROR_PARAM_INVALID, GetParamErrorMsg("tokenIDList", "Array<int>"));
            return false;
        }
    } else if (type == REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) {
        scopeInfo.tokenIDs = {GetSelfTokenID()};
    }
    scopeInfo.permList = ParseAniStringVector(context->env, aniArray);
    bool hasCallback = true;
    if (!isReg) {
        hasCallback = !(AniIsRefUndefined(context->env, aniCallback));
    }

    ani_ref callback = nullptr;
    if (hasCallback) {
        if (!AniParseCallback(context->env, aniCallback, callback)) {
            BusinessErrorAni::ThrowError(context->env, STS_ERROR_PARAM_ILLEGAL, GetParamErrorMsg(
                "callback", "Callback<PermissionStateChangeInfo>"));
            return false;
        }
    }

    return SetupPermissionSubscriber(context, scopeInfo, callback);
}

static bool IsExistRegister(const RegisterPermStateChangeInf* context)
{
    PermStateChangeScope targetScopeInfo;
    context->subscriber->GetScope(targetScopeInfo);
    std::vector<AccessTokenID> targetTokenIDs = targetScopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = targetScopeInfo.permList;
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);

    for (const auto& item : g_permStateChangeRegisters) {
        PermStateChangeScope scopeInfo;
        item->subscriber->GetScope(scopeInfo);

        bool hasPermIntersection = false;
        // Special cases:
        // 1.Have registered full, and then register some
        // 2.Have registered some, then register full
        if (scopeInfo.permList.empty() || targetPermList.empty()) {
            hasPermIntersection = true;
        }
        for (const auto& PermItem : targetPermList) {
            if (hasPermIntersection) {
                break;
            }
            auto iter = std::find(scopeInfo.permList.begin(), scopeInfo.permList.end(), PermItem);
            if (iter != scopeInfo.permList.end()) {
                hasPermIntersection = true;
            }
        }

        bool hasTokenIdIntersection = false;

        if (scopeInfo.tokenIDs.empty() || targetTokenIDs.empty()) {
            hasTokenIdIntersection = true;
        }
        for (const auto& tokenItem : targetTokenIDs) {
            if (hasTokenIdIntersection) {
                break;
            }
            auto iter = std::find(scopeInfo.tokenIDs.begin(), scopeInfo.tokenIDs.end(), tokenItem);
            if (iter != scopeInfo.tokenIDs.end()) {
                hasTokenIdIntersection = true;
            }
        }
        bool isEqual = true;
        if (!AniIsCallbackRefEqual(context->env, item->callbackRef, context->callbackRef, item->threadId, isEqual)) {
            return true;
        }
        if (hasPermIntersection && hasTokenIdIntersection && isEqual) {
            return true;
        }
    }
    return false;
}

static void RegisterPermStateChangeCallback([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_string aniType, ani_array_ref aniId, ani_array_ref aniArray, ani_ref callback)
{
    if (env == nullptr) {
        BusinessErrorAni::ThrowError(env, STS_ERROR_INNER, GetErrorMessage(STSErrorCode::STS_ERROR_INNER));
        return;
    }

    RegisterPermStateChangeInf* registerPermStateChangeInf = new (std::nothrow) RegisterPermStateChangeInf();
    if (registerPermStateChangeInf == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to allocate memory for RegisterPermStateChangeInf!");
        return;
    }
    registerPermStateChangeInf->env = env;
    std::unique_ptr<RegisterPermStateChangeInf> callbackPtr {registerPermStateChangeInf};
    if (!ParseInputToRegister(aniType, aniId, aniArray, callback, registerPermStateChangeInf, true)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to ParseInputToRegister.");
        return;
    }

    if (IsExistRegister(registerPermStateChangeInf)) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Faield to Subscribe. The current subscriber has existed or Reference_StrictEquals failed!");
        if (registerPermStateChangeInf->permStateChangeType == REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) {
            BusinessErrorAni::ThrowError(
                env, STSErrorCode::STS_ERROR_NOT_USE_TOGETHER,
                GetErrorMessage(STSErrorCode::STS_ERROR_NOT_USE_TOGETHER));
        } else {
            BusinessErrorAni::ThrowError(
                env, STSErrorCode::STS_ERROR_PARAM_INVALID, GetErrorMessage(STSErrorCode::STS_ERROR_PARAM_INVALID));
        }
        return;
    }

    int32_t result;
    if (registerPermStateChangeInf->permStateChangeType == REGISTER_PERMISSION_STATE_CHANGE_TYPE) {
        result = AccessTokenKit::RegisterPermStateChangeCallback(registerPermStateChangeInf->subscriber);
    } else {
        result = AccessTokenKit::RegisterSelfPermStateChangeCallback(registerPermStateChangeInf->subscriber);
    }
    if (result != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to RegisterPermStateChangeCallback.");
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(result);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
        g_permStateChangeRegisters.emplace_back(registerPermStateChangeInf);
        LOGI(ATM_DOMAIN, ATM_TAG,
            "g_PermStateChangeRegisters size = %{public}zu.", g_permStateChangeRegisters.size());
    }
    callbackPtr.release();
    return;
}

static bool FindAndGetSubscriberInVector(RegisterPermStateChangeInf* unregisterPermStateChangeInf,
    std::vector<RegisterPermStateChangeInf*>& batchPermStateChangeRegisters)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "FindAndGetSubscriberInVector In.");
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    std::vector<AccessTokenID> targetTokenIDs = unregisterPermStateChangeInf->scopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = unregisterPermStateChangeInf->scopeInfo.permList;
    bool callbackEqual;
    ani_ref callbackRef = unregisterPermStateChangeInf->callbackRef;
    bool isUndef = AniIsRefUndefined(unregisterPermStateChangeInf->env, unregisterPermStateChangeInf->callbackRef);

    for (const auto& item : g_permStateChangeRegisters) {
        if (isUndef) {
            // batch delete currentThread callback
            LOGI(ATM_DOMAIN, ATM_TAG, "Callback is null.");
            callbackEqual = IsCurrentThread(item->threadId);
        } else {
            LOGI(ATM_DOMAIN, ATM_TAG, "Compare callback.");
            if (!AniIsCallbackRefEqual(unregisterPermStateChangeInf->env, callbackRef,
                unregisterPermStateChangeInf->callbackRef, item->threadId, callbackEqual)) {
                continue;
            }
        }

        PermStateChangeScope scopeInfo;
        item->subscriber->GetScope(scopeInfo);
        if (scopeInfo.tokenIDs == targetTokenIDs && scopeInfo.permList == targetPermList) {
            unregisterPermStateChangeInf->subscriber = item->subscriber;
            batchPermStateChangeRegisters.emplace_back(item);
        }
    }
    if (!batchPermStateChangeRegisters.empty()) {
        return true;
    }
    return false;
}

static void DeleteRegisterFromVector(const RegisterPermStateChangeInf* context)
{
    std::vector<AccessTokenID> targetTokenIDs = context->scopeInfo.tokenIDs;
    std::vector<std::string> targetPermList = context->scopeInfo.permList;
    std::lock_guard<std::mutex> lock(g_lockForPermStateChangeRegisters);
    auto item = g_permStateChangeRegisters.begin();
    while (item != g_permStateChangeRegisters.end()) {
        PermStateChangeScope stateChangeScope;
        (*item)->subscriber->GetScope(stateChangeScope);
        bool callbackEqual = true;
        if (!AniIsCallbackRefEqual(
            context->env, (*item)->callbackRef, context->callbackRef, (*item)->threadId, callbackEqual)) {
            continue;
        }
        if (!callbackEqual) {
            continue;
        }

        if ((stateChangeScope.tokenIDs == targetTokenIDs) && (stateChangeScope.permList == targetPermList)) {
            delete *item;
            *item = nullptr;
            g_permStateChangeRegisters.erase(item);
            break;
        } else {
            ++item;
        }
    }
}

static void UnregisterPermStateChangeCallback([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_string aniType, ani_array_ref aniId, ani_array_ref aniArray, ani_ref callback)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "UnregisterPermStateChangeCallback In.");
    if (env == nullptr) {
        BusinessErrorAni::ThrowError(env, STS_ERROR_INNER, GetErrorMessage(STSErrorCode::STS_ERROR_INNER));
        return;
    }

    RegisterPermStateChangeInf* context = new (std::nothrow) RegisterPermStateChangeInf();
    if (context == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to allocate memory for UnRegisterPermStateChangeInf!");
        return;
    }
    context->env = env;
    std::unique_ptr<RegisterPermStateChangeInf> callbackPtr {context};

    if (!ParseInputToRegister(aniType, aniId, aniArray, callback, context, false)) {
        return;
    }

    std::vector<RegisterPermStateChangeInf*> batchPermStateChangeRegisters;
    if (!FindAndGetSubscriberInVector(context, batchPermStateChangeRegisters)) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Failed to Unsubscribe. The current subscriber does not exist or Reference_StrictEquals failed!");
        if (context->permStateChangeType == REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) {
            BusinessErrorAni::ThrowError(
                env, STSErrorCode::STS_ERROR_NOT_USE_TOGETHER,
                GetErrorMessage(STSErrorCode::STS_ERROR_NOT_USE_TOGETHER));
        } else {
            BusinessErrorAni::ThrowError(
                env, STSErrorCode::STS_ERROR_PARAM_INVALID, GetErrorMessage(STSErrorCode::STS_ERROR_PARAM_INVALID));
        }
        return;
    }
    for (const auto& item : batchPermStateChangeRegisters) {
        PermStateChangeScope scopeInfo;
        item->subscriber->GetScope(scopeInfo);
        int32_t result;
        if (context->permStateChangeType == REGISTER_PERMISSION_STATE_CHANGE_TYPE) {
            result = AccessTokenKit::UnRegisterPermStateChangeCallback(item->subscriber);
        } else {
            result = AccessTokenKit::UnRegisterSelfPermStateChangeCallback(item->subscriber);
        }
        if (result == RET_SUCCESS) {
            DeleteRegisterFromVector(item);
        } else {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to UnregisterPermStateChangeCallback");
            int32_t stsCode = BusinessErrorAni::GetStsErrorCode(result);
            BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
            return;
        }
    }
    return;
}

void InitAbilityCtrlFunction(ani_env *env)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return;
    }
    const char* spaceName = "@ohos.abilityAccessCtrl.abilityAccessCtrl";
    ani_namespace spc;
    if (ANI_OK != env->FindNamespace(spaceName, &spc)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Not found %{public}s.", spaceName);
        return;
    }
    std::array methods = {
        ani_native_function { "createAtManager", nullptr, reinterpret_cast<void*>(CreateAtManager) },
    };
    if (ANI_OK != env->Namespace_BindNativeFunctions(spc, methods.data(), methods.size())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Cannot bind native methods to %{public}s.", spaceName);
        return;
    };
    const char* className = "@ohos.abilityAccessCtrl.abilityAccessCtrl.AtManagerInner";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Not found %{public}s.", className);
        return;
    }
    std::array claMethods = {
        ani_native_function { "checkAccessTokenExecute", nullptr, reinterpret_cast<void*>(CheckAccessTokenExecute) },
        ani_native_function { "requestPermissionsFromUserExecute",
            nullptr, reinterpret_cast<void*>(RequestPermissionsFromUserExecute) },
        ani_native_function { "requestPermissionOnSettingExecute",
            nullptr, reinterpret_cast<void*>(RequestPermissionOnSettingExecute) },
        ani_native_function {"requestGlobalSwitchExecute",
            nullptr, reinterpret_cast<void*>(RequestGlobalSwitchExecute) },
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
        ani_native_function{ "requestAppPermOnSettingExecute",
            nullptr, reinterpret_cast<void *>(RequestAppPermOnSettingExecute) },
        ani_native_function { "onExcute", nullptr, reinterpret_cast<void*>(RegisterPermStateChangeCallback) },
        ani_native_function { "offExcute", nullptr, reinterpret_cast<void*>(UnregisterPermStateChangeCallback) },
    };
    if (ANI_OK != env->Class_BindNativeMethods(cls, claMethods.data(), claMethods.size())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Cannot bind native methods to %{public}s", className);
        return;
    };
}
extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    if (vm == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Vm is null.");
        return ANI_INVALID_ARGS;
    }
    ani_env* env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Unsupported ANI_VERSION_1.");
        return ANI_OUT_OF_MEMORY;
    }
    InitAbilityCtrlFunction(env);
    *result = ANI_VERSION_1;
    return ANI_OK;
}
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
