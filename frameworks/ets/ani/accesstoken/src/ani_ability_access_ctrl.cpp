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
#include "accesstoken_kit.h"
#include "accesstoken_log.h"
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
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AniAbilityAccessCtrl" };
constexpr int32_t VALUE_MAX_LEN = 32;
std::mutex g_lockCache;
static PermissionParamCache g_paramCache;
std::map<std::string, PermissionStatusCache> g_cache;
static constexpr const char* PERMISSION_STATUS_CHANGE_KEY = "accesstoken.permission.change";
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
        char value[VALUE_MAX_LEN] = { 0 };
        auto ret = GetParameterValue(g_paramCache.handle, value, VALUE_MAX_LEN - 1);
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

static ani_int CheckAccessTokenExecute([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_int aniTokenID, ani_string aniPermission)
{
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr env");
        return AccessToken::PermissionState::PERMISSION_DENIED;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    std::string permissionName = ParseAniString(env, static_cast<ani_string>(aniPermission));
    if ((!BusinessErrorAni::ValidateTokenIDdWithThrowError(env, tokenID)) ||
        (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenId(%{public}u) or Permission(%{public}s) is invalid.",
            tokenID, permissionName.c_str());
        return AccessToken::PermissionState::PERMISSION_DENIED;
    }

    auto* asyncContext = new (std::nothrow) AtManagerAsyncContext();
    if (asyncContext == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "New struct fail.");
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
    ACCESSTOKEN_LOG_INFO(LABEL, "CheckAccessTokenExecute result : %{public}d", asyncContext->grantStatus);
    return static_cast<ani_int>(asyncContext->grantStatus);
}

static void GrantUserGrantedPermissionExecute([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_int aniTokenID, ani_string aniPermission, ani_int aniFlags)
{
    if (env == nullptr) {
        return;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    std::string permissionName = ParseAniString(env, static_cast<ani_string>(aniPermission));
    uint32_t permissionFlags = static_cast<uint32_t>(aniFlags);
    if ((!BusinessErrorAni::ValidateTokenIDdWithThrowError(env, tokenID)) ||
        (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName)) ||
        (!BusinessErrorAni::ValidatePermissionFlagWithThrowError(env, permissionFlags))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenId(%{public}u) or Permission(%{public}s)  or flags(%{public}u)is invalid.",
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
    ACCESSTOKEN_LOG_INFO(LABEL, "RevokeUserGrantedPermission begin.");
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "env null.");
        return;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    std::string permissionName = ParseAniString(env, static_cast<ani_string>(aniPermission));
    uint32_t permissionFlags = static_cast<uint32_t>(aniFlags);
    if ((!BusinessErrorAni::ValidateTokenIDdWithThrowError(env, tokenID)) ||
        (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName)) ||
        (!BusinessErrorAni::ValidatePermissionFlagWithThrowError(env, permissionFlags))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenId(%{public}u) or Permission(%{public}s)  or flags(%{public}u)is invalid.",
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
    [[maybe_unused]] ani_object object, ani_int aniTokenID, ani_array_ref aniPermissionList)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "GetPermissionsStatusExecute begin.");
    if ((env == nullptr) || (aniPermissionList == nullptr)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "aniPermissionList or env null.");
        return nullptr;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    if (!BusinessErrorAni::ValidateTokenIDdWithThrowError(env, tokenID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenId(%{public}u) is invalid.", tokenID);
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "Env is null");
        return flag;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    std::string permissionName = ParseAniString(env, static_cast<ani_string>(aniPermissionName));
    if ((!BusinessErrorAni::ValidateTokenIDdWithThrowError(env, tokenID)) ||
        (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenId(%{public}u) or Permission(%{public}s) is invalid.",
            tokenID, permissionName.c_str());
        return flag;
    }

    int32_t result = AccessTokenKit::GetPermissionFlag(tokenID, permissionName, flag);
    if (result != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "result =  %{public}d  errcode = %{public}d",
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "Env is null");
        return;
    }
    std::string permissionName = ParseAniString(env, static_cast<ani_string>(aniPermissionName));
    if (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission(%{public}s) is invalid.", permissionName.c_str());
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "Env is null");
        return flag;
    }
    std::string permissionName = ParseAniString(env, static_cast<ani_string>(aniPermissionName));
    if (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission(%{public}s) is invalid.", permissionName.c_str());
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "Env is null.");
        return;
    }

    int32_t result = AccessTokenKit::RequestAppPermOnSetting(static_cast<AccessTokenID>(tokenID));
    if (result != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Result = %{public}d, errcode = %{public}d.",
            result, BusinessErrorAni::GetStsErrorCode(result));
        BusinessErrorAni::ThrowError(env, BusinessErrorAni::GetStsErrorCode(result),
            GetErrorMessage(BusinessErrorAni::GetStsErrorCode(result)));
    }
}

void InitAbilityCtrlFunction(ani_env *env)
{
    if (env == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "nullptr env");
        return;
    }
    const char* spaceName = "L@ohos/abilityAccessCtrl/abilityAccessCtrl;";
    ani_namespace spc;
    if (ANI_OK != env->FindNamespace(spaceName, &spc)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not found %{public}s", spaceName);
        return;
    }
    std::array methods = {
        ani_native_function { "createAtManager", nullptr, reinterpret_cast<void*>(CreateAtManager) },
    };
    if (ANI_OK != env->Namespace_BindNativeFunctions(spc, methods.data(), methods.size())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Cannot bind native methods to %{public}s", spaceName);
        return;
    };
    const char* className = "L@ohos/abilityAccessCtrl/abilityAccessCtrl/AtManagerInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not found %{public}s", className);
        return;
    }
    std::array claMethods = {
        ani_native_function { "checkAccessTokenExecute", nullptr, reinterpret_cast<void*>(CheckAccessTokenExecute) },
        ani_native_function { "requestPermissionsFromUserExecute",
            nullptr, reinterpret_cast<void*>(RequestPermissionsFromUserExecute) },
        ani_native_function { "requestPermissionOnSettingExecute",
            nullptr, reinterpret_cast<void*>(RequestPermissionOnSettingExecute) },
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
    };
    if (ANI_OK != env->Class_BindNativeMethods(cls, claMethods.data(), claMethods.size())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Cannot bind native methods to %{public}s", className);
        return;
    };
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
    InitAbilityCtrlFunction(env);
    *result = ANI_VERSION_1;
    return ANI_OK;
}
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS