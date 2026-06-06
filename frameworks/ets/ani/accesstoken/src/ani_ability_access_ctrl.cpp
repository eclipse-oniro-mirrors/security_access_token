/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "accesstoken_common_log.h"
#include "ani_hisysevent_adapter.h"
#include "ani_open_permission_on_setting.h"
#include "ani_request_global_switch_on_setting.h"
#include "ani_request_permission.h"
#include "ani_request_permission_on_setting.h"
#include "claw_permission_info.h"
#include "data_validator.h"
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
std::map<std::string, GrantStatusCache> g_cache;
static constexpr const char* PERMISSION_STATUS_CHANGE_KEY = "accesstoken.permission.change";
std::mutex g_lockStatusCache;
static PermissionParamCache g_paramFlagCache;
std::map<std::string, PermStatusCache> g_statusCache;
static constexpr const char* PERMISSION_STATUS_FLAG_CHANGE_KEY = "accesstoken.permission.flagchange";

static std::atomic<int32_t> g_tokenIdOtherCount = 0;
constexpr uint32_t REPORT_TIMES_REDUCE_FACTOR = 10;
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
    ani_option interopOption {"--interop=disable", nullptr};
    ani_options aniArgs {1, &interopOption};
    ani_env* env = isSameThread ? env_ : GetCurrentEnv(vm_, aniArgs);
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Current env is null.");
    } else if (ref_ != nullptr) {
        ani_status status;
        if ((status = env->GlobalReference_Delete(ref_)) != ANI_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GlobalReference_Delete: %{public}u.", status);
        }
    }
    ref_ = nullptr;

    if (!isSameThread) {
        if (DetachCurrentEnv(vm_) != ANI_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to DetachCurrentEnv!");
        }
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

static bool SetStringProperty(ani_env* env, ani_object& aniObject, const char* propertyName, const std::string& in)
{
    ani_string aniString = CreateAniString(env, in);
    ani_status status;
    if ((status = env->Object_SetPropertyByName_Ref(aniObject, propertyName, aniString)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Object_SetPropertyByName_Ref: %{public}u.", status);
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

    ani_option interopOption {"--interop=disable", nullptr};
    ani_options aniArgs {1, &interopOption};
    ani_env* env = GetCurrentEnv(vm_, aniArgs);
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetCurrentEnv!");
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
    if (DetachCurrentEnv(vm_) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to DetachCurrentEnv!");
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
    ani_status status;
    if ((status = env->FindClass(className, &cls)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Not found %{public}s, status: %{public}u.", className, status);
        return atManagerObj;
    }

    ani_method ctor;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &ctor)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get ctor %{public}s, status: %{public}u.", className, status);
        return atManagerObj;
    }

    if ((status = env->Object_New(cls, ctor, &atManagerObj)) != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create Object %{public}s, status: %{public}u.", className, status);
        return atManagerObj;
    }
    return atManagerObj;
}

static std::string GetPermParamValue(PermissionParamCache& paramCache, const char* paramKey)
{
    long long sysCommitId = GetSystemCommitId();
    if (sysCommitId == paramCache.sysCommitIdCache) {
        LOGD(ATM_DOMAIN, ATM_TAG, "SysCommitId = %{public}lld.", sysCommitId);
        return paramCache.sysParamCache;
    }
    paramCache.sysCommitIdCache = sysCommitId;
    if (paramCache.handle == PARAM_DEFAULT_VALUE) {
        int32_t handle = static_cast<int32_t>(FindParameter(PERMISSION_STATUS_CHANGE_KEY));
        if (handle == PARAM_DEFAULT_VALUE) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to FindParameter.");
            return "-1";
        }
        paramCache.handle = handle;
    }

    int32_t currCommitId = static_cast<int32_t>(GetParameterCommitId(paramCache.handle));
    if (currCommitId != paramCache.commitIdCache) {
        char value[VALUE_MAX_LEN] = { 0 };
        auto ret = GetParameterValue(paramCache.handle, value, VALUE_MAX_LEN - 1);
        if (ret < 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Return default value, ret=%{public}d.", ret);
            return "-1";
        }
        std::string resStr(value);
        paramCache.sysParamCache = resStr;
        paramCache.commitIdCache = currCommitId;
    }
    return paramCache.sysParamCache;
}

static void UpdateGrantStatusCache(AtManagerAsyncContext* asyncContext)
{
    if (asyncContext == nullptr) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_lockCache);
    auto iter = g_cache.find(asyncContext->permissionName);
    if (iter != g_cache.end()) {
        std::string currPara = GetPermParamValue(g_paramCache, PERMISSION_STATUS_CHANGE_KEY);
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
        g_cache[asyncContext->permissionName].paramValue = GetPermParamValue(g_paramCache,
            PERMISSION_STATUS_CHANGE_KEY);
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
    std::string permissionName;
    (void)ParseAniString(env, static_cast<ani_string>(aniPermission), permissionName);
    if ((!BusinessErrorAni::ValidateTokenIDWithThrowError(env, tokenID)) ||
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
        int32_t cnt = g_tokenIdOtherCount.fetch_add(1);
        if (!AccessTokenKit::IsSystemAppByFullTokenID(selfTokenId) && cnt % REPORT_TIMES_REDUCE_FACTOR == 0) {
            AccessTokenID selfToken = static_cast<AccessTokenID>(selfTokenId);
            (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "VERIFY_ACCESS_TOKEN_EVENT",
                HiviewDFX::HiSysEvent::EventType::STATISTIC, "EVENT_CODE", VERIFY_TOKENID_INCONSISTENCY,
                "SELF_TOKENID", selfToken, "CONTEXT_TOKENID", asyncContext->tokenId);
        }
        asyncContext->grantStatus = AccessToken::AccessTokenKit::VerifyAccessToken(tokenID, permissionName);
        return static_cast<ani_int>(asyncContext->grantStatus);
    }
    UpdateGrantStatusCache(asyncContext);
    LOGI(ATM_DOMAIN, ATM_TAG, "CheckAccessTokenExecute result : %{public}d.", asyncContext->grantStatus);
    return static_cast<ani_int>(asyncContext->grantStatus);
}

static void GrantPermissionInner([[maybe_unused]] ani_env *env,
    ani_int aniTokenID, ani_string aniPermission, ani_int aniFlags, UpdatePermissionFlag updateFlag)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    std::string permissionName;
    (void)ParseAniString(env, static_cast<ani_string>(aniPermission), permissionName);
    uint32_t permissionFlags = static_cast<uint32_t>(aniFlags);
    LOGI(ATM_DOMAIN, ATM_TAG, "tokenID = %{public}d, permissionName = %{public}s, flag = %{public}d.",
        tokenID, permissionName.c_str(), permissionFlags);

    if ((!BusinessErrorAni::ValidateTokenIDWithThrowError(env, tokenID)) ||
        (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName)) ||
        (!BusinessErrorAni::ValidatePermissionFlagWithThrowError(env, permissionFlags))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId(%{public}u) or Permission(%{public}s) or flags(%{public}u)is invalid.",
            tokenID, permissionName.c_str(), permissionFlags);
        return;
    }

    PermissionBriefDef def;
    if (!GetPermissionBriefDef(permissionName, def)) {
        std::string errMsg = GetErrorMessage(STS_ERROR_PERMISSION_NOT_EXIST);
        BusinessErrorAni::ThrowError(env, STS_ERROR_PERMISSION_NOT_EXIST, errMsg);
        return;
    }

    if (updateFlag == USER_GRANTED_PERM && def.grantMode != USER_GRANT) {
        std::string errMsg = GetErrorMessage(STS_ERROR_PERMISSION_NOT_EXIST,
            "The specified permission is not a user_grant permission.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_PERMISSION_NOT_EXIST, errMsg);
        return;
    }

    if (updateFlag == OPERABLE_PERM && def.grantMode != USER_GRANT && def.grantMode != MANUAL_SETTINGS) {
        std::string errMsg = GetErrorMessage(STS_ERROR_EXPECTED_PERMISSION_TYPE,
            "The specified permission is not a user_grant or manual_settings permission.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_EXPECTED_PERMISSION_TYPE, errMsg);
        return;
    }

    int32_t res = AccessTokenKit::GrantPermission(tokenID, permissionName, permissionFlags, updateFlag);
    if (res != RET_SUCCESS) {
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(res);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
    }
}

static void RevokePermissionInner(ani_env *env,
    ani_int aniTokenID, ani_string aniPermission, ani_int aniFlags, UpdatePermissionFlag updateFlag, bool killProcess)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    std::string permissionName;
    (void)ParseAniString(env, static_cast<ani_string>(aniPermission), permissionName);
    uint32_t permissionFlags = static_cast<uint32_t>(aniFlags);
    LOGI(ATM_DOMAIN, ATM_TAG, "tokenID = %{public}d, permissionName = %{public}s, flag = %{public}d.",
        tokenID, permissionName.c_str(), permissionFlags);

    if ((!BusinessErrorAni::ValidateTokenIDWithThrowError(env, tokenID)) ||
        (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName)) ||
        (!BusinessErrorAni::ValidatePermissionFlagWithThrowError(env, permissionFlags))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId(%{public}u) or Permission(%{public}s) or flags(%{public}u)is invalid.",
            tokenID, permissionName.c_str(), permissionFlags);
        return;
    }

    PermissionBriefDef def;
    if (!GetPermissionBriefDef(permissionName, def)) {
        std::string errMsg = GetErrorMessage(STS_ERROR_PERMISSION_NOT_EXIST);
        BusinessErrorAni::ThrowError(env, STS_ERROR_PERMISSION_NOT_EXIST, errMsg);
        return;
    }

    if (updateFlag == USER_GRANTED_PERM && def.grantMode != USER_GRANT) {
        std::string errMsg = GetErrorMessage(STS_ERROR_PERMISSION_NOT_EXIST,
            "The specified permission is not a user_grant permission.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_PERMISSION_NOT_EXIST, errMsg);
        return;
    }

    if (updateFlag == OPERABLE_PERM && def.grantMode != USER_GRANT && def.grantMode != MANUAL_SETTINGS) {
        std::string errMsg = GetErrorMessage(STS_ERROR_EXPECTED_PERMISSION_TYPE,
            "The specified permission is not a user_grant or manual_settings permission.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_EXPECTED_PERMISSION_TYPE, errMsg);
        return;
    }

    int32_t ret = AccessTokenKit::RevokePermission(tokenID, permissionName, permissionFlags, updateFlag, killProcess);
    if (ret != RET_SUCCESS) {
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(ret);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
    }
}

static void GrantUserGrantedPermissionExecute([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_int aniTokenID, ani_string aniPermission, ani_int aniFlags)
{
    GrantPermissionInner(env, aniTokenID, aniPermission, aniFlags, USER_GRANTED_PERM);
}

static void RevokeUserGrantedPermissionExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_int aniTokenID, ani_string aniPermission, ani_int aniFlags)
{
    RevokePermissionInner(env, aniTokenID, aniPermission, aniFlags, USER_GRANTED_PERM, true);
}

static void GrantPermissionExecute([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_int aniTokenID, ani_string aniPermission, ani_int aniFlags)
{
    GrantPermissionInner(env, aniTokenID, aniPermission, aniFlags, OPERABLE_PERM);
}

static void RevokePermissionExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_int aniTokenID, ani_string aniPermission, ani_int aniFlags,
    ani_boolean killProcess)
{
    RevokePermissionInner(env, aniTokenID, aniPermission, aniFlags, OPERABLE_PERM, killProcess);
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
    [[maybe_unused]] ani_object object, ani_int aniTokenID, ani_array aniPermissionList)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "GetPermissionsStatusExecute begin.");
    if ((env == nullptr) || (aniPermissionList == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AniPermissionList or env is null.");
        return nullptr;
    }
    AccessTokenID tokenID = static_cast<AccessTokenID>(aniTokenID);
    if (!BusinessErrorAni::ValidateTokenIDWithThrowError(env, tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId(%{public}u) is invalid.", tokenID);
        return nullptr;
    }
    std::vector<std::string> permissionList = ParseAniStringVector(env, aniPermissionList);

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
    std::string permissionName;
    (void)ParseAniString(env, static_cast<ani_string>(aniPermissionName), permissionName);
    if ((!BusinessErrorAni::ValidateTokenIDWithThrowError(env, tokenID)) ||
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
    std::string permissionName;
    (void)ParseAniString(env, static_cast<ani_string>(aniPermissionName), permissionName);
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
    std::string permissionName;
    (void)ParseAniString(env, static_cast<ani_string>(aniPermissionName), permissionName);
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

static bool ParseInputToRegister(const RegisterInputInfoAni& aniInputInfo,
    RegisterPermStateChangeInf* context, bool isReg)
{
    std::string type;
    if (!ParseAniString(context->env, aniInputInfo.aniType, type) || type.empty()) {
        BusinessErrorAni::ThrowError(context->env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("type", "permissionStateChange or selfPermissionStateChange"));
        return false;
    }
    if ((type != REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) && (type != REGISTER_PERMISSION_STATE_CHANGE_TYPE)) {
        BusinessErrorAni::ThrowError(
            context->env, STS_ERROR_PARAM_INVALID, GetErrorMessage(STS_ERROR_PARAM_INVALID, "type is invalid."));
        return false;
    }

    context->permStateChangeType = type;
    context->threadId = std::this_thread::get_id();

    PermStateChangeScope scopeInfo;
    std::string errMsg;
    if (type == REGISTER_PERMISSION_STATE_CHANGE_TYPE) {
        if (!AniParseAccessTokenIDArray(context->env, aniInputInfo.aniTokenIds, scopeInfo.tokenIDs)) {
            BusinessErrorAni::ThrowError(
                context->env, STS_ERROR_PARAM_ILLEGAL, GetParamErrorMsg("tokenIDList", "Array<int>"));
            return false;
        }
    } else if (type == REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) {
        scopeInfo.tokenIDs = {GetSelfTokenID()};
    }
    scopeInfo.permList = ParseAniStringVector(context->env, aniInputInfo.aniPermissionNames);
    bool hasCallback = true;
    if (!isReg) {
        hasCallback = !(AniIsRefUndefined(context->env, aniInputInfo.aniCallback));
    }

    ani_ref callback = aniInputInfo.aniCallback;
    if (hasCallback) {
        if (!AniParseCallback(context->env, aniInputInfo.aniCallback, callback)) {
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

static void FillRegisterInfo(const ani_string& aniType, const ani_array& aniId, const ani_array& aniArray,
    const ani_ref& callback, RegisterInputInfoAni& aniInputInfo)
{
    aniInputInfo.aniType = aniType;
    aniInputInfo.aniTokenIds = aniId;
    aniInputInfo.aniPermissionNames = aniArray;
    aniInputInfo.aniCallback = callback;
}

static void RegisterPermStateChangeCallback([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_string aniType, ani_array aniId, ani_array aniArray, ani_ref callback)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return;
    }

    RegisterPermStateChangeInf* registerPermStateChangeInf = new (std::nothrow) RegisterPermStateChangeInf();
    if (registerPermStateChangeInf == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to allocate memory for RegisterPermStateChangeInf!");
        return;
    }
    registerPermStateChangeInf->env = env;
    std::unique_ptr<RegisterPermStateChangeInf> callbackPtr {registerPermStateChangeInf};
    RegisterInputInfoAni aniInputInfo;
    FillRegisterInfo(aniType, aniId, aniArray, callback, aniInputInfo);
    if (!ParseInputToRegister(aniInputInfo, registerPermStateChangeInf, true)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to ParseInputToRegister.");
        return;
    }

    if (IsExistRegister(registerPermStateChangeInf)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Subscribe. The subscriber has existed or Reference_StrictEquals failed!");
        std::string errMsg = "The API reuses the same input. The subscriber already exists.";
        if (registerPermStateChangeInf->permStateChangeType == REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) {
            BusinessErrorAni::ThrowError(env, STSErrorCode::STS_ERROR_NOT_USE_TOGETHER,
                GetErrorMessage(STSErrorCode::STS_ERROR_NOT_USE_TOGETHER, errMsg));
        } else {
            BusinessErrorAni::ThrowError(env, STSErrorCode::STS_ERROR_PARAM_INVALID,
                GetErrorMessage(STSErrorCode::STS_ERROR_PARAM_INVALID, errMsg));
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
        LOGI(ATM_DOMAIN, ATM_TAG, "g_PermStateChangeRegisters size = %{public}zu.", g_permStateChangeRegisters.size());
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
            if (!AniIsCallbackRefEqual(unregisterPermStateChangeInf->env, callbackRef,
                item->callbackRef, item->threadId, callbackEqual)) {
                continue;
            }
            if (!callbackEqual) {
                continue;
            }
        }

        LOGI(ATM_DOMAIN, ATM_TAG, "Callback is equal.");
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
            ++item;
            continue;
        }
        if (!callbackEqual) {
            ++item;
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
    ani_string aniType, ani_array aniId, ani_array aniArray, ani_ref callback)
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
    RegisterInputInfoAni aniInputInfo;
    FillRegisterInfo(aniType, aniId, aniArray, callback, aniInputInfo);

    if (!ParseInputToRegister(aniInputInfo, context, false)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to ParseInputToRegister.");
        return;
    }

    std::vector<RegisterPermStateChangeInf*> batchPermStateChangeRegisters;
    if (!FindAndGetSubscriberInVector(context, batchPermStateChangeRegisters)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Unsubscribe. The subscriber does not exist or reference equals failed!");
        if (context->permStateChangeType == REGISTER_SELF_PERMISSION_STATE_CHANGE_TYPE) {
            BusinessErrorAni::ThrowError(env, STSErrorCode::STS_ERROR_NOT_USE_TOGETHER,
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
        if (result != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to UnregisterPermStateChangeCallback.");
            int32_t stsCode = BusinessErrorAni::GetStsErrorCode(result);
            BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
            return;
        }
        DeleteRegisterFromVector(item);
    }
    return;
}

static void UpdatePermStatusCache(AtManagerSyncContext* syncContext)
{
    std::lock_guard<std::mutex> lock(g_lockStatusCache);
    auto iter = g_statusCache.find(syncContext->permissionName);
    if (iter != g_statusCache.end()) {
        std::string currPara = GetPermParamValue(g_paramFlagCache, PERMISSION_STATUS_FLAG_CHANGE_KEY);
        if (currPara != iter->second.paramValue) {
            syncContext->result = AccessTokenKit::GetSelfPermissionStatus(syncContext->permissionName,
                syncContext->permissionsStatus);
            iter->second.status = syncContext->permissionsStatus;
            iter->second.paramValue = currPara;
        } else {
            syncContext->result = RET_SUCCESS;
            syncContext->permissionsStatus = iter->second.status;
        }
    } else {
        syncContext->result = AccessTokenKit::GetSelfPermissionStatus(syncContext->permissionName,
            syncContext->permissionsStatus);
        g_statusCache[syncContext->permissionName].status = syncContext->permissionsStatus;
        g_statusCache[syncContext->permissionName].paramValue = GetPermParamValue(
            g_paramFlagCache, PERMISSION_STATUS_FLAG_CHANGE_KEY);
        }
}

static ani_int GetSelfPermissionStatusExecute([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object,
    ani_string aniPermissionName)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return static_cast<ani_int>(PermissionOper::INVALID_OPER);
    }

    std::string permissionName;
    (void)ParseAniString(env, aniPermissionName, permissionName);
    if (!BusinessErrorAni::ValidatePermissionWithThrowError(env, permissionName)) {
        return static_cast<ani_int>(PermissionOper::INVALID_OPER);
    }

    auto* syncContext = new (std::nothrow) AtManagerSyncContext();
    if (syncContext == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to alloc memory for syncContext.");
        return static_cast<ani_int>(PermissionOper::INVALID_OPER);
    }

    std::unique_ptr<AtManagerSyncContext> context { syncContext };
    syncContext->permissionName = permissionName;

    UpdatePermStatusCache(syncContext);

    if (syncContext->result != RET_SUCCESS) {
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(syncContext->result);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
        return static_cast<ani_int>(PermissionOper::INVALID_OPER);
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "PermissionName %{public}s self status is %{public}d.", permissionName.c_str(),
        static_cast<int32_t>(syncContext->permissionsStatus));
    return static_cast<ani_int>(syncContext->permissionsStatus);
}

static ani_ref CreatePermissionStatusInfoArray(ani_env* env,
    const std::vector<PermissionStatus>& permissionInfoList)
{
    // Create result array
    ani_ref resultArray = CreateArrayObject(env, permissionInfoList.size());
    if (resultArray == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create result array.");
        return nullptr;
    }

    // Fill array with PermissionStatusInfo objects
    for (size_t i = 0; i < permissionInfoList.size(); ++i) {
        const auto& permStatus = permissionInfoList[i];

        ani_object aniObject = CreateClassObject(env,
            "@ohos.abilityAccessCtrl.abilityAccessCtrl.PermissionStatusInfoInner");
        if (aniObject == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to create PermissionStatusInfo object.");
            continue;
        }

        // Set tokenID property
        SetIntProperty(env, aniObject, "tokenID", static_cast<int32_t>(permStatus.tokenID));

        // Set permissionName property
        SetStringProperty(env, aniObject, "permissionName", permStatus.permissionName);

        // Set grantStatus property
        // set permStateChangeType: int32_t
        ani_size enumIndex = (permStatus.grantStatus == 0) ? 1 : 0;
        const char* enumDescriptor = "@ohos.abilityAccessCtrl.abilityAccessCtrl.GrantStatus";
        SetEnumProperty(
            env, aniObject, enumDescriptor, "grantStatus", static_cast<int32_t>(enumIndex));

        // Set grantFlags property
        SetIntProperty(env, aniObject, "grantFlags", static_cast<int32_t>(permStatus.grantFlag));

        // Set optional grantTimestamp property
        SetOptionalLongProperty(env, aniObject, "grantTimestamp", static_cast<int64_t>(permStatus.timestamp));

        // Set array element
        ani_size index = static_cast<ani_size>(i);
        ani_status status = env->Array_Set(reinterpret_cast<ani_array>(resultArray), index, aniObject);
        if (status != ANI_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to set array element at index %{public}zu.", i);
        }
    }

    return resultArray;
}

static ani_ref QueryStatusByPermissionExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_array aniPermissionList)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "QueryPermissionsByPermissionsExecute begin.");
    if ((env == nullptr) || (aniPermissionList == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env or permissionList is null.");
        return nullptr;
    }

    // Parse permission list from ANI array
    std::vector<std::string> permissionList = ParseAniStringVector(env, aniPermissionList);

    // Call C++ API to query permission information
    std::vector<PermissionStatus> permissionInfoList;
    int32_t result = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList, true);
    if (result != RET_SUCCESS) {
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(result);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
        return nullptr;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "QueryStatusByPermissionExecute end, result size: %{public}zu.",
        permissionInfoList.size());
    return CreatePermissionStatusInfoArray(env, permissionInfoList);
}

static ani_ref QueryStatusByTokenIDExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_array aniTokenIDList)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "QueryPermissionsByTokenIDsExecute begin.");
    if ((env == nullptr) || (aniTokenIDList == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env or tokenIDList is null.");
        return nullptr;
    }

    // Parse tokenID list from ANI array
    std::vector<AccessTokenID> tokenIDList;
    if (!AniParseAccessTokenIDArray(env, aniTokenIDList, tokenIDList)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to parse tokenID list.");
        BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_ILLEGAL, GetParamErrorMsg("tokenIDList", "Array<int>"));
        return nullptr;
    }

    // Call C++ API to query permission information
    std::vector<PermissionStatus> permissionInfoList;
    int32_t result = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);
    if (result != RET_SUCCESS) {
        int32_t stsCode = BusinessErrorAni::GetStsErrorCode(result);
        BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
        return nullptr;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "QueryStatusByTokenIDExecute end, result size: %{public}zu.",
        permissionInfoList.size());
    return CreatePermissionStatusInfoArray(env, permissionInfoList);
}

template<typename T, typename Parser>
static bool ParseObjectArray(ani_env* env, ani_array array, std::vector<T>& result, Parser parser)
{
    if ((env == nullptr) || (array == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env or array is null.");
        return false;
    }
    ani_size size = 0;
    ani_status status = env->Array_GetLength(array, &size);
    if (status != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Array_GetLength: %{public}u.", status);
        return false;
    }
    for (ani_size i = 0; i < size; ++i) {
        ani_ref item = nullptr;
        status = env->Array_Get(array, i, &item);
        if (status != ANI_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to Array_Get: %{public}u.", status);
            return false;
        }
        T value;
        if (!parser(env, static_cast<ani_object>(item), value)) {
            return false;
        }
        result.emplace_back(value);
    }
    return true;
}

template<typename T, typename Converter>
static ani_ref CreateAniObjectArray(ani_env* env, const std::vector<T>& values, Converter converter)
{
    ani_ref resultArray = CreateArrayObject(env, values.size());
    if (resultArray == nullptr) {
        return nullptr;
    }
    for (size_t i = 0; i < values.size(); ++i) {
        ani_object item = converter(env, values[i]);
        if (item == nullptr) {
            return nullptr;
        }
        ani_status status = env->Array_Set(reinterpret_cast<ani_array>(resultArray), static_cast<ani_size>(i), item);
        if (status != ANI_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to set array item at index %{public}zu.", i);
            return nullptr;
        }
    }
    return resultArray;
}

static bool ParseCliInfo(ani_env* env, ani_object object, CliInfo& info)
{
    if (!GetStringProperty(env, object, "cliName", info.cliName) ||
        !GetStringProperty(env, object, "subCliName", info.subCliName)) {
        return false;
    }
    return true;
}

static bool IsCliInfoValueValid(const CliInfo& info)
{
    return DataValidator::IsProcessNameValid(info.cliName) &&
        (info.cliName.length() <= MAX_CLAW_CLI_NAME_LEN) &&
        (info.subCliName.empty() || info.subCliName.length() <= MAX_CLAW_SUB_CLI_NAME_LEN);
}

static bool ParseCliInfoArray(ani_env* env, ani_array arrayObject, std::vector<CliInfo>& result)
{
    return ParseObjectArray(env, arrayObject, result, ParseCliInfo);
}

static bool GetObjectProperty(ani_env* env, ani_object object, const std::string& property, ani_object& value)
{
    ani_ref ref = nullptr;
    ani_status status = env->Object_GetPropertyByName_Ref(object, property.c_str(), &ref);
    if ((status != ANI_OK) || AniIsRefUndefined(env, ref)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get object property %{public}s.", property.c_str());
        return false;
    }
    value = static_cast<ani_object>(ref);
    return true;
}

static bool GetBoolVecProperty(ani_env* env, ani_object object, const std::string& property,
    std::vector<bool>& value)
{
    ani_ref ref = nullptr;
    ani_status status = env->Object_GetPropertyByName_Ref(object, property.c_str(), &ref);
    if ((status != ANI_OK) || AniIsRefUndefined(env, ref)) {
        return false;
    }
    ani_array array = static_cast<ani_array>(ref);
    ani_size size = 0;
    if (env->Array_GetLength(array, &size) != ANI_OK) {
        return false;
    }
    for (ani_size i = 0; i < size; ++i) {
        ani_ref item = nullptr;
        ani_boolean boolValue = false;
        if (env->Array_Get(array, i, &item) != ANI_OK) {
            return false;
        }
        if (env->Object_CallMethodByName_Boolean(
            static_cast<ani_object>(item), "toBoolean", nullptr, &boolValue) != ANI_OK) {
            return false;
        }
        value.emplace_back(static_cast<bool>(boolValue));
    }
    return true;
}

static bool ParseCliAuthInfo(ani_env* env, ani_object object, CliAuthInfo& info)
{
    ani_object cliObject = nullptr;
    return GetObjectProperty(env, object, "cliInfo", cliObject) &&
        ParseCliInfo(env, cliObject, info.cliInfo) &&
        GetStringVecProperty(env, object, "permissionNames", info.permissionNames) &&
        GetBoolVecProperty(env, object, "authorizationResults", info.authorizationResults);
}

static bool IsCliInfoListValueValid(const std::vector<CliInfo>& infos)
{
    if (infos.empty() || infos.size() > MAX_CLAW_CLI_INFO_LIST_SIZE) {
        return false;
    }
    for (const auto& info : infos) {
        if (!IsCliInfoValueValid(info)) {
            return false;
        }
    }
    return true;
}

static bool IsPermissionNameValid(const std::string& permissionName)
{
    return !permissionName.empty() && permissionName.length() <= MAX_CLAW_CLI_NAME_LEN;
}

static bool IsCliAuthInfoListValueValid(const std::vector<CliAuthInfo>& authInfos)
{
    if (authInfos.empty() || authInfos.size() > MAX_CLAW_CLI_INFO_LIST_SIZE) {
        return false;
    }
    for (const auto& authInfo : authInfos) {
        if (!IsCliInfoValueValid(authInfo.cliInfo) ||
            authInfo.permissionNames.size() != authInfo.authorizationResults.size()) {
            return false;
        }
        for (const auto& permissionName : authInfo.permissionNames) {
            if (!IsPermissionNameValid(permissionName)) {
                return false;
            }
        }
    }
    return true;
}

static std::vector<int32_t> ConvertStatusList(const std::vector<PermissionDecisionStatus>& statusList)
{
    std::vector<int32_t> result;
    result.reserve(statusList.size());
    for (const auto& status : statusList) {
        result.emplace_back(static_cast<int32_t>(status));
    }
    return result;
}

static ani_object CreatePermissionDialogDetailObject(ani_env* env, const PermissionDialogDetail& detail)
{
    ani_object aniObject = CreateClassObject(env,
        "@ohos.abilityAccessCtrl.abilityAccessCtrl.PermissionDialogDetailInner");
    if (aniObject == nullptr) {
        return nullptr;
    }
    SetBoolProperty(env, aniObject, "needPermissionDialog", detail.needPermissionDialog);
    SetRefProperty(env, aniObject, "permissionNameList", CreateAniArrayString(env, detail.permissionNameList));
    SetRefProperty(env, aniObject, "statusList", CreateAniArrayInt(env, ConvertStatusList(detail.statusList)));
    SetStringProperty(env, aniObject, "authResult", detail.authResult);
    return aniObject;
}

static ani_ref CreatePermissionDialogDetailArray(ani_env* env,
    const std::vector<PermissionDialogDetail>& detailList)
{
    return CreateAniObjectArray(env, detailList, CreatePermissionDialogDetailObject);
}

static ani_ref CreatePermissionDialogResultObject(ani_env* env, const PermissionDialogResult& result)
{
    ani_object aniObject = CreateClassObject(env,
        "@ohos.abilityAccessCtrl.abilityAccessCtrl.PermissionDialogResultInner");
    if (aniObject == nullptr) {
        return nullptr;
    }
    SetRefProperty(env, aniObject, "detailList", CreatePermissionDialogDetailArray(env, result.detailList));
    return aniObject;
}

static ani_object CreateCliPermissionDetailObject(ani_env* env, const CliPermissionDetail& detail)
{
    ani_object aniObject = CreateClassObject(env,
        "@ohos.abilityAccessCtrl.abilityAccessCtrl.CliPermissionDetailInner");
    if (aniObject == nullptr) {
        return nullptr;
    }
    SetStringProperty(env, aniObject, "requiredCliPermission", detail.requiredCliPermission);
    SetEnumProperty(env, aniObject, "@ohos.abilityAccessCtrl.abilityAccessCtrl.PermissionDecisionStatus",
        "cliPermissionStatus", static_cast<uint32_t>(detail.cliPermissionStatus));
    SetRefProperty(env, aniObject, "usedPermissions", CreateAniArrayString(env, detail.usedPermissions));
    return aniObject;
}

static ani_ref CreateCliPermissionDetailArray(ani_env* env, const std::vector<CliPermissionDetail>& detailList)
{
    return CreateAniObjectArray(env, detailList, CreateCliPermissionDetailObject);
}

static ani_object CreateCliCommandPermissionResultObject(ani_env* env, const CliCommandPermissionResult& result)
{
    ani_object aniObject = CreateClassObject(env,
        "@ohos.abilityAccessCtrl.abilityAccessCtrl.CliCommandPermissionResultInner");
    if (aniObject == nullptr) {
        return nullptr;
    }
    SetRefProperty(env, aniObject, "requiredCliPermissions",
        CreateCliPermissionDetailArray(env, result.requiredCliPermissions));
    return aniObject;
}

static ani_ref CreateCliCommandPermissionResultArray(ani_env* env,
    const std::vector<CliCommandPermissionResult>& permList)
{
    return CreateAniObjectArray(env, permList, CreateCliCommandPermissionResultObject);
}

static ani_ref CreateCliPermissionsResultObject(ani_env* env, const CliPermissionsResult& result)
{
    ani_object aniObject = CreateClassObject(env,
        "@ohos.abilityAccessCtrl.abilityAccessCtrl.CliPermissionsResultInner");
    if (aniObject == nullptr) {
        return nullptr;
    }
    SetRefProperty(env, aniObject, "permList", CreateCliCommandPermissionResultArray(env, result.permList));
    return aniObject;
}

static ani_ref CreateToolAuthResultObject(ani_env* env, const ToolAuthResult& result)
{
    ani_object aniObject = CreateClassObject(env,
        "@ohos.abilityAccessCtrl.abilityAccessCtrl.ToolAuthResultInner");
    if (aniObject == nullptr) {
        return nullptr;
    }
    SetRefProperty(env, aniObject, "authResults", CreateAniArrayString(env, result.authResults));
    return aniObject;
}

static bool CheckKitResultAndThrow(ani_env* env, int32_t result)
{
    if (result == RET_SUCCESS) {
        return true;
    }
    int32_t stsCode = BusinessErrorAni::GetStsErrorCode(result);
    BusinessErrorAni::ThrowError(env, stsCode, GetErrorMessage(stsCode));
    return false;
}

static void ThrowParamInvalidError(ani_env* env, const std::string& errorMsg)
{
    BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_INVALID, GetErrorMessage(STS_ERROR_PARAM_INVALID, errorMsg));
}

static bool IsTokenIDValid(AccessTokenID hostTokenID)
{
    return DataValidator::IsTokenIDValid(hostTokenID);
}

static bool ParseAgentID(ani_env* env, ani_string aniAgentID, std::string& agentID)
{
    return ParseAniString(env, aniAgentID, agentID);
}

static bool IsAgentIDValid(const std::string& agentID)
{
    return agentID.length() <= MAX_CLAW_AGENT_ID_LEN;
}

static ani_ref GetCliPermissionRequestInfoExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_string aniAgentID, ani_array aniCliInfoList)
{
    std::string agentID;
    if (!ParseAgentID(env, aniAgentID, agentID)) {
        BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_ILLEGAL, GetParamErrorMsg("agentID", "string"));
        return nullptr;
    }
    if (!IsAgentIDValid(agentID)) {
        ThrowParamInvalidError(env, "The agentID exceeds 48 characters.");
        return nullptr;
    }
    std::vector<CliInfo> cliInfoList;
    if (!ParseCliInfoArray(env, aniCliInfoList, cliInfoList)) {
        BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_ILLEGAL, GetParamErrorMsg("cliList", "Array<CliInfo>"));
        return nullptr;
    }
    if (!IsCliInfoListValueValid(cliInfoList)) {
        ThrowParamInvalidError(env, "The cliList is invalid.");
        return nullptr;
    }
    PermissionDialogResult result;
    int32_t ret = AccessTokenKit::GetCliPermissionRequestInfo(agentID, cliInfoList, result);
    if (!CheckKitResultAndThrow(env, ret)) {
        return nullptr;
    }
    return CreatePermissionDialogResultObject(env, result);
}

static ani_ref GetCliPermissionsExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_int aniHostTokenID, ani_string aniAgentID, ani_array aniCliInfoList)
{
    AccessTokenID hostTokenID = static_cast<AccessTokenID>(aniHostTokenID);
    if (!IsTokenIDValid(hostTokenID)) {
        ThrowParamInvalidError(env, "The hostTokenID is 0.");
        return nullptr;
    }
    std::string agentID;
    if (!ParseAgentID(env, aniAgentID, agentID)) {
        BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_ILLEGAL, GetParamErrorMsg("agentID", "string"));
        return nullptr;
    }
    if (!IsAgentIDValid(agentID)) {
        ThrowParamInvalidError(env, "The agentID exceeds 48 characters.");
        return nullptr;
    }
    std::vector<CliInfo> cliInfoList;
    if (!ParseCliInfoArray(env, aniCliInfoList, cliInfoList)) {
        BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("cliInfoList", "Array<CliInfo>"));
        return nullptr;
    }
    if (!IsCliInfoListValueValid(cliInfoList)) {
        ThrowParamInvalidError(env, "The cliInfoList is invalid.");
        return nullptr;
    }
    CliPermissionsResult result;
    int32_t ret = AccessTokenKit::GetCliPermissions(hostTokenID, agentID, cliInfoList, result);
    if (!CheckKitResultAndThrow(env, ret)) {
        return nullptr;
    }
    return CreateCliPermissionsResultObject(env, result);
}

static ani_ref GenerateCliAuthResultExecute([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object object, ani_int aniHostTokenID, ani_string aniAgentID, ani_array aniAuthInfoList)
{
    AccessTokenID hostTokenID = static_cast<AccessTokenID>(aniHostTokenID);
    if (!IsTokenIDValid(hostTokenID)) {
        ThrowParamInvalidError(env, "The hostTokenID is 0.");
        return nullptr;
    }
    std::string agentID;
    if (!ParseAgentID(env, aniAgentID, agentID)) {
        BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_ILLEGAL, GetParamErrorMsg("agentID", "string"));
        return nullptr;
    }
    if (!IsAgentIDValid(agentID)) {
        ThrowParamInvalidError(env, "The agentID exceeds 48 characters.");
        return nullptr;
    }
    std::vector<CliAuthInfo> authInfoList;
    if (!ParseObjectArray(env, aniAuthInfoList, authInfoList, ParseCliAuthInfo)) {
        BusinessErrorAni::ThrowError(env, STS_ERROR_PARAM_ILLEGAL,
            GetParamErrorMsg("authInfoList", "Array<CliAuthInfo>"));
        return nullptr;
    }
    if (!IsCliAuthInfoListValueValid(authInfoList)) {
        ThrowParamInvalidError(env, "The authInfoList is invalid.");
        return nullptr;
    }
    ToolAuthResult result;
    int32_t ret = AccessTokenKit::GenerateCliAuthResult(hostTokenID, agentID, authInfoList, result);
    if (!CheckKitResultAndThrow(env, ret)) {
        return nullptr;
    }
    return CreateToolAuthResultObject(env, result);
}

static void AppendTokenNativeFunctions(std::vector<ani_native_function>& methods)
{
    methods.insert(methods.end(), {
        ani_native_function { "checkAccessTokenExecute", nullptr, reinterpret_cast<void*>(CheckAccessTokenExecute) },
        ani_native_function { "checkContextExecute",
            nullptr, reinterpret_cast<void*>(CheckContextExecute) },
        ani_native_function { "grantUserGrantedPermissionExecute", nullptr,
            reinterpret_cast<void*>(GrantUserGrantedPermissionExecute) },
        ani_native_function { "revokeUserGrantedPermissionExecute",
            nullptr, reinterpret_cast<void*>(RevokeUserGrantedPermissionExecute) },
        ani_native_function { "grantPermissionExecute", nullptr,
            reinterpret_cast<void*>(GrantPermissionExecute) },
        ani_native_function { "revokePermissionExecute",
            nullptr, reinterpret_cast<void*>(RevokePermissionExecute) },
        ani_native_function { "getVersionExecute", nullptr, reinterpret_cast<void*>(GetVersionExecute) },
        ani_native_function{ "getPermissionFlagsExecute",
            nullptr, reinterpret_cast<void*>(GetPermissionFlagsExecute) },
        ani_native_function{ "setPermissionRequestToggleStatusExecute",
            nullptr, reinterpret_cast<void*>(SetPermissionRequestToggleStatusExecute) },
        ani_native_function{ "getPermissionRequestToggleStatusExecute",
            nullptr, reinterpret_cast<void*>(GetPermissionRequestToggleStatusExecute) },
        ani_native_function{ "requestAppPermOnSettingExecute",
            nullptr, reinterpret_cast<void*>(RequestAppPermOnSettingExecute) },
    });
}

static void AppendRequestNativeFunctions(std::vector<ani_native_function>& methods)
{
    methods.insert(methods.end(), {
        ani_native_function { "requestPermissionsFromUserExecute",
            nullptr, reinterpret_cast<void*>(RequestPermissionsFromUserExecute) },
        ani_native_function { "requestPermissionsFromUserWithWindowIdExecute",
            nullptr, reinterpret_cast<void*>(RequestPermissionsFromUserWithWindowIdExecute) },
        ani_native_function { "requestPermissionOnSettingExecute",
            nullptr, reinterpret_cast<void*>(RequestPermissionOnSettingExecute) },
        ani_native_function { "openPermissionOnSettingExecute",
            nullptr, reinterpret_cast<void*>(OpenPermissionOnSettingExecute) },
        ani_native_function {"requestGlobalSwitchExecute",
            nullptr, reinterpret_cast<void*>(RequestGlobalSwitchExecute) },
    });
}

static void AppendQueryNativeFunctions(std::vector<ani_native_function>& methods)
{
    methods.insert(methods.end(), {
        ani_native_function { "getPermissionsStatusExecute",
            nullptr, reinterpret_cast<void*>(GetPermissionsStatusExecute) },
        ani_native_function { "onPermissionStateChangeExecute", nullptr,
            reinterpret_cast<void*>(RegisterPermStateChangeCallback) },
        ani_native_function { "offPermissionStateChangeExecute", nullptr,
            reinterpret_cast<void*>(UnregisterPermStateChangeCallback) },
        ani_native_function { "getSelfPermissionStatusExecute",
            nullptr, reinterpret_cast<void*>(GetSelfPermissionStatusExecute) },
        ani_native_function { "queryStatusByPermissionExecute",
            nullptr, reinterpret_cast<void*>(QueryStatusByPermissionExecute) },
        ani_native_function { "queryStatusByTokenIDExecute",
            nullptr, reinterpret_cast<void*>(QueryStatusByTokenIDExecute) },
    });
}

static void AppendClawNativeFunctions(std::vector<ani_native_function>& methods)
{
    methods.insert(methods.end(), {
        ani_native_function { "getCliPermissionRequestInfoExecute",
            nullptr, reinterpret_cast<void*>(GetCliPermissionRequestInfoExecute) },
        ani_native_function { "getCliPermissionsExecute",
            nullptr, reinterpret_cast<void*>(GetCliPermissionsExecute) },
        ani_native_function { "generateCliAuthResultExecute",
            nullptr, reinterpret_cast<void*>(GenerateCliAuthResultExecute) },
    });
}

static ani_status AtManagerBindNativeFunction(ani_env* env, ani_class& cls)
{
    std::vector<ani_native_function> clsMethods;
    AppendTokenNativeFunctions(clsMethods);
    AppendRequestNativeFunctions(clsMethods);
    AppendQueryNativeFunctions(clsMethods);
    AppendClawNativeFunctions(clsMethods);
    return env->Class_BindNativeMethods(cls, clsMethods.data(), clsMethods.size());
}

ani_status InitAbilityCtrlFunction(ani_env* env)
{
    if (env == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Env is null.");
        return ANI_OUT_OF_MEMORY;
    }

    ani_status retStatus = ANI_OK;
    ani_namespace aniAtNamespace;
    const char* atNamespace = "@ohos.abilityAccessCtrl.abilityAccessCtrl";
    retStatus = env->FindNamespace(atNamespace, &aniAtNamespace);
    if (retStatus != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Not found %{public}s, status: %{public}u.", atNamespace, retStatus);
        return retStatus;
    }
    std::array methods = {
        ani_native_function { "createAtManager", nullptr, reinterpret_cast<void*>(CreateAtManager) },
    };
    retStatus = env->Namespace_BindNativeFunctions(aniAtNamespace, methods.data(), methods.size());
    if (retStatus != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Cannot bind native methods to %{public}s, status: %{public}u.",
            atNamespace, retStatus);
        return retStatus;
    };
    const char* atManagerClassName = "@ohos.abilityAccessCtrl.abilityAccessCtrl.AtManagerInner";
    ani_class aniAtManagerClassName;
    retStatus = env->FindClass(atManagerClassName, &aniAtManagerClassName);
    if (retStatus != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Not found %{public}s, status: %{public}u.", atManagerClassName, retStatus);
        return retStatus;
    }
    retStatus = AtManagerBindNativeFunction(env, aniAtManagerClassName);
    if (retStatus != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Cannot bind native methods to %{public}s, status: %{public}u.",
            atManagerClassName, retStatus);
        return retStatus;
    };
    return retStatus;
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
    ani_status ret = InitAbilityCtrlFunction(env);
    *result = ANI_VERSION_1;
    if (ret != ANI_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to init atmanger function.");
    }
    return ret;
}
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
