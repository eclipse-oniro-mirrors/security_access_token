/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "accesstoken_manager_service.h"

#include <unistd.h>

#include "access_token.h"
#include "access_token_db.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_service_ipc_interface_code.h"
#include "constant_common.h"
#include "data_validator.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "hisysevent_adapter.h"
#ifdef HITRACE_NATIVE_ENABLE
#include "hitrace_meter.h"
#endif
#include "ipc_skeleton.h"
#include "json_parse_loader.h"
#include "libraryloader.h"
#include "memory_guard.h"
#include "parameter.h"
#include "parameters.h"
#include "permission_list_state.h"
#include "permission_manager.h"
#include "permission_map.h"
#include "permission_validator.h"
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
#include "sec_comp_enhance_agent.h"
#endif
#include "short_grant_manager.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "token_field_const.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_modify_notifier.h"
#endif // TOKEN_SYNC_ENABLE
#include "tokenid_kit.h"
#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const char* ACCESS_TOKEN_SERVICE_INIT_KEY = "accesstoken.permission.init";
constexpr int32_t ERROR = -1;
constexpr int TWO_ARGS = 2;
const char* GRANT_ABILITY_BUNDLE_NAME = "com.ohos.permissionmanager";
const char* GRANT_ABILITY_ABILITY_NAME = "com.ohos.permissionmanager.GrantAbility";
const char* PERMISSION_STATE_SHEET_ABILITY_NAME = "com.ohos.permissionmanager.PermissionStateSheetAbility";
const char* GLOBAL_SWITCH_SHEET_ABILITY_NAME = "com.ohos.permissionmanager.GlobalSwitchSheetAbility";
const char* APPLICATION_SETTING_ABILITY_NAME = "com.ohos.permissionmanager.MainAbility";
const char* DEVELOPER_MODE_STATE = "const.security.developermode.state";

const std::string MANAGE_HAP_TOKENID_PERMISSION = "ohos.permission.MANAGE_HAP_TOKENID";
static constexpr int MAX_PERMISSION_SIZE = 1000;
static constexpr int32_t MAX_USER_POLICY_SIZE = 1024;
const std::string GRANT_SENSITIVE_PERMISSIONS = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
const std::string REVOKE_SENSITIVE_PERMISSIONS = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS";
const std::string GET_SENSITIVE_PERMISSIONS = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
const std::string DISABLE_PERMISSION_DIALOG = "ohos.permission.DISABLE_PERMISSION_DIALOG";
const std::string GRANT_SHORT_TERM_WRITE_MEDIAVIDEO = "ohos.permission.GRANT_SHORT_TERM_WRITE_MEDIAVIDEO";

static constexpr int32_t SA_ID_ACCESSTOKEN_MANAGER_SERVICE = 3503;

#ifdef HICOLLIE_ENABLE
constexpr uint32_t TIMEOUT = 40; // 40s
thread_local int32_t g_timerId = 0;
#endif // HICOLLIE_ENABLE
}

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<AccessTokenManagerService>::GetInstance().get());

AccessTokenManagerService::AccessTokenManagerService()
    : SystemAbility(SA_ID_ACCESSTOKEN_MANAGER_SERVICE, true), state_(ServiceRunningState::STATE_NOT_START)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "AccessTokenManagerService()");
}

AccessTokenManagerService::~AccessTokenManagerService()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "~AccessTokenManagerService()");
}

void AccessTokenManagerService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        LOGI(ATM_DOMAIN, ATM_TAG, "AccessTokenManagerService has already started!");
        return;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "AccessTokenManagerService is starting.");
    if (!Initialize()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to initialize.");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    bool ret = Publish(DelayedSingleton<AccessTokenManagerService>::GetInstance().get());
    if (!ret) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to publish service!");
        ReportSysEventServiceStartError(SA_PUBLISH_FAILED, "Publish accesstoken_service fail.", ERROR);
        return;
    }
    AccessTokenServiceParamSet();
    (void)AddSystemAbilityListener(SECURITY_COMPONENT_SERVICE_ID);
#ifdef TOKEN_SYNC_ENABLE
    (void)AddSystemAbilityListener(DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID);
#endif
    LOGI(ATM_DOMAIN, ATM_TAG, "Congratulations, AccessTokenManagerService start successfully!");
}

void AccessTokenManagerService::OnStop()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Stop service.");
    state_ = ServiceRunningState::STATE_NOT_START;
}

void AccessTokenManagerService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
#ifdef TOKEN_SYNC_ENABLE
    if (systemAbilityId == DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID) {
        AccessTokenInfoManager::GetInstance().InitDmCallback();
    }
#endif
}

void AccessTokenManagerService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    if (systemAbilityId == SECURITY_COMPONENT_SERVICE_ID) {
        HapTokenInfoInner::ClearAllSecCompGrantedPerm();
        return;
    }
}

int32_t AccessTokenManagerService::GetPermissionUsedType(
    AccessTokenID tokenID, const std::string& permissionName, int32_t& permUsedType)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d, permission=%{public}s", tokenID, permissionName.c_str());
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        permUsedType = static_cast<int32_t>(PermUsedTypeEnum::INVALID_USED_TYPE);
        return permUsedType;
    }
    permUsedType = static_cast<int32_t>(
        PermissionManager::GetInstance().GetPermissionUsedType(tokenID, permissionName));
    return ERR_OK;
}

int AccessTokenManagerService::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
#ifdef HITRACE_NATIVE_ENABLE
    StartTrace(HITRACE_TAG_ACCESS_CONTROL, "AccessTokenVerifyPermission");
#endif
    int32_t res = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, permissionName);
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d, permission: %{public}s, res %{public}d",
        tokenID, permissionName.c_str(), res);
    if ((res == PERMISSION_GRANTED) &&
        (AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenID) == TOKEN_HAP)) {
        res = AccessTokenInfoManager::GetInstance().IsPermissionRestrictedByUserPolicy(tokenID, permissionName) ?
            PERMISSION_DENIED : PERMISSION_GRANTED;
    }
#ifdef HITRACE_NATIVE_ENABLE
    FinishTrace(HITRACE_TAG_ACCESS_CONTROL);
#endif
    return res;
}

int AccessTokenManagerService::VerifyAccessToken(AccessTokenID tokenID,
    const std::vector<std::string>& permissionList, std::vector<int32_t>& permStateList)
{
    permStateList.clear();
    permStateList.resize(permissionList.size(), PERMISSION_DENIED);
    for (size_t i = 0; i < permissionList.size(); i++) {
        permStateList[i] = VerifyAccessToken(tokenID, permissionList[i]);
    }
    return RET_SUCCESS;
}

int AccessTokenManagerService::GetDefPermission(
    const std::string& permissionName, PermissionDefParcel& permissionDefResult)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Permission: %{public}s", permissionName.c_str());

    // for ipc call not by accesstoken client
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    PermissionBriefDef briefDef;
    if (!GetPermissionBriefDef(permissionName, briefDef)) {
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }

    ConvertPermissionBriefToDef(briefDef, permissionDefResult.permissionDef);

    if (briefDef.grantMode == GrantMode::SYSTEM_GRANT) {
        return 0;
    }

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);

    std::vector<GenericValues> results;
    int32_t res = AccessTokenDb::GetInstance().Find(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, conditionValue, results);
    if (res != 0) {
        return res;
    }

    if (results.empty()) {
        // user grant permission has define in map, not exsit in db
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    permissionDefResult.permissionDef.labelId = results[0].GetInt(TokenFiledConst::FIELD_LABEL_ID);
    permissionDefResult.permissionDef.descriptionId = results[0].GetInt(TokenFiledConst::FIELD_DESCRIPTION_ID);

    return 0;
}

int AccessTokenManagerService::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStatusParcel>& reqPermList, bool isSystemGrant)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    std::vector<PermissionStatus> permList;
    int ret = PermissionManager::GetInstance().GetReqPermissions(tokenID, permList, isSystemGrant);

    for (const auto& perm : permList) {
        PermissionStatusParcel permParcel;
        permParcel.permState = perm;
        reqPermList.emplace_back(permParcel);
    }
    return ret;
}

int32_t AccessTokenManagerService::GetSelfPermissionsState(std::vector<PermissionListStateParcel>& reqPermList,
    PermissionGrantInfoParcel& infoParcel, int32_t& permOper)
{
    uint32_t size = reqPermList.size();
    if (size > MAX_PERMISSION_SIZE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermList size %{public}d is invalid", size);
        return INVALID_OPER;
    }
    infoParcel.info.grantBundleName = grantBundleName_;
    infoParcel.info.grantAbilityName = grantAbilityName_;
    infoParcel.info.grantServiceAbilityName = grantServiceAbilityName_;
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    permOper = GetPermissionsState(callingTokenID, reqPermList);
    return ERR_OK;
}

int32_t AccessTokenManagerService::GetPermissionsStatus(AccessTokenID tokenID,
    std::vector<PermissionListStateParcel>& reqPermList)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    uint32_t size = reqPermList.size();
    if (size > MAX_PERMISSION_SIZE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermList size %{public}d is invalid", size);
        return INVALID_OPER;
    }

    if (!AccessTokenInfoManager::GetInstance().IsTokenIdExist(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d does not exist", tokenID);
        return ERR_TOKENID_NOT_EXIST;
    }
    PermissionOper ret = GetPermissionsState(tokenID, reqPermList);
    return ret == INVALID_OPER ? RET_FAILED : RET_SUCCESS;
}

static bool GetAppReqPermissions(AccessTokenID tokenID, std::vector<PermissionStatus>& permsList)
{
    int retUserGrant = PermissionManager::GetInstance().GetReqPermissions(tokenID, permsList, false);
    int retSysGrant = PermissionManager::GetInstance().GetReqPermissions(tokenID, permsList, true);
    if ((retSysGrant != RET_SUCCESS) || (retUserGrant != RET_SUCCESS)) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetReqPermissions failed, retUserGrant:%{public}d, retSysGrant:%{public}d",
            retUserGrant, retSysGrant);
        return false;
    }
    return true;
}

PermissionOper AccessTokenManagerService::GetPermissionsState(AccessTokenID tokenID,
    std::vector<PermissionListStateParcel>& reqPermList)
{
    int32_t apiVersion = 0;
    if (!PermissionManager::GetInstance().GetApiVersionByTokenId(tokenID, apiVersion)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get api version error");
        return INVALID_OPER;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d, apiVersion: %{public}d", tokenID, apiVersion);

    bool needRes = false;
    std::vector<PermissionStatus> permsList;
    if (!GetAppReqPermissions(tokenID, permsList)) {
        return INVALID_OPER;
    }

    // api9 location permission handle here
    if (apiVersion >= ACCURATE_LOCATION_API_VERSION) {
        needRes = PermissionManager::GetInstance().LocationPermissionSpecialHandle(
            tokenID, reqPermList, permsList, apiVersion);
    }

    uint32_t size = reqPermList.size();
    for (uint32_t i = 0; i < size; i++) {
        // api9 location permission special handle above
        if (((reqPermList[i].permsState.permissionName == VAGUE_LOCATION_PERMISSION_NAME) ||
            (reqPermList[i].permsState.permissionName == ACCURATE_LOCATION_PERMISSION_NAME) ||
            (reqPermList[i].permsState.permissionName == BACKGROUND_LOCATION_PERMISSION_NAME)) &&
            (apiVersion >= ACCURATE_LOCATION_API_VERSION)) {
            continue;
        }

        PermissionManager::GetInstance().GetSelfPermissionState(permsList, reqPermList[i].permsState, apiVersion);
        if (static_cast<PermissionOper>(reqPermList[i].permsState.state) == DYNAMIC_OPER) {
            needRes = true;
        }
        LOGD(ATM_DOMAIN, ATM_TAG, "Perm: %{public}s, state: %{public}d",
            reqPermList[i].permsState.permissionName.c_str(), reqPermList[i].permsState.state);
    }
    if (GetTokenType(tokenID) == TOKEN_HAP && AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}d is under control", tokenID);
        uint32_t size = reqPermList.size();
        for (uint32_t i = 0; i < size; i++) {
            if (reqPermList[i].permsState.state != INVALID_OPER) {
                reqPermList[i].permsState.state = FORBIDDEN_OPER;
                reqPermList[i].permsState.errorReason = PRIVACY_STATEMENT_NOT_AGREED;
            }
        }
        return FORBIDDEN_OPER;
    }
    if (needRes) {
        return DYNAMIC_OPER;
    }
    return PASS_OPER;
}

int AccessTokenManagerService::GetPermissionFlag(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }

    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GRANT_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED &&
        VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return PermissionManager::GetInstance().GetPermissionFlag(tokenID, permissionName, flag);
}

int32_t AccessTokenManagerService::SetPermissionRequestToggleStatus(
    const std::string& permissionName, uint32_t status, int32_t userID = 0)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }

    if (!IsPrivilegedCalling() && VerifyAccessToken(callingTokenID, DISABLE_PERMISSION_DIALOG) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR, "CALLER_TOKENID",
            callingTokenID, "PERMISSION_NAME", permissionName, "INTERFACE", "SetToggleStatus");
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return AccessTokenInfoManager::GetInstance().SetPermissionRequestToggleStatus(permissionName, status, userID);
}

int32_t AccessTokenManagerService::GetPermissionRequestToggleStatus(
    const std::string& permissionName, uint32_t& status, int32_t userID = 0)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }

    if (!IsShellProcessCalling() && !IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR, "CALLER_TOKENID",
            callingTokenID, "PERMISSION_NAME", permissionName, "INTERFACE", "GetToggleStatus");
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return AccessTokenInfoManager::GetInstance().GetPermissionRequestToggleStatus(permissionName, status, userID);
}

int32_t AccessTokenManagerService::RequestAppPermOnSetting(AccessTokenID tokenID)
{
    if (!IsSystemAppCalling()) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }

    HapTokenInfo hapInfo;
    int32_t ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, hapInfo);
    if (ret != ERR_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetHapTokenInfo failed, err=%{public}d.", ret);
        return ret;
    }
    return PermissionManager::GetInstance().RequestAppPermOnSetting(hapInfo,
        grantBundleName_, applicationSettingAbilityName_);
}

int AccessTokenManagerService::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GRANT_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callingTokenID, "PERMISSION_NAME", permissionName);
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    int32_t ret = PermissionManager::GetInstance().GrantPermission(tokenID, permissionName, flag);
    return ret;
}

int AccessTokenManagerService::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callingTokenID, "PERMISSION_NAME", permissionName);
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return PermissionManager::GetInstance().RevokePermission(tokenID, permissionName, flag);
}

int AccessTokenManagerService::GrantPermissionForSpecifiedTime(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t onceTime)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GRANT_SHORT_TERM_WRITE_MEDIAVIDEO) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callingTokenID, "PERMISSION_NAME", permissionName);
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    int32_t ret = PermissionManager::GetInstance().GrantPermissionForSpecifiedTime(tokenID, permissionName, onceTime);
    return ret;
}

int AccessTokenManagerService::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d", tokenID);
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callingTokenID);
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    AccessTokenInfoManager::GetInstance().ClearUserGrantedPermissionState(tokenID);
    AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenID, false);
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::RegisterPermStateChangeCallback(
    const PermStateChangeScopeParcel& scope, const sptr<IRemoteObject>& callback)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    if (VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return PermissionManager::GetInstance().AddPermStateChangeCallback(scope.scope, callback);
}

int32_t AccessTokenManagerService::UnRegisterPermStateChangeCallback(const sptr<IRemoteObject>& callback)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingToken) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    if (VerifyAccessToken(callingToken, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingToken);

        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return PermissionManager::GetInstance().RemovePermStateChangeCallback(callback);
}

int32_t AccessTokenManagerService::RegisterSelfPermStateChangeCallback(
    const PermStateChangeScopeParcel& scope, const sptr<IRemoteObject>& callback)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (this->GetTokenType(callingTokenID) != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is not hap.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return PermissionManager::GetInstance().AddPermStateChangeCallback(scope.scope, callback);
}

int32_t AccessTokenManagerService::UnRegisterSelfPermStateChangeCallback(const sptr<IRemoteObject>& callback)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (this->GetTokenType(callingToken) != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is not hap.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return PermissionManager::GetInstance().RemovePermStateChangeCallback(callback);
}

int32_t AccessTokenManagerService::AllocHapToken(const HapInfoParcel& info, const HapPolicyParcel& policy,
    uint64_t& fullTokenId)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "BundleName: %{public}s", info.hapInfoParameter.bundleName.c_str());
    AccessTokenIDEx tokenIdEx;
    tokenIdEx.tokenIDEx = 0LL;

    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(tokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", tokenID);
        fullTokenId = static_cast<uint64_t>(tokenIdEx.tokenIDEx);
        return ERR_OK;
    }

    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info.hapInfoParameter, policy.hapPolicy, tokenIdEx);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Hap token info create failed");
    }
    fullTokenId = static_cast<uint64_t>(tokenIdEx.tokenIDEx);
    return ERR_OK;
}

static void TransferHapPolicy(const HapPolicy& policyIn, HapPolicy& policyOut)
{
    policyOut.apl = policyIn.apl;
    policyOut.domain = policyIn.domain;
    policyOut.permList.assign(policyIn.permList.begin(), policyIn.permList.end());
    policyOut.aclRequestedList.assign(policyIn.aclRequestedList.begin(), policyIn.aclRequestedList.end());
    policyOut.preAuthorizationInfo.assign(policyIn.preAuthorizationInfo.begin(), policyIn.preAuthorizationInfo.end());
    for (const auto& perm : policyIn.permStateList) {
        PermissionStatus tmp;
        tmp.permissionName = perm.permissionName;
        tmp.grantStatus = perm.grantStatus;
        tmp.grantFlag = perm.grantFlag;
        policyOut.permStateList.emplace_back(tmp);
    }
    policyOut.checkIgnore = policyIn.checkIgnore;
    policyOut.aclExtendedMap = policyIn.aclExtendedMap;
}

int32_t AccessTokenManagerService::InitHapToken(const HapInfoParcel& info, const HapPolicyParcel& policy,
    uint64_t& fullTokenId, HapInfoCheckResultIdl& resultInfoIdl)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Init hap %{public}s.", info.hapInfoParameter.bundleName.c_str());
    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(tokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", tokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    HapPolicyParcel policyCopy;
    TransferHapPolicy(policy.hapPolicy, policyCopy.hapPolicy);

    resultInfoIdl.realResult = ERR_OK;
    std::vector<PermissionStatus> initializedList;
    if (info.hapInfoParameter.dlpType == DLP_COMMON) {
        HapInfoCheckResult permCheckResult;
        if (!PermissionManager::GetInstance().InitPermissionList(info.hapInfoParameter.appDistributionType,
            policyCopy.hapPolicy, initializedList, permCheckResult)) {
            resultInfoIdl.realResult = ERROR;
            resultInfoIdl.permissionName = permCheckResult.permCheckResult.permissionName;
            int32_t rule = permCheckResult.permCheckResult.rule;
            resultInfoIdl.rule = static_cast<PermissionRulesEnumIdl>(rule);
            return ERR_OK;
        }
    } else {
        if (!PermissionManager::GetInstance().InitDlpPermissionList(
            info.hapInfoParameter.bundleName, info.hapInfoParameter.userID, initializedList)) {
            return ERR_PERM_REQUEST_CFG_FAILED;
        }
    }
    policyCopy.hapPolicy.permStateList = initializedList;

    AccessTokenIDEx tokenIdEx;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info.hapInfoParameter, policyCopy.hapPolicy, tokenIdEx);
    fullTokenId = tokenIdEx.tokenIDEx;
    if (ret != RET_SUCCESS) {
        return ret;
    }

    return ret;
}

int AccessTokenManagerService::DeleteToken(AccessTokenID tokenID)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d", tokenID);
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(callingTokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    if (this->GetTokenType(tokenID) != TOKEN_HAP) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    // only support hap token deletion
    return AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
}

int AccessTokenManagerService::GetTokenType(AccessTokenID tokenID)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d", tokenID);
    return AccessTokenIDManager::GetInstance().GetTokenIdType(tokenID);
}

int AccessTokenManagerService::GetTokenType(AccessTokenID tokenID, int32_t& tokenType)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d", tokenID);
    tokenType = AccessTokenIDManager::GetInstance().GetTokenIdType(tokenID);
    return ERR_OK;
}

int32_t AccessTokenManagerService::GetHapTokenID(
    int32_t userID, const std::string& bundleName, int32_t instIndex, uint64_t& fullTokenId)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "UserID: %{public}d, bundle: %{public}s, instIndex: %{public}d",
        userID, bundleName.c_str(), instIndex);
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());

        AccessTokenIDEx tokenIdEx = {0};
        fullTokenId = tokenIdEx.tokenIDEx;
        return ERR_OK;
    }
    AccessTokenIDEx tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(userID, bundleName, instIndex);
    fullTokenId = tokenIdEx.tokenIDEx;
    return ERR_OK;
}

int32_t AccessTokenManagerService::AllocLocalTokenID(
    const std::string& remoteDeviceID, AccessTokenID remoteTokenID, AccessTokenID& tokenId)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RemoteDeviceID: %{public}s, remoteTokenID: %{public}d",
        ConstantCommon::EncryptDevId(remoteDeviceID).c_str(), remoteTokenID);
    if ((!IsNativeProcessCalling()) && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        tokenId = INVALID_TOKENID;
        return ERR_OK;
    }
    AccessTokenID tokenID = AccessTokenInfoManager::GetInstance().AllocLocalTokenID(remoteDeviceID, remoteTokenID);
    tokenId = tokenID;
    return ERR_OK;
}

int32_t AccessTokenManagerService::UpdateHapToken(uint64_t& fullTokenId, const UpdateHapInfoParamsIdl& infoIdl,
    const HapPolicyParcel& policyParcel, HapInfoCheckResultIdl& resultInfoIdl)
{
    AccessTokenIDEx tokenIdEx;
    tokenIdEx.tokenIDEx = fullTokenId;
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d", tokenIdEx.tokenIdExStruct.tokenID);
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(callingTokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    UpdateHapInfoParams info;
    info.appIDDesc = infoIdl.appIDDesc;
    info.apiVersion = infoIdl.apiVersion;
    info.isSystemApp = infoIdl.isSystemApp;
    info.appDistributionType = infoIdl.appDistributionType;
    std::vector<PermissionStatus> InitializedList;

    resultInfoIdl.realResult = ERR_OK;
    HapInfoCheckResult permCheckResult;
    if (!PermissionManager::GetInstance().InitPermissionList(
        info.appDistributionType, policyParcel.hapPolicy, InitializedList, permCheckResult)) {
        resultInfoIdl.realResult = ERROR;
        resultInfoIdl.permissionName = permCheckResult.permCheckResult.permissionName;
        int32_t rule = permCheckResult.permCheckResult.rule;
        resultInfoIdl.rule = static_cast<PermissionRulesEnumIdl>(rule);
        return ERR_OK;
    }
    int32_t ret = AccessTokenInfoManager::GetInstance().UpdateHapToken(tokenIdEx, info,
        InitializedList, policyParcel.hapPolicy);
    fullTokenId = tokenIdEx.tokenIDEx;
    return ret;
}
int32_t AccessTokenManagerService::GetTokenIDByUserID(int32_t userID, std::vector<AccessTokenID>& tokenIds)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "UserID: %{public}d", userID);

    if (!IsNativeProcessCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    std::unordered_set<AccessTokenID> tokenIdList;

    auto result = AccessTokenInfoManager::GetInstance().GetTokenIDByUserID(userID, tokenIdList);
    std::copy(tokenIdList.begin(), tokenIdList.end(), std::back_inserter(tokenIds));
    return result;
}

int AccessTokenManagerService::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& infoParcel)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d", tokenID);

    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    return AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, infoParcel.hapTokenInfoParams);
}

int AccessTokenManagerService::GetHapTokenInfoExtension(AccessTokenID tokenID,
    HapTokenInfoParcel& hapTokenInfoRes, std::string& appID)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d.", tokenID);
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    int ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, hapTokenInfoRes.hapTokenInfoParams);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get hap token info extenstion failed, ret is %{public}d.", ret);
        return ret;
    }

    return AccessTokenInfoManager::GetInstance().GetHapAppIdByTokenId(tokenID, appID);
}

int AccessTokenManagerService::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& infoParcel)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d", tokenID);

    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d).", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    NativeTokenInfoBase baseInfo;
    int32_t ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(tokenID, baseInfo);
    infoParcel.nativeTokenInfoParams.apl = baseInfo.apl;
    infoParcel.nativeTokenInfoParams.processName = baseInfo.processName;
    return ret;
}

#ifndef ATM_BUILD_VARIANT_USER_ENABLE
int32_t AccessTokenManagerService::ReloadNativeTokenInfo()
{
    if (!IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    LibraryLoader loader(CONFIG_PARSE_LIBPATH);
    ConfigPolicyLoaderInterface* policy = loader.GetObject<ConfigPolicyLoaderInterface>();
    if (policy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Dlopen libaccesstoken_json_parse failed.");
        return RET_FAILED;
    }

    std::vector<NativeTokenInfoBase> tokenInfos;
    int32_t res = policy->GetAllNativeTokenInfo(tokenInfos);
    if (res != RET_SUCCESS) {
        return res;
    }

    AccessTokenInfoManager::GetInstance().InitNativeTokenInfos(tokenInfos);
    return RET_SUCCESS;
}
#endif

int32_t AccessTokenManagerService::GetNativeTokenId(const std::string& processName, AccessTokenID& tokenID)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        tokenID = INVALID_TOKENID;
        return ERR_OK;
    }
    tokenID = AccessTokenInfoManager::GetInstance().GetNativeTokenId(processName);
    return ERR_OK;
}

#ifdef TOKEN_SYNC_ENABLE
int AccessTokenManagerService::GetHapTokenInfoFromRemote(AccessTokenID tokenID,
    HapTokenInfoForSyncParcel& hapSyncParcel)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d", tokenID);

    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return AccessTokenInfoManager::GetInstance().GetHapTokenInfoFromRemote(tokenID,
        hapSyncParcel.hapTokenInfoForSyncParams);
}

static void TransferHapTokenInfoForSync(const HapTokenInfoForSync& policyIn, HapTokenInfoForSync& policyOut)
{
    policyOut.baseInfo.ver = policyIn.baseInfo.ver;
    policyOut.baseInfo.userID = policyIn.baseInfo.userID;
    policyOut.baseInfo.bundleName = policyIn.baseInfo.bundleName;
    policyOut.baseInfo.apiVersion = policyIn.baseInfo.apiVersion;
    policyOut.baseInfo.instIndex = policyIn.baseInfo.instIndex;
    policyOut.baseInfo.dlpType = policyIn.baseInfo.dlpType;
    policyOut.baseInfo.tokenID = policyIn.baseInfo.tokenID;
    policyOut.baseInfo.tokenAttr = policyIn.baseInfo.tokenAttr;
    for (const auto& item : policyIn.permStateList) {
        PermissionStatus tmp;
        tmp.permissionName = item.permissionName;
        tmp.grantStatus = item.grantStatus;
        tmp.grantFlag = item.grantFlag;
        policyOut.permStateList.emplace_back(tmp);
    }
}

int AccessTokenManagerService::SetRemoteHapTokenInfo(const std::string& deviceID,
    const HapTokenInfoForSyncParcel& hapSyncParcel)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeviceID: %{public}s", ConstantCommon::EncryptDevId(deviceID).c_str());

    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    HapTokenInfoForSyncParcel hapSyncParcelCopy;
    TransferHapTokenInfoForSync(hapSyncParcel.hapTokenInfoForSyncParams, hapSyncParcelCopy.hapTokenInfoForSyncParams);

    int ret = AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(deviceID,
        hapSyncParcelCopy.hapTokenInfoForSyncParams);
    return ret;
}

int AccessTokenManagerService::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeviceID: %{public}s, token id %{public}d",
        ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID);

    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceID, tokenID);
}

int32_t AccessTokenManagerService::GetRemoteNativeTokenID(const std::string& deviceID,
    AccessTokenID tokenID, AccessTokenID& tokenId)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeviceID: %{public}s, token id %{public}d",
        ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID);

    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        tokenId = INVALID_TOKENID;
        return ERR_OK;
    }
    tokenId = AccessTokenInfoManager::GetInstance().GetRemoteNativeTokenID(deviceID, tokenID);
    return ERR_OK;
}

int AccessTokenManagerService::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeviceID: %{public}s", ConstantCommon::EncryptDevId(deviceID).c_str());

    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(deviceID);
}

int32_t AccessTokenManagerService::RegisterTokenSyncCallback(const sptr<IRemoteObject>& callback)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Call token sync callback registed.");

    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied, tokenID=%{public}d", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return TokenModifyNotifier::GetInstance().RegisterTokenSyncCallback(callback);
}

int32_t AccessTokenManagerService::UnRegisterTokenSyncCallback()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Call token sync callback unregisted.");

    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied, tokenID=%{public}d", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return TokenModifyNotifier::GetInstance().UnRegisterTokenSyncCallback();
}
#endif

int32_t AccessTokenManagerService::DumpTokenInfo(const AtmToolsParamInfoParcel& infoParcel, std::string& dumpInfo)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Called");
    if (!IsShellProcessCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        dumpInfo = "";
        return ERR_OK;
    }

    bool isDeveloperMode = OHOS::system::GetBoolParameter(DEVELOPER_MODE_STATE, false);
    if (!isDeveloperMode) {
        dumpInfo = "Developer mode not support.";
        return ERR_OK;
    }

    AccessTokenInfoManager::GetInstance().DumpTokenInfo(infoParcel.info, dumpInfo);
    return ERR_OK;
}

int32_t AccessTokenManagerService::GetVersion(uint32_t& version)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Called");
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingToken) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    version = DEFAULT_TOKEN_VERSION;
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::SetPermDialogCap(const HapBaseInfoParcel& hapBaseInfoParcel, bool enable)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, DISABLE_PERMISSION_DIALOG) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    AccessTokenIDEx tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(
        hapBaseInfoParcel.hapBaseInfo.userID,
        hapBaseInfoParcel.hapBaseInfo.bundleName,
        hapBaseInfoParcel.hapBaseInfo.instIndex);
    int32_t ret = AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenIdEx.tokenIdExStruct.tokenID, enable);
    // DFX
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "SET_PERMISSION_DIALOG_CAP",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "TOKENID", tokenIdEx.tokenIdExStruct.tokenID,
        "USERID", hapBaseInfoParcel.hapBaseInfo.userID, "BUNDLENAME", hapBaseInfoParcel.hapBaseInfo.bundleName,
        "INSTINDEX", hapBaseInfoParcel.hapBaseInfo.instIndex, "ENABLE", enable);
    return ret;
}

int32_t AccessTokenManagerService::GetPermissionManagerInfo(PermissionGrantInfoParcel& infoParcel)
{
    infoParcel.info.grantBundleName = grantBundleName_;
    infoParcel.info.grantAbilityName = grantAbilityName_;
    infoParcel.info.grantServiceAbilityName = grantServiceAbilityName_;
    infoParcel.info.permStateAbilityName = permStateAbilityName_;
    infoParcel.info.globalSwitchAbilityName = globalSwitchAbilityName_;
    return ERR_OK;
}

int32_t AccessTokenManagerService::InitUserPolicy(
    const std::vector<UserStateIdl>& userIdlList, const std::vector<std::string>& permList)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    uint32_t userSize = userIdlList.size();
    uint32_t permSize = permList.size();
    if ((userSize > MAX_USER_POLICY_SIZE) || (permSize > MAX_USER_POLICY_SIZE)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Size %{public}u is invalid", userSize);
        return AccessTokenError::ERR_OVERSIZE;
    }

    std::vector<UserState> userList;
    for (const auto& item : userIdlList) {
        UserState tmp;
        tmp.userId = item.userId;
        tmp.isActive = item.isActive;
        userList.emplace_back(tmp);
    }
    return AccessTokenInfoManager::GetInstance().InitUserPolicy(userList, permList);
}

int32_t AccessTokenManagerService::UpdateUserPolicy(const std::vector<UserStateIdl>& userIdlList)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    uint32_t userSize = userIdlList.size();
    if (userSize > MAX_USER_POLICY_SIZE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Size %{public}u is invalid", userSize);
        return AccessTokenError::ERR_OVERSIZE;
    }

    std::vector<UserState> userList;
    for (const auto& item : userIdlList) {
        UserState tmp;
        tmp.userId = item.userId;
        tmp.isActive = item.isActive;
        userList.emplace_back(tmp);
    }
    return AccessTokenInfoManager::GetInstance().UpdateUserPolicy(userList);
}

int32_t AccessTokenManagerService::ClearUserPolicy()
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    return AccessTokenInfoManager::GetInstance().ClearUserPolicy();
}

int AccessTokenManagerService::Dump(int fd, const std::vector<std::u16string>& args)
{
    if (fd < 0) {
        return ERR_INVALID_VALUE;
    }

    dprintf(fd, "AccessToken Dump:\n");
    std::string arg0 = ((args.size() == 0)? "" : Str16ToStr8(args.at(0)));
    if (arg0.compare("-h") == 0) {
        dprintf(fd, "Usage:\n");
        dprintf(fd, "       -h: command help\n");
        dprintf(fd, "       -a: dump all tokens\n");
        dprintf(fd, "       -t <TOKEN_ID>: dump special token id\n");
    } else if (arg0.compare("-t") == 0) {
        if (args.size() < TWO_ARGS) {
            return ERR_INVALID_VALUE;
        }
        long long tokenID = atoll(static_cast<const char *>(Str16ToStr8(args.at(1)).c_str()));
        if (tokenID <= 0) {
            return ERR_INVALID_VALUE;
        }
        AtmToolsParamInfoParcel infoParcel;
        infoParcel.info.tokenId = static_cast<AccessTokenID>(tokenID);
        std::string dumpStr;
        DumpTokenInfo(infoParcel, dumpStr);
        dprintf(fd, "%s\n", dumpStr.c_str());
    }  else if (arg0.compare("-a") == 0 || arg0 == "") {
        std::string dumpStr;
        AtmToolsParamInfoParcel infoParcel;
        DumpTokenInfo(infoParcel, dumpStr);
        dprintf(fd, "%s\n", dumpStr.c_str());
    }
    return ERR_OK;
}

void AccessTokenManagerService::AccessTokenServiceParamSet() const
{
    int32_t res = SetParameter(ACCESS_TOKEN_SERVICE_INIT_KEY, std::to_string(1).c_str());
    if (res != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SetParameter ACCESS_TOKEN_SERVICE_INIT_KEY 1 failed %{public}d", res);
        return;
    }
    // 2 is to tell others sa that at service is loaded.
    res = SetParameter(ACCESS_TOKEN_SERVICE_INIT_KEY, std::to_string(2).c_str());
    if (res != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SetParameter ACCESS_TOKEN_SERVICE_INIT_KEY 2 failed %{public}d", res);
        return;
    }
}

void AccessTokenManagerService::GetConfigValue()
{
    LibraryLoader loader(CONFIG_PARSE_LIBPATH);
    ConfigPolicyLoaderInterface* policy = loader.GetObject<ConfigPolicyLoaderInterface>();
    if (policy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Dlopen libaccesstoken_json_parse failed.");
        return;
    }
    AccessTokenConfigValue value;
    if (policy->GetConfigValue(ServiceType::ACCESSTOKEN_SERVICE, value)) {
        // set value from config
        grantBundleName_ = value.atConfig.grantBundleName.empty() ?
            GRANT_ABILITY_BUNDLE_NAME : value.atConfig.grantBundleName;
        grantAbilityName_ = value.atConfig.grantAbilityName.empty() ?
            GRANT_ABILITY_ABILITY_NAME : value.atConfig.grantAbilityName;
        grantServiceAbilityName_ = value.atConfig.grantServiceAbilityName.empty() ?
            GRANT_ABILITY_ABILITY_NAME : value.atConfig.grantServiceAbilityName;
        permStateAbilityName_ = value.atConfig.permStateAbilityName.empty() ?
            PERMISSION_STATE_SHEET_ABILITY_NAME : value.atConfig.permStateAbilityName;
        globalSwitchAbilityName_ = value.atConfig.globalSwitchAbilityName.empty() ?
            GLOBAL_SWITCH_SHEET_ABILITY_NAME : value.atConfig.globalSwitchAbilityName;
        applicationSettingAbilityName_ = value.atConfig.applicationSettingAbilityName.empty() ?
            APPLICATION_SETTING_ABILITY_NAME : value.atConfig.applicationSettingAbilityName;
        TempPermissionObserver::GetInstance().SetCancelTime(value.atConfig.cancleTime);
    } else {
        LOGI(ATM_DOMAIN, ATM_TAG, "No config file or config file is not valid, use default values");
        grantBundleName_ = GRANT_ABILITY_BUNDLE_NAME;
        grantAbilityName_ = GRANT_ABILITY_ABILITY_NAME;
        grantServiceAbilityName_ = GRANT_ABILITY_ABILITY_NAME;
        permStateAbilityName_ = PERMISSION_STATE_SHEET_ABILITY_NAME;
        globalSwitchAbilityName_ = GLOBAL_SWITCH_SHEET_ABILITY_NAME;
        applicationSettingAbilityName_ = APPLICATION_SETTING_ABILITY_NAME;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "GrantBundleName_ is %{public}s, grantAbilityName_ is %{public}s, "
        "grantServiceAbilityName_ is %{public}s, permStateAbilityName_ is %{public}s, "
        "globalSwitchAbilityName_ is %{public}s, applicationSettingAbilityName_ is %{public}s.",
        grantBundleName_.c_str(), grantAbilityName_.c_str(), grantServiceAbilityName_.c_str(),
        permStateAbilityName_.c_str(), globalSwitchAbilityName_.c_str(), applicationSettingAbilityName_.c_str());
}

int32_t AccessTokenManagerService::GetKernelPermissions(
    AccessTokenID tokenId, std::vector<PermissionWithValueIdl>& kernelPermIdlList)
{
    auto callingToken = IPCSkeleton::GetCallingTokenID();
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    std::vector<PermissionWithValue> kernelPermList;
    auto result = AccessTokenInfoManager::GetInstance().GetKernelPermissions(tokenId, kernelPermList);
    for (const auto& item : kernelPermList) {
        PermissionWithValueIdl tmp;
        tmp.permissionName = item.permissionName;
        tmp.value = item.value;
        kernelPermIdlList.emplace_back(tmp);
    }
    return result;
}

int32_t AccessTokenManagerService::GetReqPermissionByName(
    AccessTokenID tokenId, const std::string& permissionName, std::string& value)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission denied(tokenID=%{public}d)", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return AccessTokenInfoManager::GetInstance().GetReqPermissionByName(
        tokenId, permissionName, value);
}

bool AccessTokenManagerService::Initialize()
{
    MemoryGuard guard;
    ReportSysEventPerformance();
    AccessTokenInfoManager::GetInstance().Init();

#ifdef EVENTHANDLER_ENABLE
    TempPermissionObserver::GetInstance().InitEventHandler();
    ShortGrantManager::GetInstance().InitEventHandler();
#endif
    GetConfigValue();
    LOGI(ATM_DOMAIN, ATM_TAG, "Initialize success");
    return true;
}

bool AccessTokenManagerService::IsPrivilegedCalling() const
{
    // shell process is root in debug mode.
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return callingUid == ROOT_UID;
#else
    return false;
#endif
}

bool AccessTokenManagerService::IsAccessTokenCalling()
{
    uint32_t tokenCaller = IPCSkeleton::GetCallingTokenID();
    if (tokenSyncId_ == 0) {
        this->GetNativeTokenId("token_sync_service", tokenSyncId_);
    }
    return tokenCaller == tokenSyncId_;
}

bool AccessTokenManagerService::IsNativeProcessCalling()
{
    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    return this->GetTokenType(tokenCaller) == TOKEN_NATIVE;
}

bool AccessTokenManagerService::IsShellProcessCalling()
{
    AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    return this->GetTokenType(tokenCaller) == TOKEN_SHELL;
}

bool AccessTokenManagerService::IsSystemAppCalling() const
{
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    return TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
bool AccessTokenManagerService::IsSecCompServiceCalling()
{
    uint32_t tokenCaller = IPCSkeleton::GetCallingTokenID();
    if (secCompTokenId_ == 0) {
        this->GetNativeTokenId("security_component_service", secCompTokenId_);
    }
    return tokenCaller == secCompTokenId_;
}
#endif

int32_t AccessTokenManagerService::CallbackEnter(uint32_t code)
{
    ClearThreadErrorMsg();
#ifdef HICOLLIE_ENABLE
    std::string name = "AtmTimer";
    g_timerId = HiviewDFX::XCollie::GetInstance().SetTimer(name, TIMEOUT, nullptr, nullptr,
        HiviewDFX::XCOLLIE_FLAG_LOG);
#endif // HICOLLIE_ENABLE
    return ERR_OK;
}

int32_t AccessTokenManagerService::CallbackExit(uint32_t code, int32_t result)
{
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(g_timerId);
#endif // HICOLLIE_ENABLE
    ReportSysCommonEventError(code, 0);
    return ERR_OK;
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
int32_t AccessTokenManagerService::RegisterSecCompEnhance(const SecCompEnhanceDataParcel& enhanceParcel)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Pid: %{public}d", enhanceParcel.enhanceData.pid);
    return SecCompEnhanceAgent::GetInstance().RegisterSecCompEnhance(enhanceParcel.enhanceData);
}

int32_t AccessTokenManagerService::UpdateSecCompEnhance(int32_t pid, uint32_t seqNum)
{
    if (!IsSecCompServiceCalling()) {
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    return SecCompEnhanceAgent::GetInstance().UpdateSecCompEnhance(pid, seqNum);
}

int32_t AccessTokenManagerService::GetSecCompEnhance(int32_t pid, SecCompEnhanceDataParcel& enhanceParcel)
{
    if (!IsSecCompServiceCalling()) {
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    SecCompEnhanceData enhanceData;
    int32_t res = SecCompEnhanceAgent::GetInstance().GetSecCompEnhance(pid, enhanceData);
    if (res != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Pid: %{public}d get enhance failed ", pid);
        return res;
    }

    enhanceParcel.enhanceData = enhanceData;
    return RET_SUCCESS;
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
