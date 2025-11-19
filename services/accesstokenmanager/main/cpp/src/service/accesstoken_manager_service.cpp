/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <stack>
#include <unistd.h>

#include "access_token.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_service_ipc_interface_code.h"
#include "constant_common.h"
#include "data_usage_dfx.h"
#include "data_validator.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "hisysevent_adapter.h"
#ifdef HITRACE_NATIVE_ENABLE
#include "hitrace_meter.h"
#endif
#include "ipc_skeleton.h"
#include "libraryloader.h"
#include "memory_guard.h"
#include "parameter.h"
#include "parameters.h"
#include "permission_list_state.h"
#include "permission_manager.h"
#include "permission_validator.h"
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
#include "sec_comp_enhance_agent.h"
#include "sec_comp_raw_data.h"
#endif
#include "short_grant_manager.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "time_util.h"
#include "tokenid_attributes.h"
#include "token_field_const.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_modify_notifier.h"
#endif // TOKEN_SYNC_ENABLE
#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const char* ACCESS_TOKEN_SERVICE_INIT_KEY = "accesstoken.permission.init";
constexpr int32_t ERROR = -1;
const char* GRANT_ABILITY_BUNDLE_NAME = "com.ohos.permissionmanager";
const char* GRANT_ABILITY_ABILITY_NAME = "com.ohos.permissionmanager.GrantAbility";
const char* PERMISSION_STATE_SHEET_ABILITY_NAME = "com.ohos.permissionmanager.PermissionStateSheetAbility";
const char* GLOBAL_SWITCH_SHEET_ABILITY_NAME = "com.ohos.permissionmanager.GlobalSwitchSheetAbility";
const char* APPLICATION_SETTING_ABILITY_NAME = "com.ohos.permissionmanager.MainAbility";
const char* OPEN_SETTING_ABILITY_NAME = "com.ohos.permissionmanager.OpenSettingAbility";
const char* DEVELOPER_MODE_STATE = "const.security.developermode.state";

const std::string MANAGE_HAP_TOKENID_PERMISSION = "ohos.permission.MANAGE_HAP_TOKENID";
static constexpr int MAX_PERMISSION_SIZE = 1024;
static constexpr int32_t MAX_USER_POLICY_SIZE = 1024;
const std::string GRANT_SENSITIVE_PERMISSIONS = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
const std::string REVOKE_SENSITIVE_PERMISSIONS = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS";
const std::string GET_SENSITIVE_PERMISSIONS = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
const std::string DISABLE_PERMISSION_DIALOG = "ohos.permission.DISABLE_PERMISSION_DIALOG";
const std::string GRANT_SHORT_TERM_WRITE_MEDIAVIDEO = "ohos.permission.GRANT_SHORT_TERM_WRITE_MEDIAVIDEO";
const std::string MANAGE_EDM_POLICY = "ohos.permission.MANAGE_EDM_POLICY";

static constexpr int32_t SA_ID_ACCESSTOKEN_MANAGER_SERVICE = 3503;

#ifdef HICOLLIE_ENABLE
constexpr uint32_t TIMEOUT = 40; // 40s
thread_local std::stack<int32_t> g_timerIdStack;
#endif // HICOLLIE_ENABLE

constexpr uint32_t BITMAP_INDEX_1 = 1;
constexpr uint32_t BITMAP_INDEX_2 = 2;
constexpr uint32_t BITMAP_INDEX_3 = 3;
constexpr uint32_t BITMAP_INDEX_4 = 4;
constexpr uint32_t BITMAP_INDEX_5 = 5;
constexpr uint32_t BITMAP_INDEX_6 = 6;
constexpr uint32_t BITMAP_INDEX_7 = 7;
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
    std::lock_guard<std::mutex> lock(stateMutex_);
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
    std::lock_guard<std::mutex> lock(stateMutex_);
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
    LOGI(ATM_DOMAIN, ATM_TAG, "Id %{public}d, perm %{public}s, callerPid %{public}d.",
        tokenID, permissionName.c_str(), IPCSkeleton::GetCallingPid());
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
        permUsedType = static_cast<int32_t>(PermUsedTypeEnum::INVALID_USED_TYPE);
        return permUsedType;
    }
    permUsedType = static_cast<int32_t>(
        PermissionManager::GetInstance().GetPermissionUsedType(tokenID, permissionName));
    return ERR_OK;
}

int32_t AccessTokenManagerService::VerifyAccessToken(
    AccessTokenID tokenID, const std::string& permissionName, int32_t& state)
{
    state = VerifyAccessToken(tokenID, permissionName);
    return RET_SUCCESS;
}

int AccessTokenManagerService::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
#ifdef HITRACE_NATIVE_ENABLE
    StartTraceEx(HiTraceOutputLevel::HITRACE_LEVEL_DEBUG, HITRACE_TAG_ACCESS_CONTROL, "AccessTokenVerifyPermission");
#endif
    int32_t res = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, permissionName);
    LOGD(ATM_DOMAIN, ATM_TAG, "Id %{public}d, perm %{public}s, res %{public}d.",
        tokenID, permissionName.c_str(), res);
    if ((res == PERMISSION_GRANTED) &&
        (TokenIDAttributes::GetTokenIdTypeEnum(tokenID) == TOKEN_HAP)) {
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
    LOGI(ATM_DOMAIN, ATM_TAG, "Perm %{public}s, callerPid %{public}d.",
        permissionName.c_str(), IPCSkeleton::GetCallingPid());

    // for ipc call not by accesstoken client
    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm is invalid.");
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
    int32_t res = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, conditionValue, results);
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
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

int32_t AccessTokenManagerService::GetSelfPermissionStatus(const std::string& permissionName, int32_t& status)
{
    status = INVALID_OPER;
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    PermissionListStateParcel parcel;
    parcel.permsState.permissionName = permissionName;
    parcel.permsState.state = INVALID_OPER;
    std::vector<PermissionListStateParcel> list{parcel};
    (void)GetPermissionsState(callingTokenID, list);
    if (!list.empty()) {
        status = static_cast<int32_t>(list[0].permsState.state);
    }
    return ERR_OK;
}

int32_t AccessTokenManagerService::GetSelfPermissionsState(std::vector<PermissionListStateParcel>& reqPermList,
    PermissionGrantInfoParcel& infoParcel, int32_t& permOper)
{
    uint32_t size = reqPermList.size();
    if (size > MAX_PERMISSION_SIZE) {
        for (auto& perm: reqPermList) {
            perm.permsState.state = INVALID_OPER;
            perm.permsState.errorReason = PERM_INVALID;
        }
        LOGE(ATM_DOMAIN, ATM_TAG, "PermList size %{public}d is invalid.", size);
        return INVALID_OPER;
    }
    LOGI(ATM_DOMAIN, ATM_TAG,
        "Bundle %{public}s, uiExAbility %{public}s, serExAbility %{public}s, callerPid %{public}d.",
        grantBundleName_.c_str(), grantAbilityName_.c_str(), grantServiceAbilityName_.c_str(),
        IPCSkeleton::GetCallingPid());
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    uint32_t size = reqPermList.size();
    if (size > MAX_PERMISSION_SIZE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermList size %{public}d is invalid.", size);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    if (!AccessTokenInfoManager::GetInstance().IsTokenIdExist(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id %{public}d does not exist.", tokenID);
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
            "GetReqPermissions failed, retUserGrant %{public}d, retSysGrant %{public}d.",
            retUserGrant, retSysGrant);
        return false;
    }
    return true;
}

bool AccessTokenManagerService::isLocationPermSpecialHandle(std::string permissionName, int32_t apiVersion)
{
    return ((permissionName == VAGUE_LOCATION_PERMISSION_NAME) ||
            (permissionName == ACCURATE_LOCATION_PERMISSION_NAME) ||
            (permissionName == BACKGROUND_LOCATION_PERMISSION_NAME)) &&
        (apiVersion >= ACCURATE_LOCATION_API_VERSION);
}

PermissionOper AccessTokenManagerService::GetPermissionsState(AccessTokenID tokenID,
    std::vector<PermissionListStateParcel>& reqPermList)
{
    int32_t apiVersion = 0;
    if (!PermissionManager::GetInstance().GetApiVersionByTokenId(tokenID, apiVersion)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get api version error.");
        return INVALID_OPER;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Id %{public}d, api %{public}d.", tokenID, apiVersion);

    bool needRes = false;
    bool fixedByPolicyRes = false;
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
        if (isLocationPermSpecialHandle(reqPermList[i].permsState.permissionName, apiVersion)) {
            continue;
        }

        PermissionManager::GetInstance().GetSelfPermissionState(permsList, reqPermList[i].permsState, apiVersion);
        needRes = (static_cast<PermissionOper>(reqPermList[i].permsState.state) == DYNAMIC_OPER) ? true : needRes;
        if (static_cast<PermissionOper>(reqPermList[i].permsState.state) == FORBIDDEN_OPER) {
            fixedByPolicyRes = true;
        }
        LOGD(ATM_DOMAIN, ATM_TAG, "Perm %{public}s, state %{public}d, errorReason %{public}d.",
            reqPermList[i].permsState.permissionName.c_str(), reqPermList[i].permsState.state,
            reqPermList[i].permsState.errorReason);
    }
    if (GetTokenType(tokenID) == TOKEN_HAP && AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id %{public}d is under control.", tokenID);
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
    if (fixedByPolicyRes) {
        return FORBIDDEN_OPER;
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
        VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED &&
        VerifyAccessToken(callingTokenID, MANAGE_EDM_POLICY) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
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
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR, "CALLER_TOKENID",
            callingTokenID, "PERMISSION_NAME", permissionName, "INTERFACE", "SetToggleStatus");
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
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
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR, "CALLER_TOKENID",
            callingTokenID, "PERMISSION_NAME", permissionName, "INTERFACE", "GetToggleStatus");
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
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
        LOGE(ATM_DOMAIN, ATM_TAG, "GetHapTokenInfo failed, err %{public}d.", ret);
        return ret;
    }
    return PermissionManager::GetInstance().RequestAppPermOnSetting(hapInfo,
        grantBundleName_, applicationSettingAbilityName_);
}

int AccessTokenManagerService::GrantPermission(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t flag, int32_t updateFlag)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GRANT_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callingTokenID, "PERMISSION_NAME", permissionName);
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    int32_t ret = PermissionManager::GetInstance().GrantPermission(
        tokenID, permissionName, flag, static_cast<UpdatePermissionFlag>(updateFlag));
    return ret;
}

int AccessTokenManagerService::RevokePermission(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t flag, int32_t updateFlag)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callingTokenID, "PERMISSION_NAME", permissionName);
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    return PermissionManager::GetInstance().RevokePermission(
        tokenID, permissionName, flag, static_cast<UpdatePermissionFlag>(updateFlag));
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
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callingTokenID, "PERMISSION_NAME", permissionName);
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    int32_t ret = PermissionManager::GetInstance().GrantPermissionForSpecifiedTime(tokenID, permissionName, onceTime);
    return ret;
}

int AccessTokenManagerService::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d, callerPid %{public}d.", tokenID, IPCSkeleton::GetCallingPid());
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR,
            "CALLER_TOKENID", callingTokenID);
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    AccessTokenInfoManager::GetInstance().ClearUserGrantedPermissionState(tokenID);
    AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenID, false);
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::SetPermissionStatusWithPolicy(
    AccessTokenID tokenID, const std::vector<std::string>& permissionList, int32_t status, uint32_t flag)
{
    LOGI(ATM_DOMAIN, ATM_TAG,
        "Id %{public}d, permList size %{public}zu, status %{public}d, flag %{public}u, callerPid %{public}d.",
        tokenID, permissionList.size(), status, flag, IPCSkeleton::GetCallingPid());
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, MANAGE_EDM_POLICY) == PERMISSION_DENIED) {
        (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_VERIFY_REPORT",
            HiviewDFX::HiSysEvent::EventType::SECURITY, "CODE", VERIFY_PERMISSION_ERROR, "CALLER_TOKENID",
            callingTokenID);
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    if (!DataValidator::IsPermissionListSizeValid(permissionList)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermList size is invalid: %{public}zu.", permissionList.size());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return PermissionManager::GetInstance().SetPermissionStatusWithPolicy(tokenID, permissionList, status, flag);
}

int32_t AccessTokenManagerService::RegisterPermStateChangeCallback(
    const PermStateChangeScopeParcel& scope, const sptr<IRemoteObject>& callback)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    if (VerifyAccessToken(callingTokenID, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingToken);

        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return PermissionManager::GetInstance().RemovePermStateChangeCallback(callback);
}

int32_t AccessTokenManagerService::RegisterSelfPermStateChangeCallback(
    const PermStateChangeScopeParcel& scope, const sptr<IRemoteObject>& callback)
{
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (this->GetTokenType(callingTokenID) != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id is not hap.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return PermissionManager::GetInstance().AddPermStateChangeCallback(scope.scope, callback);
}

int32_t AccessTokenManagerService::UnRegisterSelfPermStateChangeCallback(const sptr<IRemoteObject>& callback)
{
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (this->GetTokenType(callingToken) != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id is not hap.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return PermissionManager::GetInstance().RemovePermStateChangeCallback(callback);
}

int32_t AccessTokenManagerService::AllocHapToken(const HapInfoParcel& info, const HapPolicyParcel& policy,
    uint64_t& fullTokenId)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Bundle %{public}s, callerPid %{public}d.",
        info.hapInfoParameter.bundleName.c_str(), IPCSkeleton::GetCallingPid());
    AccessTokenIDEx tokenIdEx;
    tokenIdEx.tokenIDEx = 0LL;

    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(tokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", tokenID);
        fullTokenId = static_cast<uint64_t>(tokenIdEx.tokenIDEx);
        return ERR_OK;
    }

    std::vector<GenericValues> undefValues;
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info.hapInfoParameter, policy.hapPolicy, tokenIdEx, undefValues);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Hap token info create failed.");
    }
    fullTokenId = static_cast<uint64_t>(tokenIdEx.tokenIDEx);
    return ERR_OK;
}

static void TransferHapPolicy(const HapPolicyParcel& policyIn, HapPolicy& policyOut)
{
    policyOut.apl = policyIn.hapPolicy.apl;
    policyOut.domain = policyIn.hapPolicy.domain;
    policyOut.permList.assign(policyIn.hapPolicy.permList.begin(), policyIn.hapPolicy.permList.end());
    policyOut.aclRequestedList.assign(
        policyIn.hapPolicy.aclRequestedList.begin(), policyIn.hapPolicy.aclRequestedList.end());
    policyOut.preAuthorizationInfo.assign(
        policyIn.hapPolicy.preAuthorizationInfo.begin(), policyIn.hapPolicy.preAuthorizationInfo.end());
    for (const auto& perm : policyIn.hapPolicy.permStateList) {
        PermissionStatus tmp;
        tmp.permissionName = perm.permissionName;
        tmp.grantStatus = perm.grantStatus;
        tmp.grantFlag = perm.grantFlag;
        policyOut.permStateList.emplace_back(tmp);
    }
    policyOut.checkIgnore = policyIn.hapPolicy.checkIgnore;
    policyOut.aclExtendedMap = policyIn.hapPolicy.aclExtendedMap;
}

static void DumpEventInfo(const HapPolicy& policy, HapDfxInfo& dfxInfo)
{
    dfxInfo.permInfo = std::to_string(policy.permStateList.size()) + " : [";
    for (const auto& permState : policy.permStateList) {
        dfxInfo.permInfo.append(permState.permissionName + ", ");
    }
    dfxInfo.permInfo.append("]");

    dfxInfo.aclInfo = std::to_string(policy.aclRequestedList.size()) + " : [";
    for (const auto& perm : policy.aclRequestedList) {
        dfxInfo.aclInfo.append(perm + ", ");
    }
    dfxInfo.aclInfo.append("]");

    dfxInfo.preauthInfo = std::to_string(policy.preAuthorizationInfo.size()) + " : [";
    for (const auto& preAuthInfo : policy.preAuthorizationInfo) {
        dfxInfo.preauthInfo.append(preAuthInfo.permissionName + ", ");
    }
    dfxInfo.preauthInfo.append("]");

    dfxInfo.extendInfo = std::to_string(policy.aclExtendedMap.size()) + " : {";
    for (const auto& aclExtend : policy.aclExtendedMap) {
        dfxInfo.extendInfo.append(aclExtend.first + ": " + aclExtend.second + ", ");
    }
    dfxInfo.extendInfo.append("}");
}

void AccessTokenManagerService::ReportAddHap(AccessTokenIDEx fullTokenId, const HapInfoParams& info,
    const HapPolicy& policy, int64_t beginTime, int32_t errorCode)
{
    HapDfxInfo dfxInfo;
    dfxInfo.ipcCode = static_cast<int32_t>(IAccessTokenManagerIpcCode::COMMAND_INIT_HAP_TOKEN);
    dfxInfo.tokenId = fullTokenId.tokenIdExStruct.tokenID;
    dfxInfo.tokenIdEx = fullTokenId;
    dfxInfo.userID = info.userID;
    dfxInfo.bundleName = info.bundleName;
    dfxInfo.instIndex = info.instIndex;
    dfxInfo.duration = TimeUtil::GetCurrentTimestamp() - beginTime;

    // add
    dfxInfo.sceneCode = static_cast<int32_t>(AddHapSceneCode::INSTALL_FINISH);
    dfxInfo.dlpType = static_cast<HapDlpType>(info.dlpType);
    dfxInfo.isRestore = info.isRestore;

    DumpEventInfo(policy, dfxInfo);
    ReportSysEventAddHap(errorCode, dfxInfo, true);
}

void AccessTokenManagerService::ReportUpdateHap(AccessTokenIDEx fullTokenId, const HapTokenInfo& info,
    const HapPolicy& policy, int64_t beginTime, int32_t errorCode)
{
    HapDfxInfo dfxInfo;
    dfxInfo.ipcCode = static_cast<int32_t>(IAccessTokenManagerIpcCode::COMMAND_UPDATE_HAP_TOKEN);
    dfxInfo.tokenId = fullTokenId.tokenIdExStruct.tokenID;
    dfxInfo.tokenIdEx = fullTokenId;
    dfxInfo.userID = info.userID;
    dfxInfo.bundleName = info.bundleName;
    dfxInfo.instIndex = info.instIndex;
    dfxInfo.duration = TimeUtil::GetCurrentTimestamp() - beginTime;

    DumpEventInfo(policy, dfxInfo);
    ReportSysEventUpdateHap(errorCode, dfxInfo);
}

int32_t AccessTokenManagerService::InitHapToken(const HapInfoParcel& info, const HapPolicyParcel& policy,
    uint64_t& fullTokenId, HapInfoCheckResultIdl& resultInfoIdl)
{
    HapInfoParams hapInfoParm = info.hapInfoParameter;
    LOGI(ATM_DOMAIN, ATM_TAG, "Init hap %{public}s, callerPid %{public}d.",
        hapInfoParm.bundleName.c_str(), IPCSkeleton::GetCallingPid());
    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(tokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", tokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    int64_t beginTime = TimeUtil::GetCurrentTimestamp();
    HapPolicy policyCopy;
    TransferHapPolicy(policy, policyCopy);

    resultInfoIdl.realResult = ERR_OK;
    std::vector<PermissionStatus> initializedList;
    std::vector<GenericValues> undefValues;
    if (hapInfoParm.dlpType == DLP_COMMON) {
        HapInfoCheckResult permCheckResult;
        HapInitInfo initInfo;
        initInfo.installInfo = hapInfoParm;
        initInfo.policy = policyCopy;
        initInfo.bundleName = hapInfoParm.bundleName;
        if (!PermissionManager::GetInstance().InitPermissionList(initInfo, initializedList, permCheckResult,
            undefValues)) {
            resultInfoIdl.realResult = ERROR;
            resultInfoIdl.permissionName = permCheckResult.permCheckResult.permissionName;
            resultInfoIdl.rule = static_cast<PermissionRulesEnumIdl>(permCheckResult.permCheckResult.rule);
            ReportAddHap({0}, hapInfoParm, policyCopy, beginTime, ERR_PERM_REQUEST_CFG_FAILED);
            return ERR_OK;
        }
    } else {
        if (!PermissionManager::GetInstance().InitDlpPermissionList(hapInfoParm, initializedList, undefValues)) {
            ReportAddHap({0}, hapInfoParm, policyCopy, beginTime, ERR_PERM_REQUEST_CFG_FAILED);
            return ERR_PERM_REQUEST_CFG_FAILED;
        }
    }
    policyCopy.permStateList = initializedList;

    AccessTokenIDEx tokenIdEx;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        hapInfoParm, policyCopy, tokenIdEx, undefValues);
    fullTokenId = tokenIdEx.tokenIDEx;
    ReportAddHap(tokenIdEx, hapInfoParm, policyCopy, beginTime, ret);
    return ret;
}

int AccessTokenManagerService::DeleteToken(AccessTokenID tokenID)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Id %{public}d, callerPid %{public}d.", tokenID, IPCSkeleton::GetCallingPid());
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(callingTokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    if (this->GetTokenType(tokenID) != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id %{public}u is not hap.", tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    HapDfxInfo dfxInfo = {};
    dfxInfo.tokenId = tokenID;
    dfxInfo.ipcCode = static_cast<int32_t>(IAccessTokenManagerIpcCode::COMMAND_DELETE_TOKEN);
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();
    HapTokenInfo hapInfo;
    int32_t errorCode = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, hapInfo);
    if (errorCode != ERR_OK) {
        LOGC(ATM_DOMAIN, ATM_TAG, "GetHapTokenInfo failed, err %{public}d.", errorCode);
        dfxInfo.duration = TimeUtil::GetCurrentTimestamp() - beginTime;
        ReportSysEventDelHap(errorCode, dfxInfo);
        return errorCode;
    }

    // only support hap token deletion
    errorCode = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);

    dfxInfo.userID = hapInfo.userID;
    dfxInfo.bundleName = hapInfo.bundleName;
    dfxInfo.instIndex = hapInfo.instIndex;
    dfxInfo.duration = TimeUtil::GetCurrentTimestamp() - beginTime;
    ReportSysEventDelHap(errorCode, dfxInfo);
    return errorCode;
}

int AccessTokenManagerService::GetTokenType(AccessTokenID tokenID)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Id %{public}d.", tokenID);
    return AccessTokenIDManager::GetInstance().GetTokenIdType(tokenID);
}

int AccessTokenManagerService::GetTokenType(AccessTokenID tokenID, int32_t& tokenType)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Id %{public}d.", tokenID);
    tokenType = AccessTokenIDManager::GetInstance().GetTokenIdType(tokenID);
    return ERR_OK;
}

int32_t AccessTokenManagerService::GetHapTokenID(
    int32_t userID, const std::string& bundleName, int32_t instIndex, uint64_t& fullTokenId)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "UserID %{public}d, bundle %{public}s, instIndex %{public}d.",
        userID, bundleName.c_str(), instIndex);
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());

        AccessTokenIDEx tokenIdEx = {0};
        fullTokenId = tokenIdEx.tokenIDEx;
        return ERR_OK;
    }
    AccessTokenIDEx tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(userID, bundleName, instIndex);
    fullTokenId = tokenIdEx.tokenIDEx;
    return ERR_OK;
}

int32_t AccessTokenManagerService::AllocLocalTokenID(
    const std::string& remoteDeviceID, AccessTokenID remoteTokenID, FullTokenID& tokenId)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "RemoteDeviceID %{public}s, remoteTokenID %{public}d, callerPid %{public}d.",
        ConstantCommon::EncryptDevId(remoteDeviceID).c_str(), remoteTokenID, IPCSkeleton::GetCallingPid());
    if ((!IsNativeProcessCalling()) && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
        tokenId = INVALID_TOKENID;
        return ERR_OK;
    }
    FullTokenID tokenID = AccessTokenInfoManager::GetInstance().AllocLocalTokenID(remoteDeviceID, remoteTokenID);
    tokenId = tokenID;
    return ERR_OK;
}

int32_t AccessTokenManagerService::UpdateHapToken(uint64_t& fullTokenId, const UpdateHapInfoParamsIdl& infoIdl,
    const HapPolicyParcel& policyParcel, HapInfoCheckResultIdl& resultInfoIdl)
{
    AccessTokenIDEx tokenIdEx;
    tokenIdEx.tokenIDEx = fullTokenId;
    LOGI(ATM_DOMAIN, ATM_TAG, "Id %{public}d, callerPid %{public}d.",
        tokenIdEx.tokenIdExStruct.tokenID, IPCSkeleton::GetCallingPid());
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(callingTokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();
    HapTokenInfo hapInfo = { 0 };
    int32_t error = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapInfo);
    if (error != ERR_OK) {
        LOGC(ATM_DOMAIN, ATM_TAG, "GetHapTokenInfo failed, err %{public}d.", error);
        ReportUpdateHap(tokenIdEx, hapInfo, policyParcel.hapPolicy, beginTime, error);
        return error;
    }

    UpdateHapInfoParams info;
    info.appIDDesc = infoIdl.appIDDesc;
    info.apiVersion = infoIdl.apiVersion;
    info.isSystemApp = infoIdl.isSystemApp;
    info.appDistributionType = infoIdl.appDistributionType;
    info.isAtomicService = infoIdl.isAtomicService;
    info.dataRefresh = infoIdl.dataRefresh;

    resultInfoIdl.realResult = ERR_OK;
    HapInfoCheckResult permCheckResult;
    std::vector<GenericValues> undefValues;
    std::vector<PermissionStatus> initializedList;
    HapInitInfo initInfo;
    initInfo.updateInfo = info;
    initInfo.policy = policyParcel.hapPolicy;
    initInfo.isUpdate = true;
    initInfo.bundleName = hapInfo.bundleName;
    initInfo.tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    if (!PermissionManager::GetInstance().InitPermissionList(initInfo, initializedList, permCheckResult, undefValues)) {
        resultInfoIdl.realResult = ERROR;
        resultInfoIdl.permissionName = permCheckResult.permCheckResult.permissionName;
        int32_t rule = permCheckResult.permCheckResult.rule;
        resultInfoIdl.rule = static_cast<PermissionRulesEnumIdl>(rule);
        ReportUpdateHap(tokenIdEx, hapInfo, policyParcel.hapPolicy, beginTime, ERR_PERM_REQUEST_CFG_FAILED);
        return ERR_OK;
    }

    error = AccessTokenInfoManager::GetInstance().UpdateHapToken(tokenIdEx, info,
        initializedList, policyParcel.hapPolicy, undefValues);
    fullTokenId = tokenIdEx.tokenIDEx;
    ReportUpdateHap(tokenIdEx, hapInfo, policyParcel.hapPolicy, beginTime, error);
    return error;
}

int32_t AccessTokenManagerService::GetTokenIDByUserID(int32_t userID, std::vector<AccessTokenID>& tokenIds)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "UserID: %{public}d.", userID);

    if (!IsNativeProcessCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    std::unordered_set<AccessTokenID> tokenIdList;

    auto result = AccessTokenInfoManager::GetInstance().GetTokenIDByUserID(userID, tokenIdList);
    std::copy(tokenIdList.begin(), tokenIdList.end(), std::back_inserter(tokenIds));
    return result;
}

int AccessTokenManagerService::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& infoParcel)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Id %{public}d.", tokenID);

    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    return AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, infoParcel.hapTokenInfoParams);
}

int AccessTokenManagerService::GetHapTokenInfoExtension(AccessTokenID tokenID,
    HapTokenInfoParcel& hapTokenInfoRes, std::string& appID)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Id %{public}d.", tokenID);
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    int ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, hapTokenInfoRes.hapTokenInfoParams);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get hap token info extenstion failed, ret %{public}d.", ret);
        return ret;
    }

    return AccessTokenInfoManager::GetInstance().GetHapAppIdByTokenId(tokenID, appID);
}

int AccessTokenManagerService::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& infoParcel)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Id %{public}d.", tokenID);

    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
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
    LOGI(ATM_DOMAIN, ATM_TAG, "Id %{public}d, callerPid %{public}d.", tokenID, IPCSkeleton::GetCallingPid());

    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
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
    LOGI(ATM_DOMAIN, ATM_TAG, "DeviceID %{public}s, callerPid %{public}d.",
        ConstantCommon::EncryptDevId(deviceID).c_str(), IPCSkeleton::GetCallingPid());

    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
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
    LOGI(ATM_DOMAIN, ATM_TAG, "DeviceID %{public}s, id %{public}d, callerPid %{public}d.",
        ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID, IPCSkeleton::GetCallingPid());

    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceID, tokenID);
}

int32_t AccessTokenManagerService::GetRemoteNativeTokenID(const std::string& deviceID,
    AccessTokenID tokenID, AccessTokenID& tokenId)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeviceID %{public}s, id %{public}d, callerPid %{public}d.",
        ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID, IPCSkeleton::GetCallingPid());

    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
        tokenId = INVALID_TOKENID;
        return ERR_OK;
    }
    tokenId = AccessTokenInfoManager::GetInstance().GetRemoteNativeTokenID(deviceID, tokenID);
    return ERR_OK;
}

int AccessTokenManagerService::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeviceID %{public}s, callerPid %{public}d.",
        ConstantCommon::EncryptDevId(deviceID).c_str(), IPCSkeleton::GetCallingPid());

    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(deviceID);
}

int32_t AccessTokenManagerService::RegisterTokenSyncCallback(const sptr<IRemoteObject>& callback)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Call token sync callback registed, callerPid %{public}d.",
        IPCSkeleton::GetCallingPid());

    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied, tokenID=%{public}d.", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return TokenModifyNotifier::GetInstance().RegisterTokenSyncCallback(callback);
}

int32_t AccessTokenManagerService::UnRegisterTokenSyncCallback()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Call token sync callback unregisted, callerPid %{public}d.",
        IPCSkeleton::GetCallingPid());

    if (!IsAccessTokenCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied, tokenID=%{public}d.", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    TokenModifyNotifier::GetInstance().UnRegisterTokenSyncCallback();
    return ERR_OK;
}
#endif

int32_t AccessTokenManagerService::DumpTokenInfo(const AtmToolsParamInfoParcel& infoParcel, std::string& dumpInfo)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "CallerPid %{public}d.", IPCSkeleton::GetCallingPid());
    if (!IsShellProcessCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
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
    LOGI(ATM_DOMAIN, ATM_TAG, "CallerPid %{public}d.", IPCSkeleton::GetCallingPid());
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingToken) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    version = DEFAULT_TOKEN_VERSION;
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::SetPermDialogCap(const HapBaseInfoParcel& hapBaseInfoParcel, bool enable)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "CallerPid %{public}d.", IPCSkeleton::GetCallingPid());
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, DISABLE_PERMISSION_DIALOG) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    AccessTokenIDEx tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(
        hapBaseInfoParcel.hapBaseInfo.userID,
        hapBaseInfoParcel.hapBaseInfo.bundleName,
        hapBaseInfoParcel.hapBaseInfo.instIndex);
    int32_t ret = AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenIdEx.tokenIdExStruct.tokenID, enable);
    // DFX
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "SET_PERMISSION_DIALOG_CAP",
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
    infoParcel.info.openSettingAbilityName = openSettingAbilityName_;
    return ERR_OK;
}

int32_t AccessTokenManagerService::SetUserPolicy(const std::vector<UserPermissionPolicyIdl>& userPermissionList)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "CallerPid %{public}d.", IPCSkeleton::GetCallingPid());
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    size_t policySize = userPermissionList.size();
    if ((policySize == 0) || (policySize > MAX_USER_POLICY_SIZE)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PolicySize %{public}zu is invalid.", policySize);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    std::vector<UserPermissionPolicy> policyList;
    for (const auto& permPolicyIdl : userPermissionList) {
        UserPermissionPolicy permPolicy;
        permPolicy.permissionName = permPolicyIdl.permissionName;
        for (const auto& userPolicyIdl : permPolicyIdl.userPolicyList) {
            UserPolicy policy;
            policy.userId = userPolicyIdl.userId;
            policy.isRestricted = userPolicyIdl.isRestricted;
            permPolicy.userPolicyList.emplace_back(policy);
        }
        policyList.emplace_back(permPolicy);
    }
    return AccessTokenInfoManager::GetInstance().SetUserPolicy(policyList);
}

int32_t AccessTokenManagerService::ClearUserPolicy(const std::vector<std::string>& permissionList)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "CallerPid %{public}d.", IPCSkeleton::GetCallingPid());
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    size_t permSize = permissionList.size();
    if ((permSize == 0) || (permSize > MAX_USER_POLICY_SIZE)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermSize %{public}zu is invalid.", permSize);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    return AccessTokenInfoManager::GetInstance().ClearUserPolicy(permissionList);
}

void AccessTokenManagerService::AccessTokenServiceParamSet() const
{
    int32_t res = SetParameter(ACCESS_TOKEN_SERVICE_INIT_KEY, std::to_string(1).c_str());
    if (res != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SetParameter ACCESS_TOKEN_SERVICE_INIT_KEY 1 failed %{public}d.", res);
        return;
    }
    // 2 is to tell others sa that at service is loaded.
    res = SetParameter(ACCESS_TOKEN_SERVICE_INIT_KEY, std::to_string(2).c_str());
    if (res != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SetParameter ACCESS_TOKEN_SERVICE_INIT_KEY 2 failed %{public}d.", res);
        return;
    }
}

void AccessTokenManagerService::SetFlagIfNeed(const AccessTokenServiceConfig& atConfig,
    int32_t& cancelTime, uint32_t& parseConfigFlag)
{
    parseConfigFlag = 0;
    // set value from config
    if (!atConfig.grantBundleName.empty()) {
        grantBundleName_ = atConfig.grantBundleName;
        parseConfigFlag = 0x1;
    }
    if (!atConfig.grantAbilityName.empty()) {
        grantAbilityName_ = atConfig.grantAbilityName;
        parseConfigFlag |= 0x1 << BITMAP_INDEX_1;
    }
    if (!atConfig.grantServiceAbilityName.empty()) {
        grantServiceAbilityName_ = atConfig.grantServiceAbilityName;
        parseConfigFlag |= 0x1 << BITMAP_INDEX_2;
    }
    if (!atConfig.permStateAbilityName.empty()) {
        permStateAbilityName_ = atConfig.permStateAbilityName;
        parseConfigFlag |= 0x1 << BITMAP_INDEX_3;
    }
    if (!atConfig.globalSwitchAbilityName.empty()) {
        globalSwitchAbilityName_ = atConfig.globalSwitchAbilityName;
        parseConfigFlag |= 0x1 << BITMAP_INDEX_4;
    }
    if (atConfig.cancelTime != 0) {
        cancelTime = atConfig.cancelTime;
        parseConfigFlag |= 0x1 << BITMAP_INDEX_5;
    }
    if (!atConfig.applicationSettingAbilityName.empty()) {
        applicationSettingAbilityName_ = atConfig.applicationSettingAbilityName;
        parseConfigFlag |= 0x1 << BITMAP_INDEX_6;
    }
    if (!atConfig.openSettingAbilityName.empty()) {
        openSettingAbilityName_ = atConfig.openSettingAbilityName;
        parseConfigFlag |= 0x1 << BITMAP_INDEX_7;
    }
}

void AccessTokenManagerService::GetConfigValue(uint32_t& parseConfigFlag)
{
    grantBundleName_ = GRANT_ABILITY_BUNDLE_NAME;
    grantAbilityName_ = GRANT_ABILITY_ABILITY_NAME;
    grantServiceAbilityName_ = GRANT_ABILITY_ABILITY_NAME;
    permStateAbilityName_ = PERMISSION_STATE_SHEET_ABILITY_NAME;
    globalSwitchAbilityName_ = GLOBAL_SWITCH_SHEET_ABILITY_NAME;
    int32_t cancelTime = 0;
    applicationSettingAbilityName_ = APPLICATION_SETTING_ABILITY_NAME;
    openSettingAbilityName_ = OPEN_SETTING_ABILITY_NAME;
    LibraryLoader loader(CONFIG_PARSE_LIBPATH);
    ConfigPolicyLoaderInterface* policy = loader.GetObject<ConfigPolicyLoaderInterface>();
    if (policy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Dlopen libaccesstoken_json_parse failed.");
        return;
    }
    AccessTokenConfigValue value;
    if (policy->GetConfigValue(ServiceType::ACCESSTOKEN_SERVICE, value)) {
        SetFlagIfNeed(value.atConfig, cancelTime, parseConfigFlag);
    }
    TempPermissionObserver::GetInstance().SetCancelTime(cancelTime);
    LOGI(ATM_DOMAIN, ATM_TAG, "GrantBundleName_ is %{public}s, grantAbilityName_ is %{public}s, "
        "grantServiceAbilityName_ is %{public}s, permStateAbilityName_ is %{public}s, "
        "globalSwitchAbilityName_ is %{public}s, applicationSettingAbilityName_ is %{public}s, "
        "openSettingAbilityName_ is %{public}s.",
        grantBundleName_.c_str(), grantAbilityName_.c_str(), grantServiceAbilityName_.c_str(),
        permStateAbilityName_.c_str(), globalSwitchAbilityName_.c_str(), applicationSettingAbilityName_.c_str(),
        openSettingAbilityName_.c_str());
}

int32_t AccessTokenManagerService::GetKernelPermissions(
    AccessTokenID tokenId, std::vector<PermissionWithValueIdl>& kernelPermIdlList)
{
    auto callingToken = IPCSkeleton::GetCallingTokenID();
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingToken);
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return AccessTokenInfoManager::GetInstance().GetReqPermissionByName(
        tokenId, permissionName, value);
}

void AccessTokenManagerService::FilterInvalidData(const std::vector<GenericValues>& results,
    const std::map<int32_t, TokenIdInfo>& tokenIdAplMap, std::vector<GenericValues>& validValueList)
{
    int32_t tokenId = 0;
    std::string permissionName;
    std::string appDistributionType;
    int32_t acl = 0;
    std::string value;
    PermissionBriefDef data;

    for (const auto& result : results) {
        tokenId = result.GetInt(TokenFiledConst::FIELD_TOKEN_ID);
        auto iter = tokenIdAplMap.find(tokenId);
        if (iter == tokenIdAplMap.end()) {
            continue;
        }

        permissionName = result.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        if (!GetPermissionBriefDef(permissionName, data)) {
            LOGW(ATM_DOMAIN, ATM_TAG, "permission %{public}s is still invalid!", permissionName.c_str());
            continue;
        }

        PermissionRulesEnum rule = PERMISSION_ACL_RULE;
        appDistributionType = result.GetString(TokenFiledConst::FIELD_APP_DISTRIBUTION_TYPE);
        HapInitInfo initInfo;
        initInfo.tokenID = static_cast<AccessTokenID>(tokenId);
        if (!PermissionManager::GetInstance().IsPermAvailableRangeSatisfied(
            data, appDistributionType, iter->second.isSystemApp, rule, initInfo)) {
            continue;
        }

        acl = result.GetInt(TokenFiledConst::FIELD_ACL);
        value = result.GetString(TokenFiledConst::FIELD_VALUE);
        if (!IsPermissionValid(iter->second.apl, data, value, (acl == 1))) {
            // hap apl less than perm apl without acl is invalid now, keep them in db, maybe valid someday
            continue;
        }

        validValueList.emplace_back(result);
    }
}

void AccessTokenManagerService::UpdateUndefinedInfoCache(const std::vector<GenericValues>& validValueList,
    std::vector<GenericValues>& stateValues, std::vector<GenericValues>& extendValues)
{
    std::string permissionName;
    PermissionState grantStatus;
    PermissionFlag grantFlag;
    AccessTokenID tokenId = 0;
    std::string value;

    for (const auto& validValue : validValueList) {
        permissionName = validValue.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        PermissionBriefDef data;
        if (!GetPermissionBriefDef(permissionName, data)) {
            continue;
        }

        if (data.grantMode == GrantMode::USER_GRANT || data.grantMode == GrantMode::MANUAL_SETTINGS) {
            grantStatus = PermissionState::PERMISSION_DENIED;
            grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
        } else {
            grantStatus = PermissionState::PERMISSION_GRANTED;
            grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED;
        }

        tokenId = static_cast<AccessTokenID>(validValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
        value = validValue.GetString(TokenFiledConst::FIELD_VALUE);

        int32_t res = PermissionDataBrief::GetInstance().AddBriefPermData(tokenId, permissionName, grantStatus,
            grantFlag, value);
        if (res != RET_SUCCESS) {
            continue;
        }

        PermissionManager::GetInstance().SetPermToKernel(tokenId, permissionName,
            (grantStatus == PermissionState::PERMISSION_GRANTED));

        GenericValues stateValue;
        stateValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        stateValue.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
        stateValue.Put(TokenFiledConst::FIELD_DEVICE_ID, "");
        stateValue.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
        stateValue.Put(TokenFiledConst::FIELD_GRANT_STATE, static_cast<int32_t>(grantStatus));
        stateValue.Put(TokenFiledConst::FIELD_GRANT_FLAG, static_cast<int32_t>(grantFlag));
        stateValues.emplace_back(stateValue);

        if ((data.hasValue) && !value.empty()) {
            GenericValues extendValue;
            extendValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
            extendValue.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
            extendValue.Put(TokenFiledConst::FIELD_VALUE, value);
            extendValues.emplace_back(extendValue);
        }
    }
}

bool AccessTokenManagerService::IsPermissionValid(int32_t hapApl, const PermissionBriefDef& data,
    const std::string& value, bool isAcl)
{
    if (hapApl >= static_cast<int32_t>(data.availableLevel)) {
        return true; // not cross apl, this is valid
    }

    if (isAcl) {
        return true; // cross apl but request by acl, this is valid
    } else {
        if (data.hasValue) {
            return !value.empty(); // permission hasValue is true and request with value, this is valid
        }
        return false;
    }

    return false;
}

void AccessTokenManagerService::HandleHapUndefinedInfo(const std::map<int32_t, TokenIdInfo>& tokenIdAplMap,
    std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec)
{
    GenericValues conditionValue;
    std::vector<GenericValues> results;

    // get all hap undefined data
    int32_t res = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, conditionValue, results);
    if (res != 0) {
        return;
    }

    if (results.empty()) {
        return;
    }

    // filter invalid data
    std::vector<GenericValues> validValueList;
    FilterInvalidData(results, tokenIdAplMap, validValueList);

    std::vector<GenericValues> stateValues;
    std::vector<GenericValues> extendValues;
    UpdateUndefinedInfoCache(validValueList, stateValues, extendValues);

    DelInfo delInfo;
    for (const auto& value : validValueList) {
        delInfo.delType = AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO;
        delInfo.delValue = value;
        delInfoVec.emplace_back(delInfo);
    }

    AddInfo addInfo;
    addInfo.addType = AtmDataType::ACCESSTOKEN_PERMISSION_STATE;
    addInfo.addValues = stateValues;
    addInfoVec.emplace_back(addInfo);
    addInfo.addType = AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE;
    addInfo.addValues = extendValues;
    addInfoVec.emplace_back(addInfo);
}

void AccessTokenManagerService::UpdateDatabaseAsync(const std::vector<DelInfo>& delInfoVec,
    const std::vector<AddInfo>& addInfoVec)
{
    auto task = [delInfoVec, addInfoVec]() {
        LOGI(ATM_DOMAIN, ATM_TAG, "Entry!");
        (void)AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    };
    std::thread updateDbThread(task);
    updateDbThread.detach();
}

void AccessTokenManagerService::HandlePermDefUpdate(const std::map<int32_t, TokenIdInfo>& tokenIdAplMap)
{
    std::string dbPermDefVersion;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_NAME, PERM_DEF_VERSION);
    std::vector<GenericValues> results;
    int32_t res = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG, conditionValue, results);
    if (res != 0) {
        return;
    }

    if (!results.empty()) {
        dbPermDefVersion = results[0].GetString(TokenFiledConst::FIELD_VALUE);
    }

    const char* curPermDefVersion = GetPermDefVersion();
    bool isUpdate = dbPermDefVersion != std::string(curPermDefVersion);
    if (isUpdate) {
        LOGI(ATM_DOMAIN, ATM_TAG,
            "Perm definition version from db %{public}s is not same with current version %{public}s.",
            dbPermDefVersion.c_str(), curPermDefVersion);

        GenericValues delValue;
        delValue.Put(TokenFiledConst::FIELD_NAME, PERM_DEF_VERSION);
        GenericValues addValue;
        addValue.Put(TokenFiledConst::FIELD_NAME, PERM_DEF_VERSION);
        addValue.Put(TokenFiledConst::FIELD_VALUE, std::string(curPermDefVersion));
        DelInfo delInfo;
        delInfo.delType = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
        delInfo.delValue = delValue;
        AddInfo addInfo;
        addInfo.addType = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
        addInfo.addValues.emplace_back(addValue);

        // update or insert permission define version to db
        std::vector<DelInfo> delInfoVec;
        delInfoVec.emplace_back(delInfo);
        std::vector<AddInfo> addInfoVec;
        addInfoVec.emplace_back(addInfo);

        if (!dbPermDefVersion.empty()) { // dbPermDefVersion empty means undefine table is empty
            HandleHapUndefinedInfo(tokenIdAplMap, delInfoVec, addInfoVec);
        }

        UpdateDatabaseAsync(delInfoVec, addInfoVec);
    }
}

bool AccessTokenManagerService::Initialize()
{
    MemoryGuard guard;
    ReportSysEventPerformance();

    uint32_t hapSize = 0;
    uint32_t nativeSize = 0;
    uint32_t pefDefSize = 0;
    uint32_t dlpSize = 0;
    std::map<int32_t, TokenIdInfo> tokenIdAplMap;
    AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenIdAplMap);
    HandlePermDefUpdate(tokenIdAplMap);

#ifdef EVENTHANDLER_ENABLE
    TempPermissionObserver::GetInstance().InitEventHandler();
    ShortGrantManager::GetInstance().InitEventHandler();
#endif
    InitDfxInfo dfxInfo;
    dfxInfo.pid = getpid();
    dfxInfo.hapSize = hapSize;
    dfxInfo.nativeSize = nativeSize;
    dfxInfo.permDefSize = pefDefSize;
    dfxInfo.dlpSize = dlpSize;
    GetConfigValue(dfxInfo.parseConfigFlag);

    ReportSysEventServiceStart(dfxInfo);
    std::thread reportUserData(ReportAccessTokenUserData);
    reportUserData.detach();
    LOGI(ATM_DOMAIN, ATM_TAG, "Initialize success.");
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
        std::lock_guard<std::mutex> lock(tokenSyncIdMutex_);
        if (tokenSyncId_ == 0) {
            this->GetNativeTokenId("token_sync_service", tokenSyncId_);
        }
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
    return TokenIDAttributes::IsSystemApp(fullTokenId);
}

int32_t AccessTokenManagerService::CallbackEnter(uint32_t code)
{
    ClearThreadErrorMsg();
#ifdef HICOLLIE_ENABLE
    std::string name = "AtmTimer";
    g_timerIdStack.push(HiviewDFX::XCollie::GetInstance().SetTimer(name, TIMEOUT, nullptr, nullptr,
        HiviewDFX::XCOLLIE_FLAG_LOG));
#endif // HICOLLIE_ENABLE
    return ERR_OK;
}

int32_t AccessTokenManagerService::CallbackExit(uint32_t code, int32_t result)
{
#ifdef HICOLLIE_ENABLE
    if (!g_timerIdStack.empty()) {
        HiviewDFX::XCollie::GetInstance().CancelTimer(g_timerIdStack.top());
        g_timerIdStack.pop();
    }
#endif // HICOLLIE_ENABLE
    ClearThreadErrorMsg();
    return ERR_OK;
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
bool AccessTokenManagerService::IsSecCompServiceCalling()
{
    uint32_t tokenCaller = IPCSkeleton::GetCallingTokenID();
    if (secCompTokenId_ == 0) {
        std::lock_guard<std::mutex> lock(secCompTokenIdMutex_);
        if (secCompTokenId_ == 0) {
            this->GetNativeTokenId("security_component_service", secCompTokenId_);
        }
    }
    return tokenCaller == secCompTokenId_;
}

int32_t AccessTokenManagerService::RegisterSecCompEnhance(const SecCompEnhanceDataParcel& enhanceParcel)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Pid: %{public}d.", enhanceParcel.enhanceData.pid);
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
        LOGW(ATM_DOMAIN, ATM_TAG, "Pid %{public}d get enhance failed.", pid);
        return res;
    }

    enhanceParcel.enhanceData = enhanceData;
    return RET_SUCCESS;
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
