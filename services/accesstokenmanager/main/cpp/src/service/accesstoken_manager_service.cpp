/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include <mutex>
#include <stack>
#include <unordered_set>
#include <unistd.h>

#include "access_token.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "claw_permission_info.h"
#include "accesstoken_common_log.h"
#include "accesstoken_dfx_define.h"
#include "claw_permission_info.h"
#include "claw_permission_decision_engine.h"
#include "claw_permission_metadata_provider.h"
#include "claw_permission_status_helper.h"
#include "claw_ticket_manager.h"
#include "accesstoken_id_manager.h"
#include "constant_common.h"
#include "claw_token_info_manager.h"
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
#include "permission_map.h"
#include "permission_status_parcel.h"
#include "permission_validator.h"
#include "random.h"
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
#include "sec_comp_enhance_agent.h"
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
#ifdef SUPPORT_MANAGE_USER_POLICY
static constexpr int32_t MAX_USER_POLICY_SIZE = 1024;
const std::string MANAGE_USER_POLICY = "ohos.permission.MANAGE_USER_POLICY";
#endif
const std::string GRANT_SENSITIVE_PERMISSIONS = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
const std::string REVOKE_SENSITIVE_PERMISSIONS = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS";
const std::string GET_SENSITIVE_PERMISSIONS = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
const std::string DISABLE_PERMISSION_DIALOG = "ohos.permission.DISABLE_PERMISSION_DIALOG";
const std::string GRANT_SHORT_TERM_WRITE_MEDIAVIDEO = "ohos.permission.GRANT_SHORT_TERM_WRITE_MEDIAVIDEO";
const std::string MANAGE_EDM_POLICY = "ohos.permission.MANAGE_EDM_POLICY";
const std::string MANAGE_TOOL_TOKEN = "ohos.permission.MANAGE_TOOL_TOKENID";
const std::string MANAGE_CLAW_TOKEN = "ohos.permission.MANAGE_CLAW_TOKEN";
const std::string QUERY_TOOL_PERMISSIONS = "ohos.permission.QUERY_TOOL_PERMISSIONS";
const std::string MANAGE_TOOL_RUNTIME_PERMISSIONS = "ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS";

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

bool HasDetailWithoutDialog(const std::vector<PermissionDialogDetail>& detailList)
{
    for (const auto& detail : detailList) {
        if (!detail.needPermissionDialog) {
            return true;
        }
    }
    return false;
}

size_t CountDialogDetails(const std::vector<PermissionDialogDetail>& detailList)
{
    size_t count = 0;
    for (const auto& detail : detailList) {
        if (detail.needPermissionDialog) {
            ++count;
        }
    }
    return count;
}

bool HasNotDeclaredStatus(const PermissionDialogDetail& detail)
{
    for (const auto& status : detail.statusList) {
        if (status == PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED) {
            return true;
        }
    }
    return false;
}

std::vector<bool> BuildAuthorizationResults(size_t size)
{
    return std::vector<bool>(size, false);
}

bool IsAgentIdValid(const std::string& agentID)
{
    return agentID.length() <= MAX_CLAW_AGENT_ID_LEN;
}

bool IsCliInfoValid(const CliInfo& info)
{
    return DataValidator::IsProcessNameValid(info.cliName) &&
        (info.cliName.length() <= MAX_CLAW_CLI_NAME_LEN) &&
        (info.subCliName.empty() || info.subCliName.length() <= MAX_CLAW_SUB_CLI_NAME_LEN);
}

bool AreCliInfosValid(const std::vector<CliInfoParcel>& cliInfoList)
{
    for (const auto& info : cliInfoList) {
        if (!IsCliInfoValid(info.cliInfo)) {
            return false;
        }
    }
    return true;
}

bool IsCliInfoListSizeValid(size_t size)
{
    return (size > 0) && (size <= MAX_CLAW_CLI_INFO_LIST_SIZE);
}

bool AreCliAuthInfosValid(const std::vector<CliAuthInfoParcel>& authInfoList)
{
    for (const auto& info : authInfoList) {
        if (!IsCliInfoValid(info.info.cliInfo) ||
            (info.info.permissionNames.size() != info.info.authorizationResults.size())) {
            return false;
        }
        for (const auto& permissionName : info.info.permissionNames) {
            if (permissionName.empty() || permissionName.length() > MAX_CLAW_CLI_NAME_LEN) {
                return false;
            }
        }
    }
    return true;
}

void AppendResolvedPermission(CliAuthInfo& authInfo, const std::string& permissionName, bool authorizationResult)
{
    for (size_t index = 0; index < authInfo.permissionNames.size(); ++index) {
        if (authInfo.permissionNames[index] != permissionName) {
            continue;
        }
        authInfo.authorizationResults[index] = authInfo.authorizationResults[index] || authorizationResult;
        return;
    }
    authInfo.permissionNames.emplace_back(permissionName);
    authInfo.authorizationResults.emplace_back(authorizationResult);
}

int32_t BuildCliTicketAuthInfos(AccessTokenID hostTokenID, const std::vector<CliAuthInfo>& rawAuthInfoList,
    std::vector<CliAuthInfo>& authInfos)
{
    PermissionStatusMap permissionStatusMap;
    int32_t ret = BuildPermissionStatusMap(hostTokenID, permissionStatusMap);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    authInfos.clear();
    authInfos.reserve(rawAuthInfoList.size());
    for (const auto& rawAuthInfo : rawAuthInfoList) {
        CliAuthInfo resolvedAuthInfo;
        resolvedAuthInfo.cliInfo = rawAuthInfo.cliInfo;
        for (size_t index = 0; index < rawAuthInfo.permissionNames.size(); ++index) {
            std::vector<std::string> usedPermissions;
            ret = ClawPermissionMetadataProvider::GetInstance().GetUsedPermissionsByCliPermission(
                rawAuthInfo.permissionNames[index], usedPermissions);
            if (ret != RET_SUCCESS) {
                LOGE(ATM_DOMAIN, ATM_TAG,
                    "Build cli ticket auth info failed, cli=%{public}s/%{public}s, permission=%{public}s, "
                    "ret=%{public}d.",
                    rawAuthInfo.cliInfo.cliName.c_str(), rawAuthInfo.cliInfo.subCliName.c_str(),
                    rawAuthInfo.permissionNames[index].c_str(), ret);
                return ret;
            }
            for (const auto& usedPermission : usedPermissions) {
                AppendResolvedPermission(resolvedAuthInfo, usedPermission,
                    ResolveCliGrantedPermission(permissionStatusMap, usedPermission,
                        rawAuthInfo.authorizationResults[index]));
            }
        }
        authInfos.emplace_back(std::move(resolvedAuthInfo));
    }
    return RET_SUCCESS;
}

int32_t FillCliDialogAuthResultsIfNoDialog(AccessTokenID hostTokenID, const std::string& agentID,
    const std::vector<CliInfo>& cliInfos, PermissionDialogResult& result)
{
    (void)agentID;
    if (!HasDetailWithoutDialog(result.detailList)) {
        return RET_SUCCESS;
    }
    std::vector<size_t> detailIndexes;
    std::vector<CliAuthInfo> rawAuthInfoList;
    for (size_t i = 0; i < result.detailList.size() && i < cliInfos.size(); ++i) {
        if (result.detailList[i].needPermissionDialog) {
            continue;
        }
        if (HasNotDeclaredStatus(result.detailList[i])) {
            continue;
        }
        CliAuthInfo authInfo;
        authInfo.cliInfo = cliInfos[i];
        int32_t ret = ClawPermissionMetadataProvider::GetInstance().GetRequiredCliPermissions(
            cliInfos[i], authInfo.permissionNames);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Build cli dialog auth info failed, cli=%{public}s/%{public}s, ret=%{public}d.",
                cliInfos[i].cliName.c_str(), cliInfos[i].subCliName.c_str(), ret);
            return ret;
        }
        authInfo.authorizationResults = BuildAuthorizationResults(authInfo.permissionNames.size());
        detailIndexes.emplace_back(i);
        rawAuthInfoList.emplace_back(std::move(authInfo));
    }
    if (detailIndexes.empty()) {
        return RET_SUCCESS;
    }
    std::vector<CliAuthInfo> authInfoList;
    int32_t ret = BuildCliTicketAuthInfos(hostTokenID, rawAuthInfoList, authInfoList);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    std::vector<std::string> authResults;
    ret = ClawTicketManager::GetInstance().GenerateCliTicket(hostTokenID, authInfoList, authResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Generate cli dialog auth result failed, tokenId=%{public}u, ret=%{public}d.", hostTokenID, ret);
        return ret;
    }
    for (size_t i = 0; i < detailIndexes.size() && i < authResults.size(); ++i) {
        result.detailList[detailIndexes[i]].authResult = authResults[i];
    }
    return RET_SUCCESS;
}

int32_t FillSkillDialogAuthResultsIfNoDialog(AccessTokenID hostTokenID, const std::string& agentID,
    const std::vector<SkillInfo>& skillInfos, PermissionDialogResult& result)
{
    (void)agentID;
    if (!HasDetailWithoutDialog(result.detailList)) {
        return RET_SUCCESS;
    }
    std::vector<size_t> detailIndexes;
    std::vector<SkillAuthInfo> authInfoList;
    for (size_t i = 0; i < result.detailList.size() && i < skillInfos.size(); ++i) {
        if (result.detailList[i].needPermissionDialog) {
            continue;
        }
        SkillAuthInfo authInfo;
        authInfo.skillInfo = skillInfos[i];
        authInfo.permissionNames = result.detailList[i].permissionNameList;
        authInfo.authorizationResults = BuildAuthorizationResults(authInfo.permissionNames.size());
        detailIndexes.emplace_back(i);
        authInfoList.emplace_back(authInfo);
    }
    std::vector<std::string> authResults;
    int32_t ret = ClawTicketManager::GetInstance().GenerateSkillTicket(hostTokenID, authInfoList, authResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Generate skill dialog auth result failed, tokenId=%{public}u, ret=%{public}d.", hostTokenID, ret);
        return ret;
    }
    for (size_t i = 0; i < detailIndexes.size() && i < authResults.size(); ++i) {
        result.detailList[detailIndexes[i]].authResult = authResults[i];
    }
    return RET_SUCCESS;
}

int32_t ValidateHostTokenId(AccessTokenID hostTokenID)
{
    if (hostTokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid host tokenId, tokenId is invalid token.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (AccessTokenIDManager::GetInstance().GetTokenIdType(hostTokenID) != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid host tokenId=%{public}u.", hostTokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    return RET_SUCCESS;
}

int32_t ValidateClawCliAccess(AccessTokenID hostTokenID, const std::vector<CliInfo>& cliInfos)
{
    return ClawPermissionDecisionEngine::GetInstance().ValidateClawCliAccess(hostTokenID, cliInfos);
}

std::vector<CliInfo> ConvertCliInfoParcels(const std::vector<CliInfoParcel>& cliInfoList)
{
    std::vector<CliInfo> cliInfos;
    cliInfos.reserve(cliInfoList.size());
    for (const auto& cliInfoParcel : cliInfoList) {
        cliInfos.emplace_back(cliInfoParcel.cliInfo);
    }
    return cliInfos;
}

size_t CountRequiredCliPermissions(const CliPermissionsResult& result)
{
    size_t requiredPermCount = 0;
    for (const auto& perm : result.permList) {
        requiredPermCount += perm.requiredCliPermissions.size();
    }
    return requiredPermCount;
}

bool IsCliAuthInfoValid(const CliAuthInfo& info)
{
    return info.permissionNames.size() == info.authorizationResults.size();
}

bool IsSkillAuthInfoValid(const SkillAuthInfo& info)
{
    return info.permissionNames.size() == info.authorizationResults.size();
}

int32_t BuildCliTicketAuthInfos(AccessTokenID hostTokenID, const std::vector<CliAuthInfoParcel>& authInfoList,
    std::vector<CliAuthInfo>& authInfos)
{
    std::vector<CliAuthInfo> rawAuthInfoList;
    rawAuthInfoList.reserve(authInfoList.size());
    for (const auto& authInfoParcel : authInfoList) {
        rawAuthInfoList.emplace_back(authInfoParcel.info);
    }
    return BuildCliTicketAuthInfos(hostTokenID, rawAuthInfoList, authInfos);
}
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
    if (isInitialize_) {
        featureFuture_.wait();
    }
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
    int32_t res = PERMISSION_DENIED;
    if (ToolTokenInfoManager::GetInstance().IsToolToken(tokenID)) {
        res = ToolTokenInfoManager::GetInstance().VerifyToolAccessToken(tokenID, permissionName);
    } else {
        res = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, permissionName);
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "Id %{public}d, perm %{public}s, res %{public}d.",
        tokenID, permissionName.c_str(), res);
    if ((res == PERMISSION_GRANTED) &&
        (TokenIDAttributes::GetTokenIdTypeEnum(tokenID) == TOKEN_HAP)) {
        uint32_t permCode;
        if (TransferPermissionToOpcode(permissionName, permCode)) {
            res = AccessTokenInfoManager::GetInstance().IsPermissionRestrictedByUserPolicy(tokenID, permCode) ?
                PERMISSION_DENIED : PERMISSION_GRANTED;
        }
    }
#ifdef HITRACE_NATIVE_ENABLE
    FinishTrace(HITRACE_TAG_ACCESS_CONTROL);
#endif
    return res;
}

int32_t AccessTokenManagerService::InitCliToken(const CliInitInfoParcel& initInfoParcel, uint64_t& fullTokenId,
    std::vector<PermissionWithValueIdl>& kernelPermIdlList)
{
    kernelPermIdlList.clear();
    if ((IPCSkeleton::GetCallingUid() != AIMGR_UID) && (IPCSkeleton::GetCallingUid() != ROOT_UID)) {
        LOGD(ATM_DOMAIN, ATM_TAG, "CallingUid() %{public}d.", IPCSkeleton::GetCallingUid());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<std::string> kernelPermList;
    int32_t ret = ToolTokenInfoManager::GetInstance().InitCliToken(
        initInfoParcel.cliInitInfo, IPCSkeleton::GetCallingPid(), tokenIdEx, kernelPermList);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    fullTokenId = tokenIdEx.tokenIDEx;
    for (const auto& permissionName : kernelPermList) {
        PermissionWithValueIdl item;
        item.permissionName = permissionName;
        kernelPermIdlList.emplace_back(item);
    }
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::InitSkillToken(const SkillInitInfoParcel& initInfoParcel, uint64_t& fullTokenId,
    std::vector<PermissionWithValueIdl>& kernelPermIdlList)
{
    kernelPermIdlList.clear();
    if (IPCSkeleton::GetCallingUid() != AIMGR_UID) {
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<std::string> kernelPermList;
    int32_t ret = ToolTokenInfoManager::GetInstance().InitSkillToken(
        initInfoParcel.skillInitInfo, IPCSkeleton::GetCallingPid(), tokenIdEx, kernelPermList);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    fullTokenId = tokenIdEx.tokenIDEx;
    for (const auto& permissionName : kernelPermList) {
        PermissionWithValueIdl item;
        item.permissionName = permissionName;
        kernelPermIdlList.emplace_back(item);
    }
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::DeleteToolTokenByPid(int32_t pid)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsShellProcessCalling() &&
        (!IsNativeProcessCalling() || VerifyAccessToken(callingTokenID, MANAGE_TOOL_TOKEN) == PERMISSION_DENIED)) {
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(pid);
}

int32_t AccessTokenManagerService::GetCliTokenInfo(AccessTokenID tokenId, CliInfoResultParcel& infoParcel)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return ToolTokenInfoManager::GetInstance().GetCliTokenInfo(tokenId, infoParcel.cliTokenInfo);
}

int32_t AccessTokenManagerService::GetSkillTokenInfo(AccessTokenID tokenId, SkillInfoResultParcel& infoParcel)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return ToolTokenInfoManager::GetInstance().GetSkillTokenInfo(tokenId, infoParcel.skillTokenInfo);
}

int32_t AccessTokenManagerService::GetHostTokenId(AccessTokenID toolTokenId, AccessTokenID& hostTokenId)
{
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Permission denied when get host token, callingTokenId=%{public}u, toolTokenId=%{public}u.",
            IPCSkeleton::GetCallingTokenID(), toolTokenId);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return ToolTokenInfoManager::GetInstance().GetHostTokenId(toolTokenId, hostTokenId);
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
        permOper = INVALID_OPER;
        return ERR_OK;
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

bool AccessTokenManagerService::IsLocationPermSpecialHandle(std::string permissionName, int32_t apiVersion)
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
        if (IsLocationPermSpecialHandle(reqPermList[i].permsState.permissionName, apiVersion)) {
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
        ReportPermissionVerifyEvent(callingTokenID, permissionName, "SetToggleStatus");
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
        ReportPermissionVerifyEvent(callingTokenID, permissionName, "GetToggleStatus");
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
        ReportPermissionVerifyEvent(callingTokenID, permissionName);
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    int32_t ret = PermissionManager::GetInstance().GrantPermission(
        tokenID, permissionName, flag, static_cast<UpdatePermissionFlag>(updateFlag));
    return ret;
}

int AccessTokenManagerService::RevokePermission(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t flag, int32_t updateFlag, bool killProcess)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }

    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        ReportPermissionVerifyEvent(callingTokenID, permissionName);
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    return PermissionManager::GetInstance().RevokePermission(
        tokenID, permissionName, flag, static_cast<UpdatePermissionFlag>(updateFlag), killProcess);
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
        ReportPermissionVerifyEvent(callingTokenID, permissionName);
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
        ReportPermissionVerifyEvent(callingTokenID, "");
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
        ReportPermissionVerifyEvent(callingTokenID, "");
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    if (!DataValidator::IsListSizeValid(permissionList.size())) {
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

    if (scope.scope.tokenIDs.size() != 1) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "RegisterSelf can only monitor one token, but got %{public}zu tokens.",
            scope.scope.tokenIDs.size());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (scope.scope.tokenIDs[0] != callingTokenID) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "RegisterSelf can only monitor self tokenID, expected %{public}u, got %{public}u.",
            callingTokenID, scope.scope.tokenIDs[0]);
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

    HapPolicy filteredPolicy = policy.hapPolicy;
    FilterPermFeature(info.hapInfoParameter.isSystemApp, filteredPolicy);

    std::vector<GenericValues> undefValues;
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info.hapInfoParameter, filteredPolicy, tokenIdEx, undefValues);
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
        tmp.feature = perm.feature;
        policyOut.permStateList.emplace_back(tmp);
    }
    policyOut.checkIgnore = policyIn.hapPolicy.checkIgnore;
    policyOut.aclExtendedMap = policyIn.hapPolicy.aclExtendedMap;
    policyOut.isDebugGrant = policyIn.hapPolicy.isDebugGrant;
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
    FilterPermFeature(info.hapInfoParameter.isSystemApp, policyCopy);

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

    if (hapInfoParm.isSkillHap) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Skip hap token creation for skill %{public}s.", hapInfoParm.bundleName.c_str());
        fullTokenId = static_cast<uint64_t>(INVALID_TOKENID);
        return RET_SUCCESS;
    }

    AccessTokenIDEx tokenIdEx;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        hapInfoParm, policyCopy, tokenIdEx, undefValues);
    fullTokenId = tokenIdEx.tokenIDEx;
    ReportAddHap(tokenIdEx, hapInfoParm, policyCopy, beginTime, ret);
    return ret;
}

int AccessTokenManagerService::DeleteToken(AccessTokenID tokenID, bool isTokenReserved)
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
    int32_t sceneCode = isTokenReserved ? AT_DELETE_KEEP_TOKEN_FINISH : AT_COMMON_FINISH;
    if (errorCode != ERR_OK) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to get hap info of %{public}u, err %{public}d.", tokenID, errorCode);
        dfxInfo.duration = TimeUtil::GetCurrentTimestamp() - beginTime;
        ReportSysEventDelHap(errorCode, sceneCode, dfxInfo);
        return errorCode;
    }

    // only support hap token deletion
    errorCode = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID, isTokenReserved);

    dfxInfo.userID = hapInfo.userID;
    dfxInfo.bundleName = hapInfo.bundleName;
    dfxInfo.instIndex = hapInfo.instIndex;
    dfxInfo.duration = TimeUtil::GetCurrentTimestamp() - beginTime;
    ReportSysEventDelHap(errorCode, sceneCode, dfxInfo);
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

void TransferUpdateHapInfo(const UpdateHapInfoParamsIdl& infoIdl, UpdateHapInfoParams& info)
{
    info.appIDDesc = infoIdl.appIDDesc;
    info.apiVersion = infoIdl.apiVersion;
    info.isSystemApp = infoIdl.isSystemApp;
    info.appDistributionType = infoIdl.appDistributionType;
    info.isAtomicService = infoIdl.isAtomicService;
    info.dataRefresh = infoIdl.dataRefresh;
    info.appProvisionType = infoIdl.appProvisionType;
    info.isSkillHap = infoIdl.isSkillHap;
}

int32_t AccessTokenManagerService::UpdateHapToken(uint64_t& fullTokenId, const UpdateHapInfoParamsIdl& infoIdl,
    const HapPolicyParcel& policyParcel, HapInfoCheckResultIdl& resultInfoIdl)
{
    AccessTokenIDEx tokenIdEx;
    tokenIdEx.tokenIDEx = fullTokenId;
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    LOGI(ATM_DOMAIN, ATM_TAG, "Id %{public}u, callerPid %{public}d.", tokenID, IPCSkeleton::GetCallingPid());
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(callingTokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();
    UpdateHapInfoParams info;
    TransferUpdateHapInfo(infoIdl, info);
    HapPolicy policy = policyParcel.hapPolicy;
    FilterPermFeature(info.isSystemApp, policy);
    resultInfoIdl.realResult = ERR_OK;
    HapInfoCheckResult permCheckResult;
    std::vector<GenericValues> undefValues;
    std::vector<PermissionStatus> initializedList;
    HapInitInfo initInfo;
    initInfo.updateInfo = info;
    initInfo.policy = policy;
    initInfo.isUpdate = true;
    initInfo.tokenID = tokenID;
    HapTokenInfo hapInfo = { 0 };

    if (!PermissionManager::GetInstance().InitPermissionList(initInfo, initializedList, permCheckResult, undefValues)) {
        resultInfoIdl.realResult = ERROR;
        resultInfoIdl.permissionName = permCheckResult.permCheckResult.permissionName;
        resultInfoIdl.rule = static_cast<PermissionRulesEnumIdl>(permCheckResult.permCheckResult.rule);
        ReportUpdateHap(tokenIdEx, hapInfo, policyParcel.hapPolicy, beginTime, ERR_PERM_REQUEST_CFG_FAILED);
        return ERR_OK;
    }
    if (info.isSkillHap) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Skip hap token update for skill.");
        fullTokenId = static_cast<uint64_t>(INVALID_TOKENID);
        return RET_SUCCESS;
    }

    int32_t error = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, hapInfo);
    if (error != ERR_OK) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to get hap info of %{public}u) err %{public}d.", tokenID, error);
        ReportUpdateHap(tokenIdEx, hapInfo, policyParcel.hapPolicy, beginTime, error);
        return error;
    }
    initInfo.bundleName = hapInfo.bundleName;
    error = AccessTokenInfoManager::GetInstance().UpdateHapToken(tokenIdEx, info, initializedList, policy, undefValues);
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
    AccessTokenInfoManager::GetInstance().GetTokenIDByUserID(userID, tokenIdList);
    std::copy(tokenIdList.begin(), tokenIdList.end(), std::back_inserter(tokenIds));
    return RET_SUCCESS;
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

int32_t AccessTokenManagerService::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoCompatIdl& infoIdl)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Id %{public}d.", tokenID);

    if (!IsNativeProcessCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    HapTokenInfo tokenInfo;
    int32_t error = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, tokenInfo);
    infoIdl.bundleName = tokenInfo.bundleName;
    infoIdl.userID = tokenInfo.userID;
    infoIdl.instIndex = tokenInfo.instIndex;
    infoIdl.apiVersion = tokenInfo.apiVersion;
    return error;
}

int32_t AccessTokenManagerService::GetPermissionCode(const std::string& permission, uint32_t& opCode)
{
    if (!TransferPermissionToOpcode(permission, opCode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm(%{public}s) is not exist.", permission.c_str());
        return ERR_PERMISSION_NOT_EXIST;
    }
    return RET_SUCCESS;
}

int AccessTokenManagerService::GetHapTokenInfoExtension(AccessTokenID tokenID,
    HapTokenInfoParcel& hapTokenInfoRes, std::string& appID)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Id %{public}u.", tokenID);
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}u).", IPCSkeleton::GetCallingTokenID());
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
    LOGI(ATM_DOMAIN, ATM_TAG, "CallerPid %{public}d, bundle %{public}s.", IPCSkeleton::GetCallingPid(),
        hapBaseInfoParcel.hapBaseInfo.bundleName.c_str());
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
    PermDialogCapInfo info;
    info.tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    info.userID = hapBaseInfoParcel.hapBaseInfo.userID;
    info.bundleName = hapBaseInfoParcel.hapBaseInfo.bundleName;
    info.instIndex = hapBaseInfoParcel.hapBaseInfo.instIndex;
    info.enable = enable;
    ReportSetPermDialogCapEvent(info);
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

#ifdef SUPPORT_MANAGE_USER_POLICY
int32_t AccessTokenManagerService::SetUserPolicy(const std::vector<UserPermissionPolicyIdl>& userPermissionList)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "CallerPid %{public}d.", IPCSkeleton::GetCallingPid());
    size_t policySize = userPermissionList.size();
    if ((policySize == 0) || (policySize > MAX_USER_POLICY_SIZE)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PolicySize %{public}zu is invalid.", policySize);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, MANAGE_USER_POLICY) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
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
    size_t permSize = permissionList.size();
    if ((permSize == 0) || (permSize > MAX_USER_POLICY_SIZE)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermSize %{public}zu is invalid.", permSize);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, MANAGE_USER_POLICY) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    return AccessTokenInfoManager::GetInstance().ClearUserPolicy(permissionList);
}

int32_t AccessTokenManagerService::UpdatePolicyWhiteList(AccessTokenID tokenId, uint32_t permCode, int32_t type)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "CallerPid %{public}d.", IPCSkeleton::GetCallingPid());
    auto updateType = static_cast<UpdateWhiteListType>(type);
    if (!DataValidator::IsTokenIDValid(tokenId) || !DataValidator::IsUpdateWhiteListTypeValid(updateType)) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (this->GetTokenType(tokenId) != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id=%{public}u is not hap.", tokenId);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    std::string permission = TransferOpcodeToPermission(permCode);
    if (permission.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid permCode: %{public}u.", permCode);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, MANAGE_USER_POLICY) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return AccessTokenInfoManager::GetInstance().UpdatePolicyWhiteList(tokenId, permCode, updateType);
}

int32_t AccessTokenManagerService::GetPolicyWhiteList(uint32_t permCode, std::vector<AccessTokenID>& tokenIdList)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "CallerPid %{public}d.", IPCSkeleton::GetCallingPid());
    std::string permission = TransferOpcodeToPermission(permCode);
    if (permission.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid permCode: %{public}u.", permCode);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, MANAGE_USER_POLICY) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return AccessTokenInfoManager::GetInstance().GetPolicyWhiteList(permCode, tokenIdList);
}
#endif

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
    if (policy->GetConfigValue(ConfigType::ACCESSTOKEN_SERVICE, value)) {
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

void AccessTokenManagerService::GetFeaturesConfig()
{
    LibraryLoader loader(CONFIG_PARSE_LIBPATH);
    ConfigPolicyLoaderInterface* policy = loader.GetObject<ConfigPolicyLoaderInterface>();
    if (policy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Dlopen libaccesstoken_json_parse failed.");
        return;
    }
    AccessTokenConfigValue value;
    if (policy->GetConfigValue(ConfigType::PERMISSION_FEATURES, value)) {
        features_ = value.permissionFeatures;
    }
}

void AccessTokenManagerService::FilterPermFeature(bool isSystemApp, HapPolicy& policy)
{
    if (!isSystemApp) {
        return;
    }
    for (auto it = policy.permStateList.begin(); it != policy.permStateList.end();) {
        if (it->feature.empty()) {
            ++it;
            continue;
        }

        featureFuture_.wait();
        if (features_.find(it->feature) != features_.end()) {
            ++it;
            continue;
        }
        LOGI(ATM_DOMAIN, ATM_TAG, "%{public}s filter by feature", it->permissionName.c_str());
        it = policy.permStateList.erase(it);
    }
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

    isInitialize_ = true;
    std::thread getFeature([this]() {
        this->GetFeaturesConfig();
        this->featurePromise_.set_value();
    });
    getFeature.detach();

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

int32_t AccessTokenManagerService::ValidateGetCliPermissionRequestInfoCaller(
    AccessTokenID callingTokenId, const std::string& agentID, const std::vector<CliInfoParcel>& cliInfoList)
{
    if (!IsAgentIdValid(agentID) || !IsCliInfoListSizeValid(cliInfoList.size()) ||
        !AreCliInfosValid(cliInfoList)) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetCliPermissionRequestInfo invalid param, callerToken=%{public}u, agentID=%{public}s, "
            "cliSize=%{public}zu.", callingTokenId, agentID.c_str(), cliInfoList.size());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!IsSystemAppCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetCliPermissionRequestInfo non-system caller, callerToken=%{public}u, "
            "agentID=%{public}s, cliSize=%{public}zu.",
            callingTokenId, agentID.c_str(), cliInfoList.size());
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    if (VerifyAccessToken(callingTokenId, QUERY_TOOL_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Caller does not have QUERY_TOOL_PERMISSIONS permission.");
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::ValidateGetCliPermissionsCaller(AccessTokenID callingTokenId,
    AccessTokenID hostTokenID, const std::string& agentID, const std::vector<CliInfoParcel>& cliInfoList)
{
    int32_t ret = ValidateHostTokenId(hostTokenID);
    if ((ret != RET_SUCCESS) || !IsAgentIdValid(agentID) || !IsCliInfoListSizeValid(cliInfoList.size()) ||
        !AreCliInfosValid(cliInfoList)) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetCliPermissions invalid param, callerToken=%{public}u, targetToken=%{public}u, "
            "agentID=%{public}s, cliSize=%{public}zu, ret=%{public}d.",
            callingTokenId, hostTokenID, agentID.c_str(), cliInfoList.size(), ret);
        return (ret == RET_SUCCESS) ? AccessTokenError::ERR_PARAM_INVALID : ret;
    }
    if (!IsSystemAppCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetCliPermissions non-system caller, callerToken=%{public}u, targetToken=%{public}u, "
            "agentID=%{public}s.", callingTokenId, hostTokenID, agentID.c_str());
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    if (VerifyAccessToken(callingTokenId, MANAGE_TOOL_RUNTIME_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Caller does not have MANAGE_TOOL_RUNTIME_PERMISSIONS permission.");
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return RET_SUCCESS;
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

ErrCode AccessTokenManagerService::QueryStatusByPermission(const std::vector<uint32_t>& permCodeList,
    std::vector<PermissionStatusIdl>& permissionInfoList, bool onlyHap)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Start, permCodeList size: %{public}zu, onlyHap: %{public}d",
        permCodeList.size(), onlyHap);

    AccessTokenID callingTokenId = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenId) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Third-party app is not allowed to call this interface.");
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    if ((IsShellProcessCalling() || (this->GetTokenType(callingTokenId) == TOKEN_HAP)) && !onlyHap) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Shell or hap process only allow onlyHap=true.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!IsShellProcessCalling() &&
        VerifyAccessToken(callingTokenId, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Caller does not have GET_SENSITIVE_PERMISSIONS permission.");
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    if (!DataValidator::IsListSizeValid(permCodeList.size())) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    int32_t ret = AccessTokenInfoManager::GetInstance().QueryStatusByPermission(
        permCodeList, permissionInfoList, onlyHap);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "QueryStatusByPermission failed, ret: %{public}d.", ret);
        return ret;
    }
    size_t maxQueryResultSize = AccessTokenInfoManager::GetInstance().GetMaxQueryResultSize();
    if (permissionInfoList.size() > maxQueryResultSize) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Query result size %{public}zu exceeds max limit %{public}zu.",
            permissionInfoList.size(), maxQueryResultSize);
        permissionInfoList.clear();
        return AccessTokenError::ERR_OVERSIZE;
    }
    return RET_SUCCESS;
}

ErrCode AccessTokenManagerService::QueryStatusByTokenID(const std::vector<uint32_t>& tokenIDList,
    std::vector<PermissionStatusIdl>& permissionInfoList)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Start, tokenIDList size: %{public}zu", tokenIDList.size());

    AccessTokenID callingTokenId = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenId) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Third-party app is not allowed to call this interface.");
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    if (!IsShellProcessCalling() &&
        VerifyAccessToken(callingTokenId, GET_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Caller does not have GET_SENSITIVE_PERMISSIONS permission.");
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    if (!DataValidator::IsListSizeValid(tokenIDList.size())) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    permissionInfoList.clear();
    int32_t ret = AccessTokenInfoManager::GetInstance().QueryStatusByTokenID(tokenIDList, permissionInfoList);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "QueryStatusByTokenID failed, ret: %{public}d.", ret);
        return ret;
    }

    size_t maxQueryResultSize = AccessTokenInfoManager::GetInstance().GetMaxQueryResultSize();
    if (permissionInfoList.size() > maxQueryResultSize) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Query result size %{public}zu exceeds max limit %{public}zu.",
            permissionInfoList.size(), maxQueryResultSize);
        permissionInfoList.clear();
        return AccessTokenError::ERR_OVERSIZE;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "End, result size: %{public}zu", permissionInfoList.size());
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::GetCliPermissionRequestInfo(
    const std::string& agentID, const std::vector<CliInfoParcel>& cliInfoList,
    PermissionDialogResultParcel& resultParcel)
{
    AccessTokenID callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t ret = ValidateGetCliPermissionRequestInfoCaller(callingTokenId, agentID, cliInfoList);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    std::vector<CliInfo> cliInfos = ConvertCliInfoParcels(cliInfoList);

    ret = ValidateClawCliAccess(callingTokenId, cliInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetCliPermissionRequestInfo validate failed, callerToken=%{public}u, agentID=%{public}s, "
            "cliSize=%{public}zu, ret=%{public}d.",
            callingTokenId, agentID.c_str(), cliInfos.size(), ret);
        return ret;
    }

    PermissionDialogResult result;
    ret = ClawPermissionDecisionEngine::GetInstance().BuildCliPermissionDialogInfo(
        callingTokenId, cliInfos, result);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetCliPermissionRequestInfo build failed, callerToken=%{public}u, agentID=%{public}s, "
            "cliSize=%{public}zu, ret=%{public}d.",
            callingTokenId, agentID.c_str(), cliInfos.size(), ret);
        return ret;
    }
    ret = FillCliDialogAuthResultsIfNoDialog(callingTokenId, agentID, cliInfos, result);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    resultParcel.result = result;
    LOGI(ATM_DOMAIN, ATM_TAG,
        "GetCliPermissionRequestInfo done, callerToken=%{public}u, agentID=%{public}s, "
        "cliSize=%{public}zu, detailSize=%{public}zu, dialogDetails=%{public}zu.",
        callingTokenId, agentID.c_str(), cliInfos.size(), result.detailList.size(),
        CountDialogDetails(result.detailList));
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::GetSkillPermissionRequestInfo(
    const std::string& agentID, const std::vector<SkillInfoParcel>& skillInfoList,
    PermissionDialogResultParcel& resultParcel)
{
    AccessTokenID callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (!IsAgentIdValid(agentID) || !DataValidator::IsListSizeValid(skillInfoList.size())) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetSkillPermissionRequestInfo invalid param, callerToken=%{public}u, agentID=%{public}s, "
            "skillSize=%{public}zu.", callingTokenId, agentID.c_str(), skillInfoList.size());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!IsSystemAppCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetSkillPermissionRequestInfo non-system caller, callerToken=%{public}u, "
            "agentID=%{public}s, skillSize=%{public}zu.",
            callingTokenId, agentID.c_str(), skillInfoList.size());
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    if (VerifyAccessToken(callingTokenId, QUERY_TOOL_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Caller does not have QUERY_TOOL_PERMISSIONS permission.");
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    std::vector<SkillInfo> skillInfos;
    skillInfos.reserve(skillInfoList.size());
    for (const auto& skillInfoParcel : skillInfoList) {
        skillInfos.emplace_back(skillInfoParcel.skillInfo);
    }

    PermissionDialogResult result;
    int32_t ret = ClawPermissionDecisionEngine::GetInstance().BuildSkillPermissionDialogInfo(
        callingTokenId, skillInfos, result);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetSkillPermissionRequestInfo build failed, callerToken=%{public}u, agentID=%{public}s, "
            "skillSize=%{public}zu, ret=%{public}d.",
            callingTokenId, agentID.c_str(), skillInfos.size(), ret);
        return ret;
    }
    ret = FillSkillDialogAuthResultsIfNoDialog(callingTokenId, agentID, skillInfos, result);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    resultParcel.result = result;
    LOGI(ATM_DOMAIN, ATM_TAG,
        "GetSkillPermissionRequestInfo done, callerToken=%{public}u, agentID=%{public}s, "
        "skillSize=%{public}zu, detailSize=%{public}zu, dialogDetails=%{public}zu.",
        callingTokenId, agentID.c_str(), skillInfos.size(), result.detailList.size(),
        CountDialogDetails(result.detailList));
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::GetCliPermissions(AccessTokenID hostTokenID, const std::string& agentID,
    const std::vector<CliInfoParcel>& cliInfoList, CliPermissionsResultParcel& resultParcel)
{
    AccessTokenID callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t ret = ValidateGetCliPermissionsCaller(callingTokenId, hostTokenID, agentID, cliInfoList);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    std::vector<CliInfo> cliInfos = ConvertCliInfoParcels(cliInfoList);

    ret = ValidateClawCliAccess(hostTokenID, cliInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetCliPermissions validate cli access failed, targetToken=%{public}u, "
            "agentID=%{public}s, cliSize=%{public}zu, ret=%{public}d.",
            hostTokenID, agentID.c_str(), cliInfos.size(), ret);
        return ret;
    }

    CliPermissionsResult result;
    ret = ClawPermissionDecisionEngine::GetInstance().BuildCliPermissions(hostTokenID, cliInfos, result);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetCliPermissions build failed, targetToken=%{public}u, agentID=%{public}s, "
            "cliSize=%{public}zu, ret=%{public}d.",
            hostTokenID, agentID.c_str(), cliInfos.size(), ret);
        return ret;
    }
    resultParcel.result = result;
    size_t requiredPermCount = CountRequiredCliPermissions(result);
    LOGI(ATM_DOMAIN, ATM_TAG,
        "GetCliPermissions done, callerToken=%{public}u, targetToken=%{public}u, agentID=%{public}s, "
        "cliSize=%{public}zu, resultSize=%{public}zu, requiredPerms=%{public}zu.",
        callingTokenId, hostTokenID, agentID.c_str(), cliInfos.size(), result.permList.size(),
        requiredPermCount);
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::GetSkillPermissions(AccessTokenID hostTokenID, const std::string& agentID,
    const std::vector<SkillInfoParcel>& skillInfoList, SkillPermissionsResultParcel& resultParcel)
{
    AccessTokenID callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t ret = ValidateHostTokenId(hostTokenID);
    if ((ret != RET_SUCCESS) || !IsAgentIdValid(agentID) || !DataValidator::IsListSizeValid(skillInfoList.size())) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetSkillPermissions invalid param, callerToken=%{public}u, targetToken=%{public}u, "
            "agentID=%{public}s, skillSize=%{public}zu, ret=%{public}d.",
            callingTokenId, hostTokenID, agentID.c_str(), skillInfoList.size(), ret);
        return (ret == RET_SUCCESS) ? AccessTokenError::ERR_PARAM_INVALID : ret;
    }
    if (!IsSystemAppCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetSkillPermissions non-system caller, callerToken=%{public}u, targetToken=%{public}u, "
            "agentID=%{public}s.", callingTokenId, hostTokenID, agentID.c_str());
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    if (VerifyAccessToken(callingTokenId, MANAGE_TOOL_RUNTIME_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Caller does not have MANAGE_TOOL_RUNTIME_PERMISSIONS permission.");
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    std::vector<SkillInfo> skillInfos;
    skillInfos.reserve(skillInfoList.size());
    for (const auto& skillInfoParcel : skillInfoList) {
        skillInfos.emplace_back(skillInfoParcel.skillInfo);
    }

    SkillPermissionsResult result;
    ret = ClawPermissionDecisionEngine::GetInstance().BuildSkillPermissions(hostTokenID, skillInfos, result);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetSkillPermissions build failed, targetToken=%{public}u, agentID=%{public}s, "
            "skillSize=%{public}zu, ret=%{public}d.",
            hostTokenID, agentID.c_str(), skillInfos.size(), ret);
        return ret;
    }
    resultParcel.result = result;
    size_t usedPermCount = 0;
    for (const auto& perm : result.permList) {
        usedPermCount += perm.usedPermissions.size();
    }
    LOGI(ATM_DOMAIN, ATM_TAG,
        "GetSkillPermissions done, callerToken=%{public}u, targetToken=%{public}u, agentID=%{public}s, "
        "skillSize=%{public}zu, resultSize=%{public}zu, usedPerms=%{public}zu.",
        callingTokenId, hostTokenID, agentID.c_str(), skillInfos.size(), result.permList.size(),
        usedPermCount);
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::GenerateCliAuthResult(
    AccessTokenID hostTokenID, const std::string& agentID,
    const std::vector<CliAuthInfoParcel>& authInfoList, ToolAuthResultParcel& resultParcel)
{
    AccessTokenID callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t ret = ValidateHostTokenId(hostTokenID);
    if ((ret != RET_SUCCESS) || !IsAgentIdValid(agentID) || !IsCliInfoListSizeValid(authInfoList.size()) ||
        !AreCliAuthInfosValid(authInfoList)) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GenerateCliAuthResult invalid param, callerToken=%{public}u, targetToken=%{public}u, "
            "agentID=%{public}s, authSize=%{public}zu, ret=%{public}d.",
            callingTokenId, hostTokenID, agentID.c_str(), authInfoList.size(), ret);
        return (ret == RET_SUCCESS) ? AccessTokenError::ERR_PARAM_INVALID : ret;
    }
    for (size_t i = 0; i < authInfoList.size(); ++i) {
        if (!IsCliAuthInfoValid(authInfoList[i].info)) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "GenerateCliAuthResult invalid auth info, targetToken=%{public}u, index=%{public}zu, "
                "permissionSize=%{public}zu, resultSize=%{public}zu.",
                hostTokenID, i, authInfoList[i].info.permissionNames.size(),
                authInfoList[i].info.authorizationResults.size());
            return AccessTokenError::ERR_PARAM_INVALID;
        }
    }
    if (!IsSystemAppCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GenerateCliAuthResult non-system caller, callerToken=%{public}u, targetToken=%{public}u, "
            "agentID=%{public}s.", callingTokenId, hostTokenID, agentID.c_str());
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    if (VerifyAccessToken(callingTokenId, MANAGE_TOOL_RUNTIME_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Caller does not have MANAGE_TOOL_RUNTIME_PERMISSIONS permission.");
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    resultParcel.result.authResults.clear();
    std::vector<CliAuthInfo> authInfos;
    ret = BuildCliTicketAuthInfos(hostTokenID, authInfoList, authInfos);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    ret = ClawTicketManager::GetInstance().GenerateCliTicket(hostTokenID, authInfos, resultParcel.result.authResults);
    LOGI(ATM_DOMAIN, ATM_TAG,
        "GenerateCliAuthResult done, callerToken=%{public}u, targetToken=%{public}u, agentID=%{public}s, "
        "authSize=%{public}zu, ret=%{public}d, authResultSize=%{public}zu.",
        callingTokenId, hostTokenID, agentID.c_str(), authInfos.size(), ret,
        resultParcel.result.authResults.size());
    return ret;
}

int32_t AccessTokenManagerService::GenerateSkillAuthResult(
    AccessTokenID hostTokenID, const std::string& agentID,
    const std::vector<SkillAuthInfoParcel>& authInfoList, ToolAuthResultParcel& resultParcel)
{
    AccessTokenID callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t ret = ValidateHostTokenId(hostTokenID);
    if ((ret != RET_SUCCESS) || !IsAgentIdValid(agentID) || !DataValidator::IsListSizeValid(authInfoList.size())) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GenerateSkillAuthResult invalid param, callerToken=%{public}u, targetToken=%{public}u, "
            "agentID=%{public}s, authSize=%{public}zu, ret=%{public}d.",
            callingTokenId, hostTokenID, agentID.c_str(), authInfoList.size(), ret);
        return (ret == RET_SUCCESS) ? AccessTokenError::ERR_PARAM_INVALID : ret;
    }
    for (size_t i = 0; i < authInfoList.size(); ++i) {
        if (!IsSkillAuthInfoValid(authInfoList[i].info)) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "GenerateSkillAuthResult invalid auth info, targetToken=%{public}u, index=%{public}zu, "
                "permissionSize=%{public}zu, resultSize=%{public}zu.",
                hostTokenID, i, authInfoList[i].info.permissionNames.size(),
                authInfoList[i].info.authorizationResults.size());
            return AccessTokenError::ERR_PARAM_INVALID;
        }
    }
    if (!IsSystemAppCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GenerateSkillAuthResult non-system caller, callerToken=%{public}u, targetToken=%{public}u, "
            "agentID=%{public}s.", callingTokenId, hostTokenID, agentID.c_str());
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    if (VerifyAccessToken(callingTokenId, MANAGE_TOOL_RUNTIME_PERMISSIONS) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Caller does not have MANAGE_TOOL_RUNTIME_PERMISSIONS permission.");
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    resultParcel.result.authResults.clear();
    std::vector<SkillAuthInfo> authInfos;
    authInfos.reserve(authInfoList.size());
    for (size_t i = 0; i < authInfoList.size(); ++i) {
        authInfos.emplace_back(authInfoList[i].info);
    }
    ret = ClawTicketManager::GetInstance().GenerateSkillTicket(
        hostTokenID, authInfos, resultParcel.result.authResults);
    LOGI(ATM_DOMAIN, ATM_TAG,
        "GenerateSkillAuthResult done, callerToken=%{public}u, targetToken=%{public}u, agentID=%{public}s, "
        "authSize=%{public}zu, ret=%{public}d, authResultSize=%{public}zu.",
        callingTokenId, hostTokenID, agentID.c_str(), authInfos.size(), ret,
        resultParcel.result.authResults.size());
    return ret;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
