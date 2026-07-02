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

#include <memory>
#include <mutex>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include <unistd.h>

#include "access_token.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "bundle_infos_rawdata_helper.h"
#include "check_hap_sign_result_rawdata_helper.h"
#include "claw_permission_info.h"
#include "accesstoken_common_log.h"
#include "accesstoken_dfx_define.h"
#include "claw_permission_info.h"
#include "claw_permission_decision_engine.h"
#include "claw_permission_metadata_provider.h"
#include "claw_permission_status_helper.h"
#include "claw_ticket_manager.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_dumper.h"
#include "callback_manager.h"
#include "accesstoken_migration_manager.h"
#include "constant_common.h"
#include "claw_token_info_manager.h"
#include "data_usage_dfx.h"
#include "data_validator.h"
#include "delete_bundle_manager.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "hisysevent_adapter.h"
#ifdef HITRACE_NATIVE_ENABLE
#include "hitrace_meter.h"
#endif
#ifdef IS_SUPPORT_HAP_RUNNING
#include "interfaces/hap_verify.h"
#include "provision/provision_info.h"
#endif
#include "ipc_skeleton.h"
#include "libraryloader.h"
#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
#include "install_session_manager.h"
#endif
#include "memory_guard.h"
#include "parameter.h"
#include "parameters.h"
#include "permission_change_notifier.h"
#include "permission_list_state.h"
#include "permission_manager.h"
#include "permission_constraint_check.h"
#include "permission_data_brief.h"
#include "permission_feature_manager.h"
#include "permission_kernel_utils.h"
#include "permission_map.h"
#include "permission_request_toggle_manager.h"
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
#include "user_policy_manager.h"
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
static constexpr int MAX_SET_USER_POLICY_SIZE = 200;
#endif
const std::string GET_TRUSTED_BUNDLE_INFO = "ohos.permission.GET_TRUSTED_BUNDLE_INFO";
const std::string GRANT_SENSITIVE_PERMISSIONS = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
const std::string REVOKE_SENSITIVE_PERMISSIONS = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS";
const std::string GET_SENSITIVE_PERMISSIONS = "ohos.permission.GET_SENSITIVE_PERMISSIONS";
const std::string DISABLE_PERMISSION_DIALOG = "ohos.permission.DISABLE_PERMISSION_DIALOG";
const std::string GRANT_SHORT_TERM_WRITE_MEDIAVIDEO = "ohos.permission.GRANT_SHORT_TERM_WRITE_MEDIAVIDEO";
const std::string MANAGE_EDM_POLICY = "ohos.permission.MANAGE_EDM_POLICY";
const std::string MANAGE_TOOL_TOKENID = "ohos.permission.MANAGE_TOOL_TOKENID";
const std::string MANAGE_CLAW_TOKEN = "ohos.permission.MANAGE_CLAW_TOKEN";
const std::string QUERY_TOOL_PERMISSIONS = "ohos.permission.QUERY_TOOL_PERMISSIONS";
const std::string MANAGE_TOOL_RUNTIME_PERMISSIONS = "ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS";

static constexpr int32_t SA_ID_ACCESSTOKEN_MANAGER_SERVICE = 3503;
std::mutex g_userPolicyUpdateMutex;

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

bool FindPermissionStatusInDetail(const PermissionDialogDetail& detail, const std::string& permissionName,
    PermissionDecisionStatus& status)
{
    for (size_t i = 0; i < detail.permissionNameList.size() && i < detail.statusList.size(); ++i) {
        if (detail.permissionNameList[i] != permissionName) {
            continue;
        }
        status = detail.statusList[i];
        return true;
    }
    return false;
}

std::vector<bool> BuildCliAuthorizationResults(const std::vector<std::string>& permissionNames,
    const PermissionDialogDetail& detail)
{
    std::vector<bool> results;
    results.reserve(permissionNames.size());
    for (const auto& permissionName : permissionNames) {
        PermissionDecisionStatus status = PermissionDecisionStatus::NO_DIALOG_GRANTED;
        bool hasStatus = FindPermissionStatusInDetail(detail, permissionName, status);
        results.emplace_back(!hasStatus);
    }
    return results;
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

bool AreCliInfosValid(const std::vector<CliInfoIdl>& cliInfoList)
{
    for (const auto& info : cliInfoList) {
        CliInfo cliInfo = {
            .cliName = info.cliName,
            .subCliName = info.subCliName,
        };
        if (!IsCliInfoValid(cliInfo)) {
            return false;
        }
    }
    return true;
}

bool IsCliInfoListSizeValid(size_t size)
{
    return (size > 0) && (size <= MAX_CLAW_CLI_INFO_LIST_SIZE);
}

void UpdatePermissionStates(const std::vector<PermissionStatus>& permsList,
    std::vector<PermissionListStateParcel>& reqPermList, int32_t apiVersion, bool& needRes, bool& fixedByPolicyRes)
{
    for (auto& reqPerm : reqPermList) {
        bool isLocationPermission = ((reqPerm.permsState.permissionName == VAGUE_LOCATION_PERMISSION_NAME) ||
            (reqPerm.permsState.permissionName == ACCURATE_LOCATION_PERMISSION_NAME) ||
            (reqPerm.permsState.permissionName == BACKGROUND_LOCATION_PERMISSION_NAME)) &&
            (apiVersion >= ACCURATE_LOCATION_API_VERSION);
        if (isLocationPermission) {
            continue;
        }

        PermissionManager::GetInstance().GetSelfPermissionState(permsList, reqPerm.permsState, apiVersion);
        auto permOper = static_cast<PermissionOper>(reqPerm.permsState.state);
        needRes = (permOper == DYNAMIC_OPER) ? true : needRes;
        if (permOper == FORBIDDEN_OPER) {
            fixedByPolicyRes = true;
        }
        LOGD(ATM_DOMAIN, ATM_TAG, "Perm %{public}s, state %{public}d, errorReason %{public}d.",
            reqPerm.permsState.permissionName.c_str(), reqPerm.permsState.state, reqPerm.permsState.errorReason);
    }
}

PermissionOper HandlePermissionDialogCap(AccessTokenID tokenID, std::vector<PermissionListStateParcel>& reqPermList)
{
    if (AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id %{public}d is under control.", tokenID);
        for (auto& reqPerm : reqPermList) {
            if (reqPerm.permsState.state != INVALID_OPER) {
                reqPerm.permsState.state = FORBIDDEN_OPER;
                reqPerm.permsState.errorReason = PRIVACY_STATEMENT_NOT_AGREED;
            }
        }
        return FORBIDDEN_OPER;
    }
    return PASS_OPER;
}

PermissionDecisionStatusIdl ConvertPermissionDecisionStatus(PermissionDecisionStatus status)
{
    return static_cast<PermissionDecisionStatusIdl>(status);
}

CliAuthInfo ConvertCliAuthInfoIdl(const CliAuthInfoIdl& authInfoIdl)
{
    CliAuthInfo authInfo;
    authInfo.cliInfo = {
        .cliName = authInfoIdl.cliInfo.cliName,
        .subCliName = authInfoIdl.cliInfo.subCliName,
    };
    authInfo.permissionNames = authInfoIdl.permissionNames;
    authInfo.authorizationResults.assign(
        authInfoIdl.authorizationResults.begin(), authInfoIdl.authorizationResults.end());
    return authInfo;
}

CliPermissionsResultIdl ConvertCliPermissionsResult(const CliPermissionsResult& result)
{
    CliPermissionsResultIdl resultIdl;
    resultIdl.permList.reserve(result.permList.size());
    for (const auto& permResult : result.permList) {
        CliCommandPermissionResultIdl permResultIdl;
        permResultIdl.requiredCliPermissions.reserve(permResult.requiredCliPermissions.size());
        for (const auto& cliPermDetail : permResult.requiredCliPermissions) {
            permResultIdl.requiredCliPermissions.emplace_back(CliPermissionDetailIdl {
                .requiredCliPermission = cliPermDetail.requiredCliPermission,
                .cliPermissionStatus = ConvertPermissionDecisionStatus(cliPermDetail.cliPermissionStatus),
                .usedPermissions = cliPermDetail.usedPermissions,
            });
        }
        resultIdl.permList.emplace_back(std::move(permResultIdl));
    }
    return resultIdl;
}

PermissionDialogResultIdl ConvertPermissionDialogResult(const PermissionDialogResult& result)
{
    PermissionDialogResultIdl resultIdl;
    resultIdl.detailList.reserve(result.detailList.size());
    for (const auto& detail : result.detailList) {
        PermissionDialogDetailIdl detailIdl;
        detailIdl.needPermissionDialog = detail.needPermissionDialog;
        detailIdl.permissionNameList = detail.permissionNameList;
        detailIdl.authResult = detail.authResult;
        detailIdl.statusList.reserve(detail.statusList.size());
        for (const auto& status : detail.statusList) {
            detailIdl.statusList.emplace_back(ConvertPermissionDecisionStatus(status));
        }
        resultIdl.detailList.emplace_back(std::move(detailIdl));
    }
    return resultIdl;
}

ToolAuthResultIdl ConvertToolAuthResult(const ToolAuthResult& result)
{
    return { .authResults = result.authResults };
}

using DeclaredPermissionNameSet = std::unordered_set<std::string>;

bool ArePermissionNamesValid(const std::vector<std::string>& permissionList)
{
    for (const auto& permissionName : permissionList) {
        if (!DataValidator::IsPermissionNameValid(permissionName)) {
            return false;
        }
    }
    return true;
}

int32_t ResolvePermissionDetailBase(const std::string& permissionName,
    const DeclaredPermissionNameSet& declaredPermissions, PermissionResultTypeIdl& resultType, uint32_t& permCode)
{
    PermissionBriefDef briefDef;
    if (!GetPermissionBriefDef(permissionName, briefDef) || !briefDef.isEnable) {
        resultType = PermissionResultTypeIdl::PERMISSION_NOT_EXIST;
        return RET_SUCCESS;
    }
    if (declaredPermissions.find(permissionName) == declaredPermissions.end()) {
        resultType = PermissionResultTypeIdl::PERMISSION_NOT_DECLARED;
        return RET_SUCCESS;
    }

    if (!TransferPermissionToOpcode(permissionName, permCode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission transfer to opcode failed, permission=%{public}s.",
            permissionName.c_str());
        return ERR_PERMISSION_NOT_EXIST;
    }
    resultType = PermissionResultTypeIdl::PERMISSION_VALID;
    return RET_SUCCESS;
}

int32_t BuildPermissionStatusDetail(AccessTokenID tokenID, const std::string& permissionName,
    const DeclaredPermissionNameSet& declaredPermissions, PermissionStatusDetailIdl& result)
{
    result.permissionName = permissionName;
    result.grantStatus = PermissionState::PERMISSION_DENIED;
    result.grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    uint32_t permCode = 0;
    int32_t ret = ResolvePermissionDetailBase(permissionName, declaredPermissions, result.resultType, permCode);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    if (result.resultType != PermissionResultTypeIdl::PERMISSION_VALID) {
        return RET_SUCCESS;
    }

    return PermissionDataBrief::GetInstance().QueryEffectivePermissionStatusAndFlag(
        tokenID, permCode, result.grantStatus, result.grantFlag);
}

bool AreCliAuthInfosValid(const std::vector<CliAuthInfoIdl>& authInfoList)
{
    for (const auto& info : authInfoList) {
        CliInfo cliInfo = {
            .cliName = info.cliInfo.cliName,
            .subCliName = info.cliInfo.subCliName,
        };
        if (!IsCliInfoValid(cliInfo) || (info.permissionNames.size() != info.authorizationResults.size())) {
            return false;
        }
        for (const auto& permissionName : info.permissionNames) {
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
        authInfo.authorizationResults = BuildCliAuthorizationResults(authInfo.permissionNames, result.detailList[i]);
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

CliInitInfo ConvertCliInitInfoIdl(const CliInitInfoIdl& initInfoIdl)
{
    return {
        .hostTokenId = initInfoIdl.hostTokenId,
        .challenge = initInfoIdl.challenge,
        .cliInfo = {
            .cliName = initInfoIdl.cliInfo.cliName,
            .subCliName = initInfoIdl.cliInfo.subCliName,
        },
    };
}

std::vector<CliInfo> ConvertCliInfoIdls(const std::vector<CliInfoIdl>& cliInfoList)
{
    std::vector<CliInfo> cliInfos;
    cliInfos.reserve(cliInfoList.size());
    for (const auto& cliInfoIdl : cliInfoList) {
        cliInfos.emplace_back(CliInfo {
            .cliName = cliInfoIdl.cliName,
            .subCliName = cliInfoIdl.subCliName,
        });
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

int32_t BuildCliTicketAuthInfos(AccessTokenID hostTokenID, const std::vector<CliAuthInfoIdl>& authInfoList,
    std::vector<CliAuthInfo>& authInfos)
{
    std::vector<CliAuthInfo> rawAuthInfoList;
    rawAuthInfoList.reserve(authInfoList.size());
    for (const auto& authInfoIdl : authInfoList) {
        rawAuthInfoList.emplace_back(ConvertCliAuthInfoIdl(authInfoIdl));
    }
    return BuildCliTicketAuthInfos(hostTokenID, rawAuthInfoList, authInfos);
}

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<AccessTokenManagerService>::GetInstance().get());

} // namespace

int32_t AccessTokenManagerService::PreCheckPermissionStatusDetails(
    AccessTokenID tokenID, const std::vector<std::string>& permissionList)
{
    if (!DataValidator::IsTokenIDValid(tokenID) ||
        !DataValidator::IsListSizeValid(permissionList.size()) || !ArePermissionNamesValid(permissionList)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetPermissionStatusDetails invalid input, tokenId=%{public}u, size=%{public}zu.",
            tokenID, permissionList.size());
        return ERR_PARAM_INVALID;
    }
    if (!IsNativeProcessCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetPermissionStatusDetails permission denied, callingTokenId=%{public}u.",
            IPCSkeleton::GetCallingTokenID());
        return ERR_PERMISSION_DENIED;
    }
    int32_t tokenType = GetTokenType(tokenID);
    if (tokenType == TOKEN_INVALID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetPermissionStatusDetails token does not exist, tokenId=%{public}u.", tokenID);
        return ERR_TOKENID_NOT_EXIST;
    }
    if (tokenType != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetPermissionStatusDetails only supports hap tokenId, tokenId=%{public}u.",
            tokenID);
        return ERR_PARAM_INVALID;
    }
    int32_t ret = PreVerifyHapTokenIfNeeded(tokenID);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Pre verify bundle by token failed, tokenId=%{public}u, ret=%{public}d.",
            tokenID, ret);
    }
    return ret;
}

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
    int32_t ret = PreVerifyHapTokenIfNeeded(tokenID);
    if (ret != RET_SUCCESS) {
        permUsedType = static_cast<int32_t>(PermUsedTypeEnum::INVALID_USED_TYPE);
        return ret;
    }
    permUsedType = static_cast<int32_t>(
        PermissionManager::GetInstance().GetPermissionUsedType(tokenID, permissionName));
    return ERR_OK;
}

int32_t AccessTokenManagerService::PreVerifyHapTokenIfNeeded(AccessTokenID tokenID)
{
    if (TokenIDAttributes::GetTokenIdTypeEnum(tokenID) != TOKEN_HAP) {
        return RET_SUCCESS;
    }
    return BootVerifyScheduler::GetInstance().PreVerifyBundle(tokenID);
}

int32_t AccessTokenManagerService::PreVerifyBundleIfNeeded(const std::string& bundleName)
{
    if (bundleName.empty()) {
        return RET_SUCCESS;
    }
    return BootVerifyScheduler::GetInstance().PreVerifyBundle(bundleName);
}

int32_t AccessTokenManagerService::PreVerifyHapTokenListIfNeeded(const std::vector<uint32_t>& tokenIDList)
{
    for (const auto tokenID : tokenIDList) {
        int32_t ret = PreVerifyHapTokenIfNeeded(tokenID);
        if (ret != RET_SUCCESS) {
            return ret;
        }
    }
    return RET_SUCCESS;
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
    int32_t ret = PreVerifyHapTokenIfNeeded(tokenID);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Pre verify bundle by token failed, tokenID=%{public}u, ret=%{public}d.",
            tokenID, ret);
        return PERMISSION_DENIED;
    }
    int32_t res = PERMISSION_DENIED;
    if (ToolTokenInfoManager::GetInstance().IsToolToken(tokenID)) {
        res = ToolTokenInfoManager::GetInstance().VerifyToolAccessToken(tokenID, permissionName);
    } else {
        res = AccessTokenInfoManager::GetInstance().VerifyAccessToken(tokenID, permissionName);
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "Id %{public}d, perm %{public}s, res %{public}d.",
        tokenID, permissionName.c_str(), res);
#ifdef HITRACE_NATIVE_ENABLE
    FinishTrace(HITRACE_TAG_ACCESS_CONTROL);
#endif
    return res;
}

int32_t AccessTokenManagerService::InitCliToken(const CliInitInfoIdl& initInfoIdl, uint64_t& fullTokenId,
    std::vector<PermissionWithValueIdl>& kernelPermIdlList)
{
    std::lock_guard<std::mutex> userPolicyUpdateGuard(g_userPolicyUpdateMutex);
    kernelPermIdlList.clear();
    if (IPCSkeleton::GetCallingUid() != ROOT_UID) {
        LOGD(ATM_DOMAIN, ATM_TAG, "CallingUid() %{public}d.", IPCSkeleton::GetCallingUid());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<std::string> kernelPermList;
    int32_t ret = ToolTokenInfoManager::GetInstance().InitCliToken(
        ConvertCliInitInfoIdl(initInfoIdl), IPCSkeleton::GetCallingPid(), tokenIdEx, kernelPermList);
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
    if (!IsNativeProcessCalling() || VerifyAccessToken(callingTokenID, MANAGE_TOOL_TOKENID) == PERMISSION_DENIED) {
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(pid);
}

int32_t AccessTokenManagerService::GetHostTokenId(AccessTokenID toolTokenId, AccessTokenID& hostTokenId)
{
    if (!IsNativeProcessCalling()) {
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
    if (!GetPermissionBriefDef(permissionName, briefDef) || !briefDef.isEnable) {
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
    int32_t ret = PreVerifyHapTokenIfNeeded(tokenID);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Pre verify bundle by token failed, tokenID=%{public}u, ret=%{public}d.",
            tokenID, ret);
        return ret;
    }

    std::vector<PermissionStatus> permList;
    int result = PermissionManager::GetInstance().GetReqPermissions(tokenID, permList, isSystemGrant);

    for (const auto& perm : permList) {
        PermissionStatusParcel permParcel;
        permParcel.permState = perm;
        reqPermList.emplace_back(permParcel);
    }
    return result;
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
    int32_t verifyRet = PreVerifyHapTokenIfNeeded(callingTokenID); // 影响API的错误码返回
    if (verifyRet != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Pre verify bundle by token failed, tokenID=%{public}u, ret=%{public}d.",
            callingTokenID, verifyRet);
        return verifyRet;
    }
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

    int32_t ret = PreVerifyHapTokenIfNeeded(tokenID);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Pre verify bundle by token failed, tokenID=%{public}u, ret=%{public}d.",
            tokenID, ret);
        return ret;
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
    PermissionOper permOper = GetPermissionsState(tokenID, reqPermList);
    return permOper == INVALID_OPER ? RET_FAILED : RET_SUCCESS;
}

bool GetAppReqPermissions(AccessTokenID tokenID, std::vector<PermissionStatus>& permsList)
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

bool IsRenderToken(AccessTokenID tokenID)
{
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&tokenID);
    return idInner->renderFlag;
}

int32_t AccessTokenManagerService::GetPermissionStatusDetails(AccessTokenID tokenID,
    const std::vector<std::string>& permissionList, std::vector<PermissionStatusDetailIdl>& resultList)
{
    int32_t ret = PreCheckPermissionStatusDetails(tokenID, permissionList);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    std::vector<PermissionStatus> permsList;
    if (!GetAppReqPermissions(tokenID, permsList)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetPermissionStatusDetails get requested permissions failed, tokenId=%{public}u.",
            tokenID);
        return ERR_SERVICE_ABNORMAL;
    }
    DeclaredPermissionNameSet declaredPermissions;
    for (const auto& perm : permsList) {
        declaredPermissions.emplace(perm.permissionName);
    }
    resultList.clear();
    resultList.reserve(permissionList.size());
    for (const auto& permissionName : permissionList) {
        PermissionStatusDetailIdl result = {};
        ret = BuildPermissionStatusDetail(tokenID, permissionName, declaredPermissions, result);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Build permission status detail failed, tokenId=%{public}u, permission=%{public}s, ret=%{public}d.",
                tokenID, permissionName.c_str(), ret);
            return ret;
        }
        resultList.emplace_back(result);
    }
    return RET_SUCCESS;
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
    int32_t ret = PreVerifyHapTokenIfNeeded(tokenID);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Pre verify bundle by token failed, tokenID=%{public}u, ret=%{public}d.",
            tokenID, ret);
        return INVALID_OPER;
    }
    int32_t apiVersion = 0;
    if (!AccessTokenInfoManager::GetInstance().GetApiVersionByTokenId(tokenID, apiVersion)) {
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

    UpdatePermissionStates(permsList, reqPermList, apiVersion, needRes, fixedByPolicyRes);
    if (GetTokenType(tokenID) == TOKEN_HAP && AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenID)) {
        return HandlePermissionDialogCap(tokenID, reqPermList);
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
    int32_t ret = PreVerifyHapTokenIfNeeded(tokenID);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Pre verify bundle by token failed, tokenID=%{public}u, ret=%{public}d.",
            tokenID, ret);
        return ret;
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
    return PermissionRequestToggleManager::GetInstance().SetPermissionRequestToggleStatus(permissionName, status,
        userID);
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
    return PermissionRequestToggleManager::GetInstance().GetPermissionRequestToggleStatus(permissionName, status,
        userID);
}

int32_t AccessTokenManagerService::RequestAppPermOnSetting(AccessTokenID tokenID)
{
    int32_t ret = PreVerifyHapTokenIfNeeded(tokenID);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Pre verify bundle by token failed, tokenID=%{public}u, ret=%{public}d.",
            tokenID, ret);
        return ret;
    }
    if (!IsSystemAppCalling()) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }

    HapTokenInfo hapInfo;
    ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, hapInfo);
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
    int32_t ret = PreVerifyHapTokenIfNeeded(tokenID);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Pre verify bundle by token failed, tokenID=%{public}u, ret=%{public}d.",
            tokenID, ret);
        return ret;
    }
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }
    
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, GRANT_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED &&
        !IsShellCallingForDebugHap(tokenID)) {
        ReportPermissionVerifyEvent(callingTokenID, permissionName);
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    int32_t grantRet = PermissionManager::GetInstance().GrantPermission(
        tokenID, permissionName, flag, static_cast<UpdatePermissionFlag>(updateFlag));
    return grantRet;
}

int AccessTokenManagerService::RevokePermission(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t flag, int32_t updateFlag, bool killProcess)
{
    int32_t ret = PreVerifyHapTokenIfNeeded(tokenID);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Pre verify bundle by token failed, tokenID=%{public}u, ret=%{public}d.",
            tokenID, ret);
        return ret;
    }
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if ((this->GetTokenType(callingTokenID) == TOKEN_HAP) && (!IsSystemAppCalling())) {
        return AccessTokenError::ERR_NOT_SYSTEM_APP;
    }

    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED &&
        !IsShellCallingForDebugHap(tokenID)) {
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
    int32_t ret = PreVerifyHapTokenIfNeeded(tokenID);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Pre verify bundle by token failed, tokenID=%{public}u, ret=%{public}d.",
            tokenID, ret);
        return ret;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d, callerPid %{public}d.", tokenID, IPCSkeleton::GetCallingPid());
    uint32_t callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        VerifyAccessToken(callingTokenID, REVOKE_SENSITIVE_PERMISSIONS) == PERMISSION_DENIED &&
        !IsShellCallingForDebugHap(tokenID)) {
        ReportPermissionVerifyEvent(callingTokenID, "");
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    if (!AccessTokenInfoManager::GetInstance().IsHapTokenIdExist(tokenID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID %{public}u does not exist or is not a valid hap token.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    AccessTokenInfoManager::GetInstance().ClearUserGrantedPermissionState(tokenID);
    AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenID, false);
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::ClearUserGrantedPermStateByBundle(const std::string& bundleName)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Bundle %{public}s, callerPid %{public}d.", bundleName.c_str(),
        IPCSkeleton::GetCallingPid());
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsShellProcessCalling()) {
        ReportPermissionVerifyEvent(callingTokenID, "");
        LOGE(ATM_DOMAIN, ATM_TAG, "Caller is not shell, callerTokenID=%{public}d.", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    if (!DataValidator::IsBundleNameValid(bundleName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Bundle name is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    std::vector<AccessTokenID> tokenIdList;
    int32_t ret = AccessTokenInfoManager::GetInstance().GetHapTokenIdListByBundleName(bundleName, tokenIdList);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    bool isCleared = false;
    for (const auto tokenID : tokenIdList) {
#ifdef ATM_BUILD_VARIANT_USER_ENABLE
        if (!IsDebugHapToken(tokenID)) {
            continue;
        }
#endif
        AccessTokenInfoManager::GetInstance().ClearUserGrantedPermissionState(tokenID);
        AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenID, false);
        isCleared = true;
    }
    if (!isCleared) {
        ReportPermissionVerifyEvent(callingTokenID, "");
        LOGE(ATM_DOMAIN, ATM_TAG, "No debug hap can be cleared, bundle=%{public}s.", bundleName.c_str());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
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
    dfxInfo.sceneCode = CommonSceneCode::AT_COMMON_FINISH;

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
        BundleParam bundleParam;
        bundleParam.bundleName = hapInfoParm.bundleName;
        bundleParam.appId = hapInfoParm.appIDDesc;
        bundleParam.apiVersion = hapInfoParm.apiVersion;
#ifdef IS_SUPPORT_HAP_RUNNING
        bundleParam.distributionType = static_cast<int32_t>(Verify::ParseAppDistType(hapInfoParm.appDistributionType));
#endif
        bundleParam.isSystem = hapInfoParm.isSystemApp;
        bundleParam.isAtomicService = hapInfoParm.isAtomicService;
        bundleParam.isDebug = (hapInfoParm.appProvisionType == "debug" ||
            hapInfoParm.appDistributionType == "none");
        if (!PermissionManager::GetInstance().InitPermissionList(bundleParam, policyCopy, initializedList,
            permCheckResult,
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
        // return success if token id not exsits;
        return RET_SUCCESS;
    }

    // only support hap token deletion
    errorCode = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID, isTokenReserved);
    if (errorCode == RET_SUCCESS && !isTokenReserved) {
        int32_t ret = UserPolicyManager::GetInstance().RemoveTokenFromPolicyWhiteList(tokenID);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Remove token %{public}u from policy whitelist failed, ret=%{public}d.",
                tokenID, ret);
        }
    }

    dfxInfo.userID = hapInfo.userID;
    dfxInfo.bundleName = hapInfo.bundleName;
    dfxInfo.instIndex = hapInfo.instIndex;
    dfxInfo.duration = TimeUtil::GetCurrentTimestamp() - beginTime;
    ReportSysEventDelHap(errorCode, sceneCode, dfxInfo);
    return errorCode;
}

int32_t AccessTokenManagerService::DeleteIdentityCore(AccessTokenID tokenID, const std::string& bundleName,
    ReservedType reservedType, int32_t& sceneCode)
{
    // Case 1: tokenID is INVALID_TOKENID
    if (tokenID == INVALID_TOKENID) {
        sceneCode = static_cast<int32_t>(AT_DELETE_ALL_BUNDLE);
        if (reservedType != ReservedType::NONE) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Invalid param: reservedType must be NONE when tokenID is INVALID.");
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        // Delete all reserved tokens for this bundle and package info
        std::vector<AccessTokenID> activeTokens;
        int32_t ret = DeleteBundleManager::GetInstance().DeleteBundleAndAllTokens(bundleName, activeTokens);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to delete bundle %{public}s, err %{public}d.",
                bundleName.c_str(), ret);
            return ret;
        }

        // Clean up cache for active tokens
        for (const auto& tokenId : activeTokens) {
            AccessTokenInfoManager::GetInstance().CommitDeleteHapCache(tokenId, bundleName);
            // Release TokenId for active tokens
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        }
        return RET_SUCCESS;
    }

    // Case 2: tokenID is valid
    // Check if it's a HAP token
    if (TokenIDAttributes::GetTokenIdTypeEnum(tokenID) != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is not a HAP token.", tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    // Case 2.1: tokenID is a ReservedTokenId
    if (AccessTokenIDManager::GetInstance().IsReservedTokenId(tokenID)) {
        sceneCode = static_cast<int32_t>(AT_DELETE_RESERVED_TOKEN);
        if (reservedType != ReservedType::NONE) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Invalid param: reservedType must be NONE for reserved tokenID.");
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        // Delete this reserved token completely
        return DeleteBundleManager::GetInstance().DeleteReservedToken(tokenID, bundleName);
    }

    if (reservedType == ReservedType::RESERVED_IDENTITY) {
        sceneCode = static_cast<int32_t>(AT_DELETE_KEEP_TOKEN_FINISH);
    } else if (reservedType == ReservedType::RESERVED_DATA) {
        sceneCode = static_cast<int32_t>(AT_DELETE_KEEP_DATA);
    } else {
        sceneCode = static_cast<int32_t>(AT_DELETE_NORMAL);
    }
    // Case 2.2: tokenID is a normal (non-reserved) token
    // Match bundleName and call DeleteIdentity
    return AccessTokenInfoManager::GetInstance().DeleteIdentity(tokenID, bundleName, reservedType);
}

int32_t AccessTokenManagerService::DeleteIdentity(
    AccessTokenID tokenID, const std::string& bundleName, ReservedTypeIdl type)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Id %{public}d, bundle %{public}s, type %{public}d, callerPid %{public}d.",
        tokenID, bundleName.c_str(), type, IPCSkeleton::GetCallingPid());
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingTokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    if (bundleName.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid param: bundle empty.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    HapDfxInfo dfxInfo = {};
    dfxInfo.tokenId = tokenID;
    dfxInfo.ipcCode = static_cast<int32_t>(IAccessTokenManagerIpcCode::COMMAND_DELETE_IDENTITY);
    ReservedType reservedType = static_cast<ReservedType>(type);
    int32_t sceneCode = static_cast<int32_t>(AT_DELETE_COMMON_FINISH);
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();
    int32_t ret = DeleteIdentityCore(tokenID, bundleName, reservedType, sceneCode);
    dfxInfo.duration = TimeUtil::GetCurrentTimestamp() - beginTime;
    ReportSysEventDelHap(ret, static_cast<int32_t>(sceneCode), dfxInfo);
    return ret;
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
    if (!DataValidator::IsBundleNameValid(bundleName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Bundle name is invalid.");
        fullTokenId = 0;
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    int32_t res = PreVerifyBundleIfNeeded(bundleName);
    if (res != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Pre verify bundle failed, res %{public}d.", res);
        fullTokenId = 0;
        return ERR_OK;
    }
    AccessTokenIDEx tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(userID, bundleName, instIndex);
    fullTokenId = tokenIdEx.tokenIDEx;
    return ERR_OK;
}

int32_t AccessTokenManagerService::GetHapIdentity(const HapBaseInfoParcel& hapBaseInfoParcel, IdentityIdl& identityIdl)
{
    const HapBaseInfo& info = hapBaseInfoParcel.hapBaseInfo;
    LOGD(ATM_DOMAIN, ATM_TAG, "UserID %{public}d, bundle %{public}s, instIndex %{public}d.",
        info.userID, info.bundleName.c_str(), info.instIndex);
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    int32_t ret = PreVerifyBundleIfNeeded(info.bundleName);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    Identity identity;
    ret = AccessTokenInfoManager::GetInstance().GetHapIdentity(info, identity);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    identityIdl.uid = identity.uid;
    identityIdl.tokenId = identity.tokenId;
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::GetHapBaseInfoByUid(int32_t uid, HapBaseInfoParcel& hapBaseInfoParcel)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "Uid %{public}d.", uid);
    if (!IsNativeProcessCalling() && !IsPrivilegedCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return AccessTokenInfoManager::GetInstance().GetHapBaseInfoByUid(uid, hapBaseInfoParcel.hapBaseInfo);
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
    HapTokenInfo hapInfo = { 0 };
    BundleParam bundleParam;
    int32_t error = ERR_OK;
    if (!info.isSkillHap) {
        error = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, hapInfo);
        if (error != ERR_OK) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Failed to get hap info of %{public}u) err %{public}d.", tokenID, error);
            ReportUpdateHap(tokenIdEx, hapInfo, policyParcel.hapPolicy, beginTime, error);
            return error;
        }
        bundleParam.bundleName = hapInfo.bundleName;
    }
    bundleParam.appId = info.appIDDesc;
    bundleParam.apiVersion = info.apiVersion;
#ifdef IS_SUPPORT_HAP_RUNNING
    bundleParam.distributionType = static_cast<int32_t>(Verify::ParseAppDistType(info.appDistributionType));
#endif
    bundleParam.isSystem = info.isSystemApp;
    bundleParam.isAtomicService = info.isAtomicService;
    bundleParam.isDebug = (info.appProvisionType == "debug" || info.appDistributionType == "none");

    if (!PermissionManager::GetInstance().InitPermissionList(bundleParam, policy, initializedList,
        permCheckResult, undefValues, info.dataRefresh)) {
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

    if (IsNativeProcessCalling() || IsPrivilegedCalling()) {
        return AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, infoParcel.hapTokenInfoParams);
    }

    if (!IsShellProcessCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is not exist.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    if (!TokenIDAttributes::IsDebugAppAttr(infoPtr->GetAttr())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", IPCSkeleton::GetCallingTokenID());
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    infoPtr->TranslateToHapTokenInfo(infoParcel.hapTokenInfoParams);
    return RET_SUCCESS;
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
    if (!IsDefinedPermissionInner(permission)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm(%{public}s) is not exist.", permission.c_str());
        return ERR_PERMISSION_NOT_EXIST;
    }
    if (!TransferPermissionToOpcode(permission, opCode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm(%{public}s) is not exist.", permission.c_str());
        return ERR_PERMISSION_NOT_EXIST;
    }
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::IsSupportPermission(const std::string& permission, bool& isSupported)
{
    isSupported = IsDefinedPermissionInner(permission);
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::RefreshTokenStatus(const IdentityIdl& identity, ReservedTypeIdl reserved)
{
    if (identity.tokenId == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid param: tokenId is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    // Permission check
    int32_t ret = CheckHapManagerPermission();
    if (ret != RET_SUCCESS) {
        return ret;
    }

    Identity identityInner;
    identityInner.tokenId = identity.tokenId;
    identityInner.uid = identity.uid;
    ReservedType reservedType = static_cast<ReservedType>(reserved);

    return AccessTokenInfoManager::GetInstance().RefreshTokenStatus(identityInner, reservedType);
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

    AccessTokenInfoDumper::DumpTokenInfo(infoParcel.info, dumpInfo);
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
int32_t GetHapUserIdByTokenId(AccessTokenID tokenId, int32_t& userId)
{
    HapTokenInfo hapInfo = { 0 };
    int32_t ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenId, hapInfo);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get hap info, token %{public}u.", tokenId);
        return ret;
    }
    userId = hapInfo.userID;
    return RET_SUCCESS;
}

void AccessTokenManagerService::RollbackPolicyWhiteList(const PolicyWhiteListUpdateInfo& context)
{
    PolicyWhiteListUpdateInfo rollbackContext = context;
    rollbackContext.type = (context.type == ADD) ? DELETE : ADD;
    int32_t ret = UserPolicyManager::GetInstance().UpdatePolicyWhiteList(rollbackContext);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Rollback whitelist policy failed, tokenId=%{public}u, permCode=%{public}u, ret=%{public}d.",
            context.tokenId, context.permCode, ret);
    }
}

int32_t AccessTokenManagerService::HandlePolicyWhiteListUpdate(const PolicyWhiteListUpdateInfo& policyContext)
{
    bool isPersist = false;
    int32_t ret = UserPolicyManager::GetInstance().UpdatePolicyWhiteList(policyContext, isPersist);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    bool targetRestricted = policyContext.type == DELETE;
    ret = AccessTokenInfoManager::GetInstance().UpdateRestrictedFlagAndRefreshKernel(
        policyContext.tokenId, policyContext.permCode, targetRestricted, isPersist, "whitelist");
    if (ret != RET_SUCCESS) {
        RollbackPolicyWhiteList(policyContext);
        return ret;
    }
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::RefreshUserPolicyPermState(const std::vector<UserPolicyChange>& changedPolicyList)
{
    if (changedPolicyList.empty()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Empty changedPolicyList.");
        return RET_SUCCESS;
    }

    std::vector<UserPolicyRefreshSnapshot> hapSnapshots;
    int32_t ret = AccessTokenInfoManager::GetInstance().RefreshUserPolicyFlag(changedPolicyList, hapSnapshots);
    if (ret != RET_SUCCESS) {
        AccessTokenInfoManager::GetInstance().RollbackUserPolicyFlag(hapSnapshots);
        return ret;
    }

    std::vector<UserPolicyRefreshSnapshot> toolSnapshots;
    ret = ToolTokenInfoManager::GetInstance().RefreshUserPolicyFlag(changedPolicyList, toolSnapshots);
    if (ret != RET_SUCCESS) {
        ToolTokenInfoManager::GetInstance().RollbackUserPolicyFlag(toolSnapshots);
        AccessTokenInfoManager::GetInstance().RollbackUserPolicyFlag(hapSnapshots);
        return ret;
    }
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::SetUserPolicy(const std::vector<UserPermissionPolicyIdl>& userPermissionList)
{
    std::lock_guard<std::mutex> userPolicyUpdateGuard(g_userPolicyUpdateMutex);
    LOGI(ATM_DOMAIN, ATM_TAG, "CallerPid %{public}d.", IPCSkeleton::GetCallingPid());
    size_t policySize = userPermissionList.size();
    if (policySize == 0) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (policySize > MAX_SET_USER_POLICY_SIZE) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, "ohos.permission.MANAGE_USER_POLICY") == PERMISSION_DENIED) {
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
        permPolicy.isPersist = permPolicyIdl.isPersist;
        policyList.emplace_back(permPolicy);
    }
    std::vector<UserPolicyChange> changedPolicyList;
    int32_t ret = UserPolicyManager::GetInstance().SetUserPolicy(policyList, callingToken, changedPolicyList);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    return RefreshUserPolicyPermState(changedPolicyList);
}

int32_t AccessTokenManagerService::ClearUserPolicy(const std::vector<std::string>& permissionList)
{
    std::lock_guard<std::mutex> userPolicyUpdateGuard(g_userPolicyUpdateMutex);
    LOGI(ATM_DOMAIN, ATM_TAG, "CallerPid %{public}d.", IPCSkeleton::GetCallingPid());
    size_t permSize = permissionList.size();
    if (permSize == 0) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsListSizeValid(permSize)) {
        return AccessTokenError::ERR_OVERSIZE;
    }

    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, "ohos.permission.MANAGE_USER_POLICY") == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    std::vector<UserPolicyChange> changedPolicyList;
    int32_t ret = UserPolicyManager::GetInstance().ClearUserPolicy(permissionList, callingToken, changedPolicyList);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    ret = RefreshUserPolicyPermState(changedPolicyList);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::UpdatePolicyWhiteList(AccessTokenID tokenId, uint32_t permCode, int32_t type)
{
    std::lock_guard<std::mutex> userPolicyUpdateGuard(g_userPolicyUpdateMutex);
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
    if (VerifyAccessToken(callingToken, "ohos.permission.MANAGE_USER_POLICY") == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    int32_t userId = 0;
    if (GetHapUserIdByTokenId(tokenId, userId) != RET_SUCCESS) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    PolicyWhiteListUpdateInfo policyContext {
        .tokenId = tokenId,
        .userId = userId,
        .permCode = permCode,
        .type = updateType,
        .callerToken = callingToken
    };
    return HandlePolicyWhiteListUpdate(policyContext);
}

int32_t AccessTokenManagerService::GetPolicyWhiteList(uint32_t permCode, std::vector<AccessTokenID>& tokenIdList)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "CallerPid %{public}d.", IPCSkeleton::GetCallingPid());
    tokenIdList.clear();
    std::string permission = TransferOpcodeToPermission(permCode);
    if (permission.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid permCode: %{public}u.", permCode);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    uint32_t callingToken = IPCSkeleton::GetCallingTokenID();
    if (VerifyAccessToken(callingToken, "ohos.permission.MANAGE_USER_POLICY") == PERMISSION_DENIED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingToken);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return UserPolicyManager::GetInstance().GetPolicyWhiteList(permCode, tokenIdList);
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

void AccessTokenManagerService::FilterPermFeature(bool isSystemApp, HapPolicy& policy)
{
    if (!isSystemApp) {
        return;
    }
    for (auto it = policy.permStateList.begin(); it != policy.permStateList.end();) {
        if (PermissionFeatureManager::GetInstance().IsSupportFeature(*it)) {
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

int32_t AccessTokenManagerService::MigrateInstalledBundles(const std::vector<MigratedInfoIdl>& migratedInfoList,
    std::vector<BundleMigrateResultIdl>& results)
{
    results.clear();
    int32_t ret = CheckHapManagerPermission();
    if (ret != RET_SUCCESS) {
        return ret;
    }

    return AccessTokenMigrationManager::GetInstance().MigrateInstalledBundles(migratedInfoList, results);
}

int32_t AccessTokenManagerService::FinishMigration()
{
    int32_t ret = CheckHapManagerPermission();
    if (ret != RET_SUCCESS) {
        return ret;
    }
    return AccessTokenMigrationManager::GetInstance().FinishMigration();
}

int32_t AccessTokenManagerService::CheckHapManagerPermission()
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(callingTokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", callingTokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return RET_SUCCESS;
}

bool AccessTokenManagerService::Initialize()
{
    MemoryGuard guard;
    ReportSysEventPerformance();

    uint32_t hapSize = 0;
    uint32_t nativeSize = 0;
    uint32_t pefDefSize = 0;
    uint32_t dlpSize = 0;
    int32_t ret = RET_SUCCESS;
    AccessTokenInfoManager::GetInstance().Init(nativeSize, pefDefSize, dlpSize);
    ret = BootVerifyScheduler::GetInstance().VerifyBundleSignInfoWhenStart(hapSize);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Verify bundle sign info when start failed, ret=%{public}d.", ret);
        return false;
    }
    BootVerifyScheduler::GetInstance().StartVerifyNormalBundleListAsync();
#ifdef SUPPORT_MANAGE_USER_POLICY
    ret = UserPolicyManager::GetInstance().LoadPersistedPolicies();
    if (ret != RET_SUCCESS) {
        ReportSysEventServiceStartError(INIT_USER_POLICY_ERROR, "Load user policy from db fail.", ret);
    }
#endif

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

    ReportSysEventServiceStart(dfxInfo);
    std::thread reportUserData(ReportAccessTokenUserData);
    reportUserData.detach();

    AccessTokenMigrationManager::GetInstance().Initialize();
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

bool AccessTokenManagerService::IsShellCallingForDebugHap(AccessTokenID tokenID)
{
    if (!IsShellProcessCalling()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Caller is not shell, callerTokenID=%{public}d.",
            IPCSkeleton::GetCallingTokenID());
        return false;
    }

    return IsDebugHapToken(tokenID);
}

bool AccessTokenManagerService::IsDebugHapToken(AccessTokenID tokenID)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is not a valid hap token.", tokenID);
        return false;
    }
    if (!TokenIDAttributes::IsDebugAppAttr(infoPtr->GetAttr())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is not a debug hap token.", tokenID);
        return false;
    }
    return true;
}

bool AccessTokenManagerService::IsSystemAppCalling() const
{
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    return TokenIDAttributes::IsSystemApp(fullTokenId);
}

int32_t AccessTokenManagerService::ValidateGetCliPermissionRequestInfoCaller(
    AccessTokenID callingTokenId, const std::string& agentID, const std::vector<CliInfoIdl>& cliInfoList)
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
    AccessTokenID hostTokenID, const std::string& agentID, const std::vector<CliInfoIdl>& cliInfoList)
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

int32_t AccessTokenManagerService::StoreSecCompEnhanceKey(const SecCompEnhanceKeyParcel& enhanceKeyParcel)
{
    if (!IsSecCompServiceCalling()) {
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return SecCompEnhanceAgent::GetInstance().StoreSecCompEnhanceKey(enhanceKeyParcel.enhanceKey);
}

int32_t AccessTokenManagerService::GetSecCompEnhanceKey(SecCompEnhanceKeyParcel& enhanceKeyParcel)
{
    if (!IsSecCompServiceCalling()) {
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return SecCompEnhanceAgent::GetInstance().GetSecCompEnhanceKey(enhanceKeyParcel.enhanceKey);
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

#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
void TransferBundleHapListFromIdl(const BundleHapListIdl& listIdl, BundleHapList& list)
{
    list.hapPaths = listIdl.hapPaths;
    list.isPreInstalled = listIdl.isPreInstalled;
    list.userId = listIdl.userId;
}

void TransferHapBaseInfoFromIdl(const HapBaseInfoIdl& infoIdl, HapBaseInfo& info)
{
    info.userID = infoIdl.userID;
    info.bundleName = infoIdl.bundleName;
    info.instIndex = infoIdl.instIndex;
}

void TransferIdentityToIdl(const Identity& identity, IdentityIdl& identityIdl)
{
    identityIdl.uid = identity.uid;
    identityIdl.tokenId = identity.tokenId;
}

void TransferPreAuthorizationInfoFromIdl(const PreAuthorizationInfoIdl& infoIdl, PreAuthorizationInfo& info)
{
    info.permissionName = infoIdl.permissionName;
    info.userCancelable = infoIdl.userCancelable;
}

void TransferBundlePolicyFromIdl(const BundlePolicyIdl& policyIdl, BundlePolicy& policy)
{
    for (const auto& infoIdl : policyIdl.preAuthorizationInfo) {
        PreAuthorizationInfo info;
        TransferPreAuthorizationInfoFromIdl(infoIdl, info);
        policy.preAuthorizationInfo.emplace_back(info);
    }
    policy.dlpType = static_cast<DlpType>(policyIdl.dlpType);
    policy.isDebugGrant = policyIdl.isDebugGrant;
}

int32_t AccessTokenManagerService::CheckHapSignInfo(const BundleHapListIdl& list, const sptr<IRemoteObject>& cb,
    CheckHapSignResultRawdata& result)
{
    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(tokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", tokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    BundleHapList bundleHapList;
    TransferBundleHapListFromIdl(list, bundleHapList);
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfoList;
    HapVerifyResultInfo resultInfo;
    int32_t ret = InstallSessionManager::GetInstance().CheckHapSignInfo(
        bundleHapList, cb, sessionId, bundleInfoList, resultInfo);
    if (!CheckHapSignResultRawdataHelper::WriteToRawData(ret, sessionId, bundleInfoList, resultInfo, result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteToRawData failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    
    return ERR_OK;
}

int32_t AccessTokenManagerService::CheckHapPermissionInfo(int32_t sessionId, InstallTypeEnumIdl type,
    HapInfoCheckResultIdl& resultInfoIdl)
{
    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(tokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", tokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    HapInfoCheckResult checkResult;
    int32_t ret = InstallSessionManager::GetInstance().CheckHapPermissionInfo(
        sessionId, static_cast<InstallTypeEnum>(type), checkResult);
    resultInfoIdl.realResult = ret;
    if (ret != ERR_OK) {
        resultInfoIdl.permissionName = checkResult.permCheckResult.permissionName;
        resultInfoIdl.rule = static_cast<PermissionRulesEnumIdl>(checkResult.permCheckResult.rule);
    }

    return ERR_OK;
}

int32_t AccessTokenManagerService::PrepareHapIdentity(int32_t& sessionId, const HapBaseInfoIdl& info,
    const BundlePolicyIdl& policy, const sptr<IRemoteObject>& cb, IdentityIdl& identity)
{
    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(tokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", tokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    HapBaseInfo hapBaseInfo;
    TransferHapBaseInfoFromIdl(info, hapBaseInfo);
    BundlePolicy bundlePolicy;
    TransferBundlePolicyFromIdl(policy, bundlePolicy);
    Identity ident;
    int32_t ret = InstallSessionManager::GetInstance().PrepareHapIdentity(
        sessionId, hapBaseInfo, bundlePolicy, cb, ident);
    TransferIdentityToIdl(ident, identity);
    return ret;
}

int32_t AccessTokenManagerService::UpdateHapPolicy(int32_t sessionId, AccessTokenID tokenId,
    const BundlePolicyIdl& policy)
{
    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(tokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", tokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    BundlePolicy bundlePolicy;
    TransferBundlePolicyFromIdl(policy, bundlePolicy);
    return InstallSessionManager::GetInstance().UpdateHapPolicy(sessionId, tokenId, bundlePolicy);
}

int32_t AccessTokenManagerService::FinishInstall(int32_t sessionId, bool isSuccess,
    const std::map<std::string, std::string>& modulePathMap)
{
    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() &&
        (VerifyAccessToken(tokenID, MANAGE_HAP_TOKENID_PERMISSION) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", tokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    int32_t ret = InstallSessionManager::GetInstance().FinishInstall(sessionId, isSuccess, modulePathMap);
    return ret;
}

int32_t AccessTokenManagerService::GetCacheSignInfoBySessionId(int32_t sessionId,
    BundleInfosRawdata& bundleInfos)
{
    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() && (VerifyAccessToken(tokenID, GET_TRUSTED_BUNDLE_INFO) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", tokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    std::vector<TrustedBundleInfo> bundleInfoList;
    int32_t ret = InstallSessionManager::GetInstance().GetCacheSignInfoBySessionId(sessionId, bundleInfoList);
    
    if (!BundleInfosRawdataHelper::WriteToRawData(bundleInfoList, bundleInfos)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteToRawData failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    
    return ret;
}

int32_t AccessTokenManagerService::GetHapSignInfo(const std::string& bundleName,
    BundleInfosRawdata& bundleInfos)
{
    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() && (VerifyAccessToken(tokenID, GET_TRUSTED_BUNDLE_INFO) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", tokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    std::vector<TrustedBundleInfo> bundleInfoList;
    int32_t ret = InstallSessionManager::GetInstance().GetHapSignInfo(bundleName, bundleInfoList);
    
    if (!BundleInfosRawdataHelper::WriteToRawData(bundleInfoList, bundleInfos)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteToRawData failed.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    
    return ret;
}

int32_t AccessTokenManagerService::GetCachePolicyBySessionId(int32_t sessionId, const std::string& bundleName,
    BundlePolicyInfoIdl& bundlePolicyInfoIdl)
{
    AccessTokenID tokenID = IPCSkeleton::GetCallingTokenID();
    if (!IsPrivilegedCalling() && (VerifyAccessToken(tokenID, GET_TRUSTED_BUNDLE_INFO) == PERMISSION_DENIED)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Perm denied(tokenID %{public}d).", tokenID);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    BundlePolicyInfo bundlePolicyInfo;
    int32_t ret = InstallSessionManager::GetInstance().GetCachePolicyBySessionId(
        sessionId, bundleName, bundlePolicyInfo);
    bundlePolicyInfoIdl.reqPermissions = bundlePolicyInfo.reqPermissions;

    return ret;
}
#else
int32_t AccessTokenManagerService::CheckHapSignInfo(const BundleHapListIdl& list, const sptr<IRemoteObject>& cb,
    CheckHapSignResultRawdata& result)
{
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::CheckHapPermissionInfo(int32_t sessionId, InstallTypeEnumIdl type,
    HapInfoCheckResultIdl& resultInfoIdl)
{
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::PrepareHapIdentity(int32_t& sessionId, const HapBaseInfoIdl& info,
    const BundlePolicyIdl& policy, const sptr<IRemoteObject>& cb, IdentityIdl& identity)
{
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::UpdateHapPolicy(int32_t sessionId, AccessTokenID tokenId,
    const BundlePolicyIdl& policy)
{
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::FinishInstall(int32_t sessionId, bool isSuccess,
    const std::map<std::string, std::string>& modulePathMap)
{
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::GetCacheSignInfoBySessionId(int32_t sessionId,
    BundleInfosRawdata& bundleInfos)
{
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::GetHapSignInfo(const std::string& bundleName,
    BundleInfosRawdata& bundleInfos)
{
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::GetCachePolicyBySessionId(int32_t sessionId, const std::string& bundleName,
    BundlePolicyInfoIdl& bundlePolicyInfoIdl)
{
    return RET_SUCCESS;
}
#endif

int32_t AccessTokenManagerService::GetCliPermissionRequestInfo(
    const std::string& agentID, const std::vector<CliInfoIdl>& cliInfoList,
    PermissionDialogResultIdl& resultIdl)
{
    AccessTokenID callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t ret = ValidateGetCliPermissionRequestInfoCaller(callingTokenId, agentID, cliInfoList);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    std::vector<CliInfo> cliInfos = ConvertCliInfoIdls(cliInfoList);

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
    resultIdl = ConvertPermissionDialogResult(result);
    LOGI(ATM_DOMAIN, ATM_TAG,
        "GetCliPermissionRequestInfo done, callerToken=%{public}u, agentID=%{public}s, "
        "cliSize=%{public}zu, detailSize=%{public}zu, dialogDetails=%{public}zu.",
        callingTokenId, agentID.c_str(), cliInfos.size(), result.detailList.size(),
        CountDialogDetails(result.detailList));
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::GetCliPermissions(AccessTokenID hostTokenID, const std::string& agentID,
    const std::vector<CliInfoIdl>& cliInfoList, CliPermissionsResultIdl& resultIdl)
{
    AccessTokenID callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t ret = ValidateGetCliPermissionsCaller(callingTokenId, hostTokenID, agentID, cliInfoList);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    std::vector<CliInfo> cliInfos = ConvertCliInfoIdls(cliInfoList);

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
    resultIdl = ConvertCliPermissionsResult(result);
    size_t requiredPermCount = CountRequiredCliPermissions(result);
    LOGI(ATM_DOMAIN, ATM_TAG,
        "GetCliPermissions done, callerToken=%{public}u, targetToken=%{public}u, agentID=%{public}s, "
        "cliSize=%{public}zu, resultSize=%{public}zu, requiredPerms=%{public}zu.",
        callingTokenId, hostTokenID, agentID.c_str(), cliInfos.size(), result.permList.size(),
        requiredPermCount);
    return RET_SUCCESS;
}

int32_t AccessTokenManagerService::GenerateCliAuthResult(
    AccessTokenID hostTokenID, const std::string& agentID,
    const std::vector<CliAuthInfoIdl>& authInfoList, ToolAuthResultIdl& resultIdl)
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
        CliAuthInfo authInfo = ConvertCliAuthInfoIdl(authInfoList[i]);
        if (!IsCliAuthInfoValid(authInfo)) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "GenerateCliAuthResult invalid auth info, targetToken=%{public}u, index=%{public}zu, "
                "permissionSize=%{public}zu, resultSize=%{public}zu.",
                hostTokenID, i, authInfo.permissionNames.size(), authInfo.authorizationResults.size());
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
    ToolAuthResult result;
    std::vector<CliAuthInfo> authInfos;
    ret = BuildCliTicketAuthInfos(hostTokenID, authInfoList, authInfos);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    ret = ClawTicketManager::GetInstance().GenerateCliTicket(hostTokenID, authInfos, result.authResults);
    resultIdl = ConvertToolAuthResult(result);
    LOGI(ATM_DOMAIN, ATM_TAG,
        "GenerateCliAuthResult done, callerToken=%{public}u, targetToken=%{public}u, agentID=%{public}s, "
        "authSize=%{public}zu, ret=%{public}d, authResultSize=%{public}zu.",
        callingTokenId, hostTokenID, agentID.c_str(), authInfos.size(), ret, result.authResults.size());
    return ret;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
