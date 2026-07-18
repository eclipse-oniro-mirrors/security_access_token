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

#include "permission_manager.h"

#include <iostream>
#include <numeric>
#include <sstream>

#include "access_token.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_common_log.h"
#include "app_manager_access_client.h"
#include "callback_manager.h"
#ifdef SUPPORT_SANDBOX_APP
#include "dlp_permission_set_manager.h"
#endif
#include "iaccess_token_manager.h"
#include "ipc_skeleton.h"
#ifdef IS_SUPPORT_HAP_RUNNING
#include "interfaces/hap_verify.h"
#include "provision/provision_info.h"
#endif
#include "hisysevent_adapter.h"
#include "permission_change_notifier.h"
#include "permission_kernel_utils.h"
#include "parameters.h"
#include "short_grant_manager.h"
#include "permission_map.h"
#include "permission_validator.h"
#include "tokenid_attributes.h"
#include "token_field_const.h"
#include "user_policy_manager.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_modify_notifier.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::vector<std::string> g_notDisplayedPerms = {
    "ohos.permission.ANSWER_CALL",
    "ohos.permission.MANAGE_VOICEMAIL",
    "ohos.permission.READ_CELL_MESSAGES",
    "ohos.permission.RECEIVE_MMS",
    "ohos.permission.RECEIVE_SMS",
    "ohos.permission.RECEIVE_WAP_MESSAGES",
    "ohos.permission.SEND_MESSAGES",
    "ohos.permission.WRITE_CALL_LOG",
    "ohos.permission.SHORT_TERM_WRITE_IMAGEVIDEO"
};

}
PermissionManager* PermissionManager::implInstance_ = nullptr;
std::recursive_mutex PermissionManager::mutex_;

PermissionManager& PermissionManager::GetInstance()
{
    if (implInstance_ == nullptr) {
        std::lock_guard<std::recursive_mutex> lock_l(mutex_);
        if (implInstance_ == nullptr) {
            implInstance_ = new PermissionManager();
        }
    }
    return *implInstance_;
}

void PermissionManager::RegisterImpl(PermissionManager* implInstance)
{
    implInstance_ = implInstance;
}

PermissionManager::PermissionManager()
{}

PermissionManager::~PermissionManager()
{}

int PermissionManager::VerifyHapAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    return HapTokenInfoInner::VerifyPermissionStatus(tokenID, permissionName); // 从data获取
}

PermUsedTypeEnum PermissionManager::GetPermissionUsedType(
    AccessTokenID tokenID, const std::string& permissionName)
{
    if ((tokenID == INVALID_TOKENID) ||
        (TOKEN_HAP != TokenIDAttributes::GetTokenIdTypeEnum(tokenID))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d is invalid.", tokenID);
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    PermUsedTypeEnum ret = HapTokenInfoInner::GetPermissionUsedType(tokenID, permissionName);
    LOGI(ATM_DOMAIN, ATM_TAG,
        "Application %{public}u apply for %{public}s for type %{public}d.", tokenID, permissionName.c_str(), ret);
    return ret;
}

int PermissionManager::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStatus>& reqPermList, bool isSystemGrant)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}u, isSystemGrant: %{public}d", tokenID, isSystemGrant);
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    std::vector<PermissionStatus> tmpList;
    int32_t ret = infoPtr->GetPermissionStateList(tmpList);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetPermissionStateList failed, token %{public}u is invalid.", tokenID);
        return ret;
    }
    for (const auto& perm : tmpList) {
        PermissionBriefDef briefDef;
        if (!GetPermissionBriefDef(perm.permissionName, briefDef)) {
            continue;
        }

        if ((isSystemGrant && briefDef.grantMode == SYSTEM_GRANT) ||
            (!isSystemGrant && briefDef.grantMode != SYSTEM_GRANT)) {
            reqPermList.emplace_back(perm);
        }
    }
    return RET_SUCCESS;
}

static bool IsPermissionRequestedInHap(const std::vector<PermissionStatus>& permsList,
    PermissionListState& permState, int32_t& status, uint32_t& flag)
{
    const std::string permission = permState.permissionName;
    if (!IsPermissionValidForHap(permission)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "No definition for hap permission: %{public}s!", permission.c_str());
        permState.errorReason = PERM_INVALID;
        return false;
    }
    auto iter = std::find_if(permsList.begin(), permsList.end(), [permission](const PermissionStatus& perm) {
        return permission == perm.permissionName;
    });
    if (iter == permsList.end()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Can not find permission: %{public}s from request permission!", permission.c_str());
        permState.errorReason = PERM_NOT_DECLEARED;
        return false;
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "Find goal permission: %{public}s, status: %{public}d, flag: %{public}d",
        permission.c_str(), iter->grantStatus, iter->grantFlag);
    status = iter->grantStatus;
    flag = static_cast<uint32_t>(iter->grantFlag);
    return true;
}

static bool IsPermissionRestrictedByRules(const std::string& permission)
{
    // Several permission is not available to common apps.
    // Specified apps can get the permission by pre-authorization instead of Pop-ups.
    auto iterator = std::find(g_notDisplayedPerms.begin(), g_notDisplayedPerms.end(), permission);
    if (iterator != g_notDisplayedPerms.end()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Permission(%{public}s) is not available to common apps!", permission.c_str());
        return true;
    }

#ifdef SUPPORT_SANDBOX_APP
    // Specified dlp permissions are limited to specified dlp type hap.
    AccessTokenID callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t dlpType = AccessTokenInfoManager::GetInstance().GetHapTokenDlpType(callingTokenId);
    if ((dlpType != DLP_COMMON) &&
        !DlpPermissionSetManager::GetInstance().IsPermissionAvailableToDlpHap(dlpType, permission)) {
        LOGW(ATM_DOMAIN, ATM_TAG,
            "Id(%{public}u) is not allowed to grant dlp permission: %{public}s!", callingTokenId, permission.c_str());
        return true;
    }
#endif

    return false;
}

bool PermissionManager::HandlePermissionDeniedCase(uint32_t goalGrantFlag, PermissionListState& permState)
{
    PermissionBriefDef briefDef;
    if (GetPermissionBriefDef(permState.permissionName, briefDef) && briefDef.grantMode == MANUAL_SETTINGS) {
        permState.state = INVALID_OPER;
        permState.errorReason = MANUAL_SETTING_PERM;
        return true;
    }
    if ((goalGrantFlag & PERMISSION_FIXED_BY_ADMIN_POLICY) != 0) {
        permState.state = FORBIDDEN_OPER;
        permState.errorReason = UNABLE_POP_UP;
        return true;
    }
    if ((goalGrantFlag & PERMISSION_ADMIN_POLICIES_CANCEL) != 0) {
        permState.state = SETTING_OPER;
        permState.errorReason = REQ_SUCCESS;
        return true;
    }
    if ((goalGrantFlag & PERMISSION_FIXED_FOR_SECURITY_POLICY) != 0) {
        permState.state = SETTING_OPER;
        permState.errorReason = REQ_SUCCESS;
        return true;
    }
    if ((goalGrantFlag == PERMISSION_DEFAULT_FLAG) || ((goalGrantFlag & PERMISSION_USER_SET) != 0) ||
        ((goalGrantFlag & PERMISSION_COMPONENT_SET) != 0) || ((goalGrantFlag & PERMISSION_ALLOW_THIS_TIME) != 0)) {
        permState.state = DYNAMIC_OPER;
        permState.errorReason = REQ_SUCCESS;
        return true;
    }
    if ((goalGrantFlag & PERMISSION_USER_FIXED) != 0) {
        permState.state = SETTING_OPER;
        permState.errorReason = REQ_SUCCESS;
        return true;
    }
    return false;
}

void PermissionManager::GetSelfPermissionState(const std::vector<PermissionStatus>& permsList,
    PermissionListState& permState, int32_t apiVersion)
{
    int32_t goalGrantStatus;
    uint32_t goalGrantFlag;

    // api8 require vague location permission refuse directly because there is no vague location permission in api8
    if ((permState.permissionName == VAGUE_LOCATION_PERMISSION_NAME) && (apiVersion < ACCURATE_LOCATION_API_VERSION)) {
        permState.state = INVALID_OPER;
        permState.errorReason = CONDITIONS_NOT_MET;
        return;
    }
    if (!IsPermissionRequestedInHap(permsList, permState, goalGrantStatus, goalGrantFlag)) {
        permState.state = INVALID_OPER;
        return;
    }
    if (IsPermissionRestrictedByRules(permState.permissionName)) {
        permState.state = INVALID_OPER;
        permState.errorReason = UNABLE_POP_UP;
        return;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "%{public}s: status: %{public}d, flag: %{public}d",
        permState.permissionName.c_str(), goalGrantStatus, goalGrantFlag);
    if ((goalGrantStatus == PERMISSION_DENIED) && HandlePermissionDeniedCase(goalGrantFlag, permState)) {
        return;
    }
    permState.state = PASS_OPER;
    permState.errorReason = REQ_SUCCESS;
    return;
}

int PermissionManager::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}u, permissionName: %{public}s", tokenID, permissionName.c_str());
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "%{public}s of %{public}u is invalid!", permissionName.c_str(), tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!IsDefinedPermissionInner(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid %{public}s.", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    uint32_t opCode;
    if (!TransferPermissionToOpcode(permissionName, opCode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid %{public}s.", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    int32_t status = PERMISSION_DENIED;
    return  HapTokenInfoInner::QueryPermissionStatusAndFlag(tokenID, opCode, status, flag);
}

std::shared_ptr<LibraryLoader> PermissionManager::GetAbilityManager()
{
#ifdef DYNAMIC_CLOSE_LIBS
    return std::make_shared<LibraryLoader>(ABILITY_MANAGER_LIBPATH);
#endif
    if (abilityManagerLoader_ == nullptr) {
        std::lock_guard<std::mutex> lock(abilityManagerMutex_);
        if (abilityManagerLoader_ == nullptr) {
            abilityManagerLoader_ = std::make_shared<LibraryLoader>(ABILITY_MANAGER_LIBPATH);
        }
    }
    return abilityManagerLoader_;
}

int32_t PermissionManager::RequestAppPermOnSetting(const HapTokenInfo& hapInfo,
    const std::string& bundleName, const std::string& abilityName)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "bundleName=%{public}s, abilityName=%{public}s, hapInfo.bundleName=%{public}s",
        bundleName.c_str(), abilityName.c_str(), hapInfo.bundleName.c_str());

    InnerWant innerWant = {
        .bundleName = bundleName,
        .abilityName = abilityName,
        .hapBundleName = hapInfo.bundleName,
        .hapAppIndex = hapInfo.instIndex,
        .hapUserID = hapInfo.userID,
        .callerTokenId = IPCSkeleton::GetCallingTokenID()
    };

    std::shared_ptr<LibraryLoader> abilityManagerLoader = GetAbilityManager();
    AbilityManagerAccessLoaderInterface* abilityManager =
        abilityManagerLoader->GetObject<AbilityManagerAccessLoaderInterface>();
    if (abilityManager == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AbilityManager is nullptr!");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    ErrCode err = abilityManager->StartAbility(innerWant, nullptr);
    if (err != ERR_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fail to StartAbility, err:%{public}d", err);
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return ERR_OK;
}

void PermissionManager::NotifyWhenPermissionStateUpdated(const std::string& permissionName,
    bool isGranted, uint32_t flag, const std::shared_ptr<HapTokenInfoInner>& infoPtr)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "IsUpdated");
    AccessTokenID tokenID = infoPtr->GetTokenID();
    int32_t userID = infoPtr->GetUserID();

    uint32_t permCode = 0;
    (void)TransferPermissionToOpcode(permissionName, permCode);
    bool isGrantedBefore = false;
    int32_t ret = PermissionKernelUtils::GetPermFromKernel(tokenID, permCode, isGrantedBefore);
    bool isRestricted = UserPolicyManager::GetInstance().IsPermissionRestricted(tokenID, userID, permCode);
    bool effectiveGranted = isGranted && !isRestricted;
    int32_t changeType = effectiveGranted ? STATE_CHANGE_GRANTED : STATE_CHANGE_REVOKED;
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetPermFromKernel failed, tokenID=%{public}u, permCode=%{public}u, ret=%{public}d.",
            tokenID, permCode, ret);
        PermissionKernelUtils::SetPermToKernel(tokenID, permissionName, effectiveGranted);
    } else if (isGrantedBefore != effectiveGranted) {
        // Keep kernel permission denied when the grant is still restricted by user policy.
        PermissionKernelUtils::SetPermToKernel(tokenID, permissionName, effectiveGranted);
        CallbackManager::GetInstance().ExecuteCallbackAsync(tokenID, permissionName, changeType);
    }

    // To notify the client cache to update by resetting paramValue_.
    PermissionChangeNotifier::GetInstance().ParamUpdate(permissionName, flag, false);

    // DFX.
    PermissionCheckEventInfo eventInfo;
    eventInfo.code = USER_GRANT_PERMISSION_EVENT;
    eventInfo.callerTokenId = tokenID;
    eventInfo.permissionName = permissionName;
    eventInfo.flag = flag;
    eventInfo.changeType = changeType;
    ReportPermissionCheckDetailEvent(eventInfo);
    grantEvent_.AddEvent(tokenID, permissionName, infoPtr->permUpdateTimestamp_);
}

int32_t PermissionManager::UpdateTokenPermissionState(const std::shared_ptr<HapTokenInfoInner>& infoPtr,
    AccessTokenID tokenID, const std::string& permission, bool isGranted, uint32_t flag, bool needKill)
{
    std::string bundleName = infoPtr->GetBundleName();
    bool isSecCompGrantedBefore = HapTokenInfoInner::IsPermissionGrantedWithSecComp(tokenID, permission);
    bool statusChanged = false;
    int32_t ret = infoPtr->UpdatePermissionStatus(permission, isGranted, flag, statusChanged);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to update %{public}s of %{public}u-%{public}s, isGranted=%{public}d, \
            flag=%{public}u, ret=%{public}d.", permission.c_str(), tokenID, bundleName.c_str(), isGranted, flag, ret);
        ReportUpdatePermStatusErrorEvent({.errorCode = UPDATE_PERMISSION_STATUS_FAILED, .tokenId = tokenID,
            .permissionName = permission, .bundleName = bundleName, .val1 = ret, .val2 = static_cast<int32_t>(flag),
            .needKill = needKill});
        return ret;
    }
    if (statusChanged) {
        NotifyWhenPermissionStateUpdated(permission, isGranted, flag, infoPtr);
        // To notify kill process when perm is revoke
        if (needKill && (!isGranted && !isSecCompGrantedBefore)) {
            LOGI(ATM_DOMAIN, ATM_TAG, "(%{public}s) is revoked, kill process(%{public}u, %{public}s).",
                permission.c_str(), tokenID, bundleName.c_str());
            std::shared_ptr<LibraryLoader> abilityManagerLoader = GetAbilityManager();
            AbilityManagerAccessLoaderInterface *abilityManager =
                abilityManagerLoader->GetObject<AbilityManagerAccessLoaderInterface>();
            if (abilityManager == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "AbilityManager is nullptr!");
            } else if ((ret = abilityManager->KillProcessForPermissionUpdate(tokenID)) != ERR_OK) {
                LOGE(ATM_DOMAIN, ATM_TAG, "kill process failed, ret=%{public}d.", ret);
            }
        }
    }
    return RET_SUCCESS;
}

int32_t PermissionManager::UpdateMultiTokenPermissionState(const std::shared_ptr<HapTokenInfoInner> &infoPtr,
    AccessTokenID tokenID, const std::vector<std::string> &permissionList, bool isGranted, uint32_t flag, bool needKill)
{
    HapTokenInfo hapInfo;
    AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, hapInfo);
    ClearThreadErrorMsg();

    int32_t ret = RET_SUCCESS;
    bool isUpdateSuccess = false;
    for (const std::string &permissionName : permissionList) {
        UpdatePermissionInfo updateInfo;
        updateInfo.sceneCode = CommonSceneCode::AT_COMMON_START;
        updateInfo.tokenId = tokenID;
        updateInfo.userID = hapInfo.userID;
        updateInfo.bundleName = hapInfo.bundleName;
        updateInfo.instIndex = hapInfo.instIndex;
        updateInfo.permissionName = permissionName;
        updateInfo.permissionFlag = flag;
        updateInfo.grantedFlag = isGranted;
        ReportUpdatePermissionEvent(updateInfo);

        ret = UpdateTokenPermissionState(infoPtr, tokenID, permissionName, isGranted, flag, needKill);
        if (ret != RET_SUCCESS) {
            break;
        }

        isUpdateSuccess = true;

        uint32_t newFlag = flag;
        if (GetPermissionFlag(tokenID, permissionName, newFlag) == RET_SUCCESS) {
            flag = newFlag;
        }
        updateInfo.sceneCode = CommonSceneCode::AT_COMMON_FINISH;
        updateInfo.permissionFlag = flag;
        ReportUpdatePermissionEvent(updateInfo);
        ReportSysCommonEventError(static_cast<int32_t>(isGranted ?
            IAccessTokenManagerIpcCode::COMMAND_GRANT_PERMISSION :
            IAccessTokenManagerIpcCode::COMMAND_REVOKE_PERMISSION), ret);
    }

    if (isUpdateSuccess) {
        PermissionChangeNotifier::GetInstance().ParamFlagUpdate();
#ifdef TOKEN_SYNC_ENABLE
        TokenModifyNotifier::GetInstance().NotifyTokenModify(tokenID);
#endif
    }
    return ret;
}

int32_t PermissionManager::UpdateTokenPermissionState(
    AccessTokenID id, const std::string& permission, bool isGranted, uint32_t flag, bool needKill)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(id);
    if (infoPtr == nullptr) {
        LOGC(ATM_DOMAIN, ATM_TAG, "%{public}u is not exist.", id);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    int32_t ret = UpdateTokenPermissionStateCheck(infoPtr, id, permission, isGranted, flag);
    if (ret != ERR_OK) {
        return ret;
    }

    // statusBefore cannot use VerifyPermissionStatus in permPolicySet, because the function exclude secComp
    bool isSecCompGrantedBefore = HapTokenInfoInner::IsPermissionGrantedWithSecComp(id, permission);
    bool statusChanged = false;
    ret = infoPtr->UpdatePermissionStatus(permission, isGranted, flag, statusChanged);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to update %{public}s of %{public}us, granted=%{public}d, \
            flag=%{public}u, ret=%{public}d.", permission.c_str(), id, isGranted, flag, ret);
        ReportUpdatePermStatusErrorEvent({.errorCode = UPDATE_PERMISSION_STATUS_FAILED, .tokenId = id,
            .permissionName = permission, .bundleName = infoPtr->GetBundleName(), .val1 = ret,
            .val2 = static_cast<int32_t>(flag), .needKill = needKill});
        return ret;
    }

    // notify flag change
    PermissionChangeNotifier::GetInstance().ParamFlagUpdate();

    if (statusChanged) {
        NotifyWhenPermissionStateUpdated(permission, isGranted, flag, infoPtr);
        // To notify kill process when perm is revoke
        if (needKill && (!isGranted && !isSecCompGrantedBefore)) {
            LOGI(ATM_DOMAIN, ATM_TAG, "(%{public}s) is revoked, kill process(%{public}u).", permission.c_str(), id);
            std::shared_ptr<LibraryLoader> abilityManagerLoader = GetAbilityManager();
            AbilityManagerAccessLoaderInterface* abilityManager =
                abilityManagerLoader->GetObject<AbilityManagerAccessLoaderInterface>();
            if (abilityManager == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "AbilityManager is nullptr!");
            } else if ((ret = abilityManager->KillProcessForPermissionUpdate(id)) != ERR_OK) {
                LOGE(ATM_DOMAIN, ATM_TAG, "kill process failed, ret=%{public}d.", ret);
            }
        }
    }

#ifdef TOKEN_SYNC_ENABLE
    TokenModifyNotifier::GetInstance().NotifyTokenModify(id);
#endif
    return RET_SUCCESS;
}

int32_t PermissionManager::UpdateTokenPermissionStateCheck(const std::shared_ptr<HapTokenInfoInner>& infoPtr,
    AccessTokenID id, const std::string& permission, bool isGranted, uint32_t flag)
{
    std::string bundleName = infoPtr->GetBundleName();
    if (infoPtr->IsRemote()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Remote token can not update");
        return AccessTokenError::ERR_IDENTITY_CHECK_FAILED;
    }
    if ((flag == PERMISSION_ALLOW_THIS_TIME) && isGranted) {
        if (!TempPermissionObserver::GetInstance().IsAllowGrantTempPermission(id, permission)) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Failed to grant perm(%{public}s) of (%{public}u, %{public}s).",
                permission.c_str(), id, bundleName.c_str());
            return ERR_IDENTITY_CHECK_FAILED;
        }
    }

#ifdef SUPPORT_SANDBOX_APP
    int32_t hapDlpType = infoPtr->GetDlpType();
    if (hapDlpType != DLP_COMMON) {
        int32_t permDlpMode = DlpPermissionSetManager::GetInstance().GetPermDlpMode(permission);
        if (!DlpPermissionSetManager::GetInstance().IsPermDlpModeAvailableToDlpHap(hapDlpType, permDlpMode)) {
            LOGC(ATM_DOMAIN, ATM_TAG, "%{public}s cannot to be granted to (%{public}u, %{public}s), \
                dlpType: %{public}d, permDlpMode: %{public}d.",
                permission.c_str(), id, bundleName.c_str(), hapDlpType, permDlpMode);
            ReportUpdatePermStatusErrorEvent({
                .errorCode = DLP_CHECK_FAILED, .tokenId = id, .permissionName = permission,
                .bundleName = bundleName, .val1 = hapDlpType, .val2 = permDlpMode, .needKill = false});
            return AccessTokenError::ERR_IDENTITY_CHECK_FAILED;
        }
    }
#endif
    return ERR_OK;
}

int32_t PermissionManager::UpdateMultiPermissionStatus(
    AccessTokenID tokenID, const std::vector<std::string> &permissionList, int32_t status, uint32_t flag)
{
    bool isGranted = (status == PERMISSION_GRANTED);
    bool needKill = false;
    // To kill process when perm is revoke
    if (!isGranted) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Perm of process(%{public}u) is revoked.", tokenID);
        needKill = true;
    }

    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        LOGC(ATM_DOMAIN, ATM_TAG, "tokenInfo is null, tokenId=%{public}u.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    int32_t ret = UpdateMultiTokenPermissionStateCheck(infoPtr, tokenID, permissionList);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    ret = UpdateMultiTokenPermissionState(infoPtr, tokenID, permissionList, isGranted, flag, needKill);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to update perms of (%{public}u, %{public}s), ret is %{public}d.",
            tokenID, infoPtr->GetBundleName().c_str(), ret);
        return ret;
    }

#ifdef SUPPORT_SANDBOX_APP
    // The action of sharing would be taken place only if the grant operation or revoke operation equals to success.
    std::vector<AccessTokenID> tokenIdList;
    AccessTokenInfoManager::GetInstance().GetRelatedSandBoxHapList(tokenID, tokenIdList);
    for (const auto &id : tokenIdList) {
        (void)UpdateMultiTokenPermissionState(infoPtr, id, permissionList, isGranted, flag, needKill);
    }
#endif

    return RET_SUCCESS;
}

int32_t PermissionManager::UpdateMultiTokenPermissionStateCheck(const std::shared_ptr<HapTokenInfoInner> &infoPtr,
    AccessTokenID tokenID, const std::vector<std::string> &permissionList)
{
    if (infoPtr->IsRemote()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Remote token can not update.");
        return AccessTokenError::ERR_IDENTITY_CHECK_FAILED;
    }

#ifdef SUPPORT_SANDBOX_APP
    int32_t hapDlpType = infoPtr->GetDlpType();
    if (hapDlpType == DLP_COMMON) {
        return RET_SUCCESS;
    }
    for (const std::string& permissionName : permissionList) {
        int32_t permDlpMode = DlpPermissionSetManager::GetInstance().GetPermDlpMode(permissionName);
        if (!DlpPermissionSetManager::GetInstance().IsPermDlpModeAvailableToDlpHap(hapDlpType, permDlpMode)) {
            LOGC(ATM_DOMAIN, ATM_TAG, "%{public}s cannot to be granted to %{public}u, dlpType: %{public}d, \
                permDlpMode: %{public}d.", permissionName.c_str(), tokenID, hapDlpType, permDlpMode);
            ReportUpdatePermStatusErrorEvent({.errorCode = DLP_CHECK_FAILED, .tokenId = tokenID,
                .permissionName = permissionName, .bundleName = infoPtr->GetBundleName(), .val1 = hapDlpType,
                .val2 = permDlpMode, .needKill = false});
            return AccessTokenError::ERR_IDENTITY_CHECK_FAILED;
        }
    }
#endif

    return RET_SUCCESS;
}

int32_t PermissionManager::UpdatePermission(AccessTokenID tokenID, const std::string& permissionName,
    bool isGranted, uint32_t flag, bool needKill)
{
    int32_t ret = UpdateTokenPermissionState(tokenID, permissionName, isGranted, flag, needKill);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to update %{public}s of %{public}u, isGranted=%{public}d, \
            flag=%{public}u, ret=%{public}d.", permissionName.c_str(), tokenID, isGranted, flag, ret);
        return ret;
    }

#ifdef SUPPORT_SANDBOX_APP
    // The action of sharing would be taken place only if the grant operation or revoke operation equals to success.
    std::vector<AccessTokenID> tokenIdList;
    AccessTokenInfoManager::GetInstance().GetRelatedSandBoxHapList(tokenID, tokenIdList);
    for (const auto& id : tokenIdList) {
        (void)UpdateTokenPermissionState(id, permissionName, isGranted, flag, needKill);
    }
#endif

    return RET_SUCCESS;
}

int32_t PermissionManager::CheckAndUpdatePermission(AccessTokenID tokenID, const std::string& permissionName,
    bool isGranted, uint32_t flag, bool killProcess)
{
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        LOGC(ATM_DOMAIN, ATM_TAG, "%{public}s of %{public}u is invalid!", permissionName.c_str(), tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!IsDefinedPermissionInner(permissionName)) {
        LOGC(ATM_DOMAIN, ATM_TAG, "No definition for permission: %{public}s!", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    if (!PermissionValidator::IsPermissionFlagValid(flag) || PermissionValidator::IsPermissionFlagValidForAdmin(flag)) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Flag(%{public}u) of %{public}s from %{public}u is invaid!",
            flag, permissionName.c_str(), tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    bool needKill = false;
    // To kill process when perm is revoke
    if (!isGranted && flag != PERMISSION_COMPONENT_SET) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Perm(%{public}s) of process(%{public}u) is revoked.",
            permissionName.c_str(), tokenID);
        needKill = killProcess;
    }

    return UpdatePermission(tokenID, permissionName, isGranted, flag, needKill);
}

int32_t PermissionManager::CheckAndUpdatePermissionInner(AccessTokenID tokenID, const std::string& permissionName,
    bool isGranted, uint32_t flag, bool killProcess)
{
    HapTokenInfo hapInfo;
    AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, hapInfo);
    ClearThreadErrorMsg();

    UpdatePermissionInfo updateInfo;
    updateInfo.sceneCode = CommonSceneCode::AT_COMMON_START;
    updateInfo.tokenId = tokenID;
    updateInfo.userID = hapInfo.userID;
    updateInfo.bundleName = hapInfo.bundleName;
    updateInfo.instIndex = hapInfo.instIndex;
    updateInfo.permissionName = permissionName;
    updateInfo.permissionFlag = flag;
    updateInfo.grantedFlag = isGranted;
    ReportUpdatePermissionEvent(updateInfo);

    int32_t ret = CheckAndUpdatePermission(tokenID, permissionName, isGranted, flag, killProcess);

    uint32_t newFlag = flag;
    if (ret == RET_SUCCESS && GetPermissionFlag(tokenID, permissionName, newFlag) == RET_SUCCESS) {
        flag = newFlag;
    }

    updateInfo.sceneCode = CommonSceneCode::AT_COMMON_FINISH;
    updateInfo.permissionFlag = flag;
    ReportUpdatePermissionEvent(updateInfo);
    ReportSysCommonEventError(static_cast<int32_t>(isGranted ? IAccessTokenManagerIpcCode::COMMAND_GRANT_PERMISSION :
        IAccessTokenManagerIpcCode::COMMAND_REVOKE_PERMISSION), ret);
    return ret;
}

int32_t PermissionManager::CheckMultiPermissionStatus(
    AccessTokenID tokenID, const std::vector<std::string> &permissionList, int32_t status, uint32_t flag)
{
    if (!PermissionValidator::IsPermissionFlagValidForAdmin(flag)) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Invalid flag: %{public}d!", flag);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    for (const std::string& permissionName : permissionList) {
        LOGI(ATM_DOMAIN, ATM_TAG,
            "Id: %{public}d, perm: %{public}s, status: %{public}d, flag: %{public}d.", tokenID,
            permissionName.c_str(), status, flag);
        if (!IsDefinedPermissionInner(permissionName)) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Perm(%{public}s) is not defined!", permissionName.c_str());
            return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
        }
        if (!IsUserGrantPermission(permissionName)) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Perm(%{public}s) is not user_grant, cannot be granted.", permissionName.c_str());
            return AccessTokenError::ERR_PARAM_INVALID;
        }
    }
    return RET_SUCCESS;
}

int32_t PermissionManager::CheckAndUpdateMultiPermissionStatus(
    AccessTokenID tokenID, const std::vector<std::string> &permissionList, int32_t status, uint32_t flag)
{
    int32_t ret = RET_SUCCESS;
    ret = CheckMultiPermissionStatus(tokenID, permissionList, status, flag);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    ret = UpdateMultiPermissionStatus(tokenID, permissionList, status, flag);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    return RET_SUCCESS;
}

int32_t PermissionManager::GrantPermission(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t flag, UpdatePermissionFlag updateFlag)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}u, permissionName: %{public}s, flag: %{public}d",
        tokenID, permissionName.c_str(), flag);
    
    if (updateFlag < OPERABLE_PERM) {
        PermissionBriefDef briefDef;
        if (GetPermissionBriefDef(permissionName, briefDef) && briefDef.grantMode == MANUAL_SETTINGS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "MANUAL_SETTINGS %{public}s can't be grant.", permissionName.c_str());
            return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
        }
    }
    return CheckAndUpdatePermissionInner(tokenID, permissionName, true, flag);
}

int32_t PermissionManager::RevokePermission(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t flag,
    UpdatePermissionFlag updateFlag, bool killProcess)
{
    LOGI(ATM_DOMAIN, ATM_TAG,
        "TokenID: %{public}u, permissionName: %{public}s, flag: %{public}d, killProcess: %{public}d",
        tokenID, permissionName.c_str(), flag, killProcess);

    if (updateFlag < OPERABLE_PERM) {
        PermissionBriefDef briefDef;
        if (GetPermissionBriefDef(permissionName, briefDef) && briefDef.grantMode == MANUAL_SETTINGS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "MANUAL_SETTINGS %{public}s can't be revoke.", permissionName.c_str());
            return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
        }
    }
    return CheckAndUpdatePermissionInner(tokenID, permissionName, false, flag, killProcess);
}

int32_t PermissionManager::GrantPermissionForSpecifiedTime(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t onceTime)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}u, permissionName: %{public}s, onceTime: %{public}d",
        tokenID, permissionName.c_str(), onceTime);
    return ShortGrantManager::GetInstance().RefreshPermission(tokenID, permissionName, onceTime);
}

void PermissionManager::ScopeToString(
    const std::vector<AccessTokenID>& tokenIDs, const std::vector<std::string>& permList)
{
    std::stringstream str;
    copy(tokenIDs.begin(), tokenIDs.end(), std::ostream_iterator<uint32_t>(str, ", "));
    std::string tokenidStr = str.str();

    std::string permStr = accumulate(permList.begin(), permList.end(), std::string(" "));

    LOGI(ATM_DOMAIN, ATM_TAG, "TokenidStr = %{public}s permStr =%{public}s",
        tokenidStr.c_str(), permStr.c_str());
}

int32_t PermissionManager::SetPermissionStatusWithPolicy(
    AccessTokenID tokenID, const std::vector<std::string>& permissionList, int32_t status, uint32_t flag)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}u, status: %{public}d, flag: %{public}u.", tokenID, status, flag);
    return CheckAndUpdateMultiPermissionStatus(tokenID, permissionList, status, flag);
}

int32_t PermissionManager::ScopeFilter(const PermStateChangeScope& scopeSrc, PermStateChangeScope& scopeRes)
{
    std::set<uint32_t> tokenIdSet;
    for (const auto& tokenId : scopeSrc.tokenIDs) {
        if (AccessTokenInfoManager::GetInstance().IsTokenIdExist(tokenId) &&
            (tokenIdSet.count(tokenId) == 0)) {
            scopeRes.tokenIDs.emplace_back(tokenId);
            tokenIdSet.insert(tokenId);
            continue;
        }
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId %{public}d invalid!", tokenId);
    }
    std::set<std::string> permSet;
    for (const auto& permissionName : scopeSrc.permList) {
        if (IsDefinedPermissionInner(permissionName) &&
            permSet.count(permissionName) == 0) {
            scopeRes.permList.emplace_back(permissionName);
            permSet.insert(permissionName);
            continue;
        }
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission %{public}s invalid!", permissionName.c_str());
    }
    if ((scopeRes.tokenIDs.empty()) && (!scopeSrc.tokenIDs.empty())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Valid tokenid size is 0!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if ((scopeRes.permList.empty()) && (!scopeSrc.permList.empty())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Valid permission size is 0!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    ScopeToString(scopeRes.tokenIDs, scopeRes.permList);
    return RET_SUCCESS;
}

int32_t PermissionManager::AddPermStateChangeCallback(
    const PermStateChangeScope& scope, const sptr<IRemoteObject>& callback)
{
    PermStateChangeScope scopeRes;
    int32_t result = ScopeFilter(scope, scopeRes);
    if (result != RET_SUCCESS) {
        return result;
    }
    return CallbackManager::GetInstance().AddCallback(scopeRes, callback);
}

int32_t PermissionManager::RemovePermStateChangeCallback(const sptr<IRemoteObject>& callback)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Called");
    return CallbackManager::GetInstance().RemoveCallback(callback);
}

bool PermissionManager::IsPermissionVaild(const std::string& permissionName)
{
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Invalid permissionName %{public}s", permissionName.c_str());
        return false;
    }

    if (!IsDefinedPermissionInner(permissionName)) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Permission %{public}s has no definition ", permissionName.c_str());
        return false;
    }
    return true;
}

bool PermissionManager::GetLocationPermissionIndex(std::vector<PermissionListStateParcel>& reqPermList,
    LocationIndex& locationIndex)
{
    uint32_t index = 0;
    bool hasFound = false;

    for (const auto& perm : reqPermList) {
        if (perm.permsState.permissionName == VAGUE_LOCATION_PERMISSION_NAME) {
            locationIndex.vagueIndex = index;
            hasFound = true;
        } else if (perm.permsState.permissionName == ACCURATE_LOCATION_PERMISSION_NAME) {
            locationIndex.accurateIndex = index;
            hasFound = true;
        } else if (perm.permsState.permissionName == BACKGROUND_LOCATION_PERMISSION_NAME) {
            locationIndex.backIndex = index;
            hasFound = true;
        }

        index++;

        if ((locationIndex.vagueIndex != PERMISSION_NOT_REQUSET) &&
            (locationIndex.accurateIndex != PERMISSION_NOT_REQUSET) &&
            (locationIndex.backIndex != PERMISSION_NOT_REQUSET)) {
            break;
        }
    }

    LOGI(ATM_DOMAIN, ATM_TAG,
        "vague index is %{public}d, accurate index is %{public}d, background index is %{public}d!",
        locationIndex.vagueIndex, locationIndex.accurateIndex, locationIndex.backIndex);

    return hasFound;
}

bool PermissionManager::GetLocationPermissionState(AccessTokenID tokenID,
    std::vector<PermissionListStateParcel>& reqPermList, std::vector<PermissionStatus>& permsList,
    int32_t apiVersion, const LocationIndex& locationIndex)
{
    bool needVagueDynamic = false;
    bool needAccurateDynamic = false; // needVagueDynamic-false, 1. not request;2. request but not equal to DYNAMIC_OPER
    if (locationIndex.vagueIndex != PERMISSION_NOT_REQUSET) {
        GetSelfPermissionState(permsList, reqPermList[locationIndex.vagueIndex].permsState, apiVersion);
        needVagueDynamic = reqPermList[locationIndex.vagueIndex].permsState.state == DYNAMIC_OPER;
    }

    if (locationIndex.accurateIndex != PERMISSION_NOT_REQUSET) {
        bool isVagueGranted = VerifyHapAccessToken(tokenID, VAGUE_LOCATION_PERMISSION_NAME) == PERMISSION_GRANTED;
        // request accurate and vague permission, if vague has been set or invalid, accurate can't be requested
        GetSelfPermissionState(permsList, reqPermList[locationIndex.accurateIndex].permsState, apiVersion);
        needAccurateDynamic = reqPermList[locationIndex.accurateIndex].permsState.state == DYNAMIC_OPER;

        // update permsState
        if (needAccurateDynamic) {
            // vague permissoion is not pop and permission status os not granted
            if (!needVagueDynamic && !isVagueGranted) {
                reqPermList[locationIndex.accurateIndex].permsState.state = INVALID_OPER;
                reqPermList[locationIndex.accurateIndex].permsState.errorReason = CONDITIONS_NOT_MET;
                needAccurateDynamic = false;
            }
        }
    }

    if (locationIndex.backIndex != PERMISSION_NOT_REQUSET) {
        if (apiVersion >= BACKGROUND_LOCATION_API_VERSION) {
            // background permission
            // with back and vague permission, request back can not pop dynamic dialog
            if (locationIndex.vagueIndex != PERMISSION_NOT_REQUSET) {
                reqPermList[locationIndex.vagueIndex].permsState.state = INVALID_OPER;
                reqPermList[locationIndex.vagueIndex].permsState.errorReason = CONDITIONS_NOT_MET;
            }
            if (locationIndex.accurateIndex != PERMISSION_NOT_REQUSET) {
                reqPermList[locationIndex.accurateIndex].permsState.state = INVALID_OPER;
                reqPermList[locationIndex.accurateIndex].permsState.errorReason = CONDITIONS_NOT_MET;
            }
            reqPermList[locationIndex.backIndex].permsState.state = INVALID_OPER;
            reqPermList[locationIndex.backIndex].permsState.errorReason = CONDITIONS_NOT_MET;
            return false;
        }
        // with back and vague permission
        // back state is SETTING_OPER when dynamic pop-up dialog appears and INVALID_OPER when it doesn't
        GetSelfPermissionState(permsList, reqPermList[locationIndex.backIndex].permsState, apiVersion);
        if (reqPermList[locationIndex.backIndex].permsState.state == DYNAMIC_OPER) {
            if (needAccurateDynamic || needVagueDynamic) {
                reqPermList[locationIndex.backIndex].permsState.state = SETTING_OPER;
                reqPermList[locationIndex.backIndex].permsState.errorReason = REQ_SUCCESS;
            } else {
                reqPermList[locationIndex.backIndex].permsState.state = INVALID_OPER;
                reqPermList[locationIndex.backIndex].permsState.errorReason = CONDITIONS_NOT_MET;
            }
        }
    }
    return needVagueDynamic || needAccurateDynamic;
}

bool PermissionManager::LocationPermissionSpecialHandle(
    AccessTokenID tokenID,
    std::vector<PermissionListStateParcel>& reqPermList,
    std::vector<PermissionStatus>& permsList, int32_t apiVersion)
{
    struct LocationIndex locationIndex;
    if (!GetLocationPermissionIndex(reqPermList, locationIndex)) {
        return false;
    }
    return GetLocationPermissionState(tokenID, reqPermList, permsList, apiVersion, locationIndex);
}

void PermissionManager::NotifyPermGrantStoreResult(bool result, uint64_t timestamp)
{
    grantEvent_.NotifyPermGrantStoreResult(result, timestamp);
}

void PermissionManager::NotifyUpdatedPermList(const std::vector<std::string>& grantedPermListBefore,
    const std::vector<std::string>& grantedPermListAfter, AccessTokenID tokenID)
{
    for (uint32_t i = 0; i < grantedPermListBefore.size(); i++) {
        LOGI(ATM_DOMAIN, ATM_TAG, "grantedPermListBefore[i] %{public}s.", grantedPermListBefore[i].c_str());
        auto it = find(grantedPermListAfter.begin(), grantedPermListAfter.end(), grantedPermListBefore[i]);
        if (it == grantedPermListAfter.end()) {
            CallbackManager::GetInstance().ExecuteCallbackAsync(
                tokenID, grantedPermListBefore[i], STATE_CHANGE_REVOKED);
            PermissionChangeNotifier::GetInstance().ParamUpdate(grantedPermListBefore[i], 0, true);
        }
    }
    for (uint32_t i = 0; i < grantedPermListAfter.size(); i++) {
        LOGI(ATM_DOMAIN, ATM_TAG, "grantedPermListAfter[i] %{public}s.", grantedPermListAfter[i].c_str());
        auto it = find(grantedPermListBefore.begin(), grantedPermListBefore.end(), grantedPermListAfter[i]);
        if (it == grantedPermListBefore.end()) {
            CallbackManager::GetInstance().ExecuteCallbackAsync(
                tokenID, grantedPermListAfter[i], STATE_CHANGE_GRANTED);
            PermissionChangeNotifier::GetInstance().ParamUpdate(grantedPermListAfter[i], 0, false);
        }
    }
}

bool IsUserGrantPermPreAuthorized(const std::vector<PreAuthorizationInfo> &list,
    const std::string &permissionName, bool &userCancelable)
{
    auto iter = std::find_if(list.begin(), list.end(), [&permissionName](const auto &info) {
            return info.permissionName == permissionName;
        });
    if (iter == list.end()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Permission(%{public}s) is not in the list", permissionName.c_str());
        return false;
    }

    userCancelable = iter->userCancelable;
    return true;
}

void PermissionManager::GetMasterAppUndValues(AccessTokenID tokenId, std::vector<GenericValues>& undefValues)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> results;

    // get master app hap undefined data
    int32_t res = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, conditionValue, results);
    if (res != 0) {
        return;
    }

    if (results.empty()) {
        return;
    }

    for (auto& value : results) {
        value.Remove(TokenFiledConst::FIELD_TOKEN_ID);
        undefValues.emplace_back(value);
    }
}

bool PermissionManager::InitDlpPermissionList(const HapInfoParams& info,
    std::vector<PermissionStatus>& initializedList, std::vector<GenericValues>& undefValues)
{
    // get dlp original app, index is 0
    AccessTokenIDEx tokenId = AccessTokenInfoManager::GetInstance().GetHapTokenID(info.userID, info.bundleName, 0);
    std::shared_ptr<HapTokenInfoInner> infoPtr =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId.tokenIdExStruct.tokenID);
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", tokenId.tokenIdExStruct.tokenID);
        return false;
    }
    (void)infoPtr->GetPermissionStateList(initializedList);
    GetMasterAppUndValues(tokenId.tokenIdExStruct.tokenID, undefValues);
    return true;
}

void PermissionManager::FillUndefinedPermVector(const std::string& permissionName,
    const std::string& appDistributionType, const HapPolicy& policy, std::vector<GenericValues>& undefValues)
{
    GenericValues value;
    value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
    value.Put(TokenFiledConst::FIELD_APP_DISTRIBUTION_TYPE, appDistributionType);

    auto it = std::find_if(
        policy.aclRequestedList.begin(), policy.aclRequestedList.end(), [permissionName](const std::string& perm) {
        return permissionName == perm;
    });
    if (it != policy.aclRequestedList.end()) {
        value.Put(TokenFiledConst::FIELD_ACL, 1);
    } else {
        value.Put(TokenFiledConst::FIELD_ACL, 0);
    }

    auto iter = std::find_if(policy.aclExtendedMap.begin(), policy.aclExtendedMap.end(),
        [permissionName](const auto& item) {
            return permissionName == item.first;
        });
    if (iter != policy.aclExtendedMap.end()) {
        value.Put(TokenFiledConst::FIELD_VALUE, iter->second);
    }

    undefValues.emplace_back(value);

    return;
}

void PermissionManager::InitPermState(const HapPolicy& policy,
    const PermissionBriefDef& briefDef, bool needGrantForDebug, PermissionStatus& state)
{
    if (briefDef.grantMode == AccessToken::GrantMode::SYSTEM_GRANT) {
        state.grantFlag = PERMISSION_SYSTEM_FIXED;
        state.grantStatus = PERMISSION_GRANTED;
        return;
    }
    if (policy.preAuthorizationInfo.empty() && (!needGrantForDebug)) {
        return;
    }
    bool userCancelable = true;
    if (IsUserGrantPermPreAuthorized(policy.preAuthorizationInfo, state.permissionName, userCancelable)) {
        state.grantFlag = userCancelable ? PERMISSION_PRE_AUTHORIZED_CANCELABLE : PERMISSION_SYSTEM_FIXED;
        state.grantStatus = PERMISSION_GRANTED;
    } else if (needGrantForDebug) {
        state.grantFlag = PERMISSION_USER_FIXED;
        state.grantStatus = PERMISSION_GRANTED;
    }
}

bool PermissionManager::InitPermissionList(const BundleParam& param, const HapPolicy& policy,
    std::vector<PermissionStatus>& initializedList, HapInfoCheckResult& result,
    std::vector<GenericValues>& undefValues, bool dataRefresh)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Before, request perm list size: %{public}zu, preAuthorizationInfo size %{public}zu, "
        "ACLRequestedList size %{public}zu.", policy.permStateList.size(),
        policy.preAuthorizationInfo.size(), policy.aclRequestedList.size());

    PermissionStatus state;
    bool needGrantForDebug = param.isDebug && policy.isDebugGrant;
    for (const auto& status : policy.permStateList) {
        state = status;
        PermissionBriefDef briefDef;
        if (!GetPermissionBriefDef(state.permissionName, briefDef) || !briefDef.isEnable) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get definition of %{public}s failed.",
                state.permissionName.c_str());
#ifdef IS_SUPPORT_HAP_RUNNING
            FillUndefinedPermVector(state.permissionName, Verify::AppDistTypeToString(
                static_cast<Verify::AppDistType>(param.distributionType)),
                policy, undefValues);
#endif
            continue;
        }

        result.permCheckResult.permissionName = state.permissionName;
        if (!PermissionConstraintCheck::AclAndEdmCheck(param, briefDef, policy, result)) {
            if (dataRefresh) {
#ifdef IS_SUPPORT_HAP_RUNNING
                FillUndefinedPermVector(state.permissionName, Verify::AppDistTypeToString(
                    static_cast<Verify::AppDistType>(param.distributionType)),
                    policy, undefValues);
#endif
                continue;
            }
            return false;
        }

        state.grantFlag = PERMISSION_DEFAULT_FLAG;
        state.grantStatus = PERMISSION_DENIED;

        InitPermState(policy, briefDef, needGrantForDebug, state);
        initializedList.emplace_back(state);
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "After, request perm list size: %{public}zu.", initializedList.size());
    return true;
}

bool PermissionManager::InitPermissionList(const BundleParam& param, const HapPolicy& policy,
    std::vector<PermissionStatus>& initializedList, HapInfoCheckResult& result)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Before, request perm list size: %{public}zu, preAuthorizationInfo size %{public}zu, "
        "ACLRequestedList size %{public}zu.", policy.permStateList.size(),
        policy.preAuthorizationInfo.size(), policy.aclRequestedList.size());

    PermissionStatus state;
    bool needGrantForDebug = param.isDebug && policy.isDebugGrant;
    for (const auto& status : policy.permStateList) {
        state = status;
        PermissionBriefDef briefDef;
        if (!GetPermissionBriefDef(state.permissionName, briefDef) || !briefDef.isEnable) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get definition of %{public}s failed.",
                state.permissionName.c_str());
            continue;
        }

        result.permCheckResult.permissionName = state.permissionName;
        if (!PermissionConstraintCheck::AclAndEdmCheck(param, briefDef, policy, result)) {
            return false;
        }

        state.grantFlag = PERMISSION_DEFAULT_FLAG;
        state.grantStatus = PERMISSION_DENIED;

        InitPermState(policy, briefDef, needGrantForDebug, state);
        initializedList.emplace_back(state);
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "After, request perm list size: %{public}zu.", initializedList.size());
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
