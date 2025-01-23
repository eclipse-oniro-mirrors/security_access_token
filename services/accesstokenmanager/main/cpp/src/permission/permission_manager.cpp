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

#include "permission_manager.h"

#include <iostream>
#include <numeric>
#include <sstream>

#include "ability_manager_access_loader.h"
#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "access_token_db.h"
#include "app_manager_access_client.h"
#include "callback_manager.h"
#include "constant_common.h"
#ifdef SUPPORT_SANDBOX_APP
#include "dlp_permission_set_manager.h"
#endif
#include "ipc_skeleton.h"
#include "hisysevent_adapter.h"
#include "parameter.h"
#include "permission_definition_cache.h"
#include "short_grant_manager.h"
#include "permission_map.h"
#include "permission_validator.h"
#include "perm_setproc.h"
#include "token_field_const.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_modify_notifier.h"
#endif
#include "want.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "PermissionManager"};
static const char* PERMISSION_STATUS_CHANGE_KEY = "accesstoken.permission.change";
static constexpr int32_t VALUE_MAX_LEN = 32;
static const std::vector<std::string> g_notDisplayedPerms = {
    "ohos.permission.ANSWER_CALL",
    "ohos.permission.MANAGE_VOICEMAIL",
    "ohos.permission.READ_CELL_MESSAGES",
    "ohos.permission.READ_MESSAGES",
    "ohos.permission.RECEIVE_MMS",
    "ohos.permission.RECEIVE_SMS",
    "ohos.permission.RECEIVE_WAP_MESSAGES",
    "ohos.permission.SEND_MESSAGES",
    "ohos.permission.READ_CALL_LOG",
    "ohos.permission.WRITE_CALL_LOG",
    "ohos.permission.SHORT_TERM_WRITE_IMAGEVIDEO"
};
constexpr const char* APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* APP_INDEX = "appIndex";
constexpr const char* USER_ID = "userId";
constexpr const char* CALLER_TOKENID = "callerTokenId";
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
{
    char value[VALUE_MAX_LEN] = {0};
    int32_t ret = GetParameter(PERMISSION_STATUS_CHANGE_KEY, "", value, VALUE_MAX_LEN - 1);
    if (ret < 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Return default value, ret=%{public}d", ret);
        paramValue_ = 0;
        return;
    }
    paramValue_ = static_cast<uint64_t>(std::atoll(value));
}

PermissionManager::~PermissionManager()
{}

void PermissionManager::AddDefPermissions(const std::vector<PermissionDef>& permList, AccessTokenID tokenId,
    bool updateFlag)
{
    std::vector<PermissionDef> permFilterList;
    PermissionValidator::FilterInvalidPermissionDef(permList, permFilterList);
    ACCESSTOKEN_LOG_INFO(LABEL, "PermFilterList size: %{public}zu", permFilterList.size());
    for (const auto& perm : permFilterList) {
        if (updateFlag) {
            PermissionDefinitionCache::GetInstance().Update(perm, tokenId);
            continue;
        }

        if (!PermissionDefinitionCache::GetInstance().HasDefinition(perm.permissionName)) {
            PermissionDefinitionCache::GetInstance().Insert(perm, tokenId);
        } else {
            PermissionDefinitionCache::GetInstance().Update(perm, tokenId);
            ACCESSTOKEN_LOG_INFO(LABEL, "Permission %{public}s has define", perm.permissionName.c_str());
        }
    }
}

void PermissionManager::RemoveDefPermissions(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID: %{public}u", tokenID);
    PermissionDefinitionCache::GetInstance().DeleteByToken(tokenID);
}

int PermissionManager::VerifyHapAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    return HapTokenInfoInner::VerifyPermissionStatus(tokenID, permissionName); // 从data获取
}

PermUsedTypeEnum PermissionManager::GetPermissionUsedType(
    AccessTokenID tokenID, const std::string& permissionName)
{
    if ((tokenID == INVALID_TOKENID) ||
        (TOKEN_HAP != AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenID))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID: %{public}d is invalid.", tokenID);
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    PermUsedTypeEnum ret = HapTokenInfoInner::GetPermissionUsedType(tokenID, permissionName);
    ACCESSTOKEN_LOG_INFO(LABEL,
        "Application %{public}u apply for %{public}s for type %{public}d.", tokenID, permissionName.c_str(), ret);
    return ret;
}

int PermissionManager::GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult)
{
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid params!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return PermissionDefinitionCache::GetInstance().FindByPermissionName(permissionName, permissionDefResult);
}

void PermissionManager::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList)
{
    PermissionDefinitionCache::GetInstance().GetDefPermissionsByTokenId(permList, tokenID);
}

int PermissionManager::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStatus>& reqPermList, bool isSystemGrant)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called, tokenID: %{public}u, isSystemGrant: %{public}d",
        __func__, tokenID, isSystemGrant);
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Token %{public}u is invalid.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    GrantMode mode = isSystemGrant ? SYSTEM_GRANT : USER_GRANT;
    std::vector<PermissionStatus> tmpList;
    int32_t ret = infoPtr->GetPermissionStateList(tmpList);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetPermissionStateList failed, token %{public}u is invalid.", tokenID);
        return ret;
    }
    for (const auto& perm : tmpList) {
        PermissionDef permDef;
        GetDefPermission(perm.permissionName, permDef);
        if (permDef.grantMode == mode) {
            reqPermList.emplace_back(perm);
        }
    }
    return RET_SUCCESS;
}

static bool IsPermissionRequestedInHap(const std::vector<PermissionStatus>& permsList,
    PermissionListState& permState, int32_t& status, uint32_t& flag)
{
    const std::string permission = permState.permissionName;
    if (!PermissionDefinitionCache::GetInstance().HasHapPermissionDefinitionForHap(permission)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "No definition for hap permission: %{public}s!", permission.c_str());
        permState.errorReason = PERM_INVALID;
        return false;
    }
    auto iter = std::find_if(permsList.begin(), permsList.end(), [permission](const PermissionStatus& perm) {
        return permission == perm.permissionName;
    });
    if (iter == permsList.end()) {
        ACCESSTOKEN_LOG_WARN(LABEL, "Can not find permission: %{public}s define!", permission.c_str());
        permState.errorReason = PERM_NOT_DECLEARED;
        return false;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Find goal permission: %{public}s, status: %{public}d, flag: %{public}d",
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
        ACCESSTOKEN_LOG_WARN(LABEL, "Permission is not available to common apps: %{public}s!", permission.c_str());
        return true;
    }

#ifdef SUPPORT_SANDBOX_APP
    // Specified dlp permissions are limited to specified dlp type hap.
    AccessTokenID callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t dlpType = AccessTokenInfoManager::GetInstance().GetHapTokenDlpType(callingTokenId);
    if ((dlpType != DLP_COMMON) &&
        !DlpPermissionSetManager::GetInstance().IsPermissionAvailableToDlpHap(dlpType, permission)) {
        ACCESSTOKEN_LOG_WARN(LABEL,
            "callingTokenId is not allowed to grant dlp permission: %{public}s!", permission.c_str());
        return true;
    }
#endif

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
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s: status: %{public}d, flag: %{public}d",
        permState.permissionName.c_str(), goalGrantStatus, goalGrantFlag);
    if (goalGrantStatus == PERMISSION_DENIED) {
        if ((goalGrantFlag & PERMISSION_POLICY_FIXED) != 0) {
            permState.state = SETTING_OPER;
            permState.errorReason = REQ_SUCCESS;
            return;
        }

        if ((goalGrantFlag == PERMISSION_DEFAULT_FLAG) || ((goalGrantFlag & PERMISSION_USER_SET) != 0) ||
            ((goalGrantFlag & PERMISSION_COMPONENT_SET) != 0) || ((goalGrantFlag & PERMISSION_ALLOW_THIS_TIME) != 0)) {
            permState.state = DYNAMIC_OPER;
            permState.errorReason = REQ_SUCCESS;
            return;
        }
        if ((goalGrantFlag & PERMISSION_USER_FIXED) != 0) {
            permState.state = SETTING_OPER;
            permState.errorReason = REQ_SUCCESS;
            return;
        }
    }
    permState.state = PASS_OPER;
    permState.errorReason = REQ_SUCCESS;
    return;
}

int PermissionManager::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: %{public}u, permissionName: %{public}s",
        __func__, tokenID, permissionName.c_str());
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PermissionName:%{public}s invalid!", permissionName.c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "No definition for permission: %{public}s!", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    uint32_t fullFlag;
    int32_t ret = HapTokenInfoInner::QueryPermissionFlag(tokenID, permissionName, fullFlag);
    if (ret == RET_SUCCESS) {
        flag = ConstantCommon::GetFlagWithoutSpecifiedElement(fullFlag, PERMISSION_GRANTED_BY_POLICY);
    }
    return ret;
}

int32_t PermissionManager::RequestAppPermOnSetting(const HapTokenInfo& hapInfo,
    const std::string& bundleName, const std::string& abilityName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "bundleName=%{public}s, abilityName=%{public}s, hapInfo.bundleName=%{public}s",
        bundleName.c_str(), abilityName.c_str(), hapInfo.bundleName.c_str());
    AAFwk::Want want;
    want.SetElementName(bundleName, abilityName);
    want.SetParam(BUNDLE_NAME, hapInfo.bundleName);
    want.SetParam(APP_INDEX, hapInfo.instIndex);
    want.SetParam(USER_ID, hapInfo.userID);

    AccessTokenID callerTokenId = IPCSkeleton::GetCallingTokenID();
    want.SetParam(CALLER_TOKENID, std::to_string(callerTokenId));

    {
        std::lock_guard<std::mutex> lock(abilityManagerMutex_);
        if (abilityManagerLoader_ == nullptr) {
            abilityManagerLoader_ = std::make_shared<LibraryLoader>(ABILITY_MANAGER_LIBPATH);
        }
    }

    AbilityManagerAccessLoaderInterface* abilityManager =
        abilityManagerLoader_->GetObject<AbilityManagerAccessLoaderInterface>();
    if (abilityManager == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "AbilityManager is nullptr!");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    ErrCode err = abilityManager->StartAbility(want, nullptr);
    if (err != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to StartAbility, err:%{public}d", err);
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return ERR_OK;
}

void PermissionManager::ParamUpdate(const std::string& permissionName, uint32_t flag, bool filtered)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permParamSetLock_);
    if (filtered || (PermissionDefinitionCache::GetInstance().IsUserGrantedPermission(permissionName) &&
        ((flag != PERMISSION_GRANTED_BY_POLICY) && (flag != PERMISSION_SYSTEM_FIXED)))) {
        paramValue_++;
        ACCESSTOKEN_LOG_DEBUG(LABEL,
            "paramValue_ change %{public}llu", static_cast<unsigned long long>(paramValue_));
        int32_t res = SetParameter(PERMISSION_STATUS_CHANGE_KEY, std::to_string(paramValue_).c_str());
        if (res != 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "SetParameter failed %{public}d", res);
        }
    }
}

void PermissionManager::NotifyWhenPermissionStateUpdated(AccessTokenID tokenID, const std::string& permissionName,
    bool isGranted, uint32_t flag, const std::shared_ptr<HapTokenInfoInner>& infoPtr)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "IsUpdated");
    int32_t changeType = isGranted ? STATE_CHANGE_GRANTED : STATE_CHANGE_REVOKED;

    // set to kernel(grant/revoke)
    SetPermToKernel(tokenID, permissionName, isGranted);

    // To notify the listener register.
    CallbackManager::GetInstance().ExecuteCallbackAsync(tokenID, permissionName, changeType);

    // To notify the client cache to update by resetting paramValue_.
    ParamUpdate(permissionName, flag, false);

    // DFX.
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK_EVENT",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "CODE", USER_GRANT_PERMISSION_EVENT,
        "CALLER_TOKENID", tokenID, "PERMISSION_NAME", permissionName, "FLAG", flag,
        "PERMISSION_GRANT_TYPE", changeType);
    grantEvent_.AddEvent(tokenID, permissionName, infoPtr->permUpdateTimestamp_);
}

int32_t PermissionManager::UpdateTokenPermissionState(
    AccessTokenID id, const std::string& permission, bool isGranted, uint32_t flag, bool needKill)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(id);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenInfo is null, tokenId=%{public}u", id);
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
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "UPDATE_PERMISSION_STATUS_ERROR",
            HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", UPDATE_PERMISSION_STATUS_FAILED, "TOKENID", id,
            "PERM", permission, "BUNDLE_NAME", infoPtr->GetBundleName(), "INT_VAL1", ret,
            "INT_VAL2", static_cast<int32_t>(flag), "NEED_KILL", needKill);
        return ret;
    }
    if (statusChanged) {
        NotifyWhenPermissionStateUpdated(id, permission, isGranted, flag, infoPtr);
        // To notify kill process when perm is revoke
        if (needKill && (!isGranted && !isSecCompGrantedBefore)) {
            ACCESSTOKEN_LOG_INFO(LABEL, "(%{public}s) is revoked, kill process(%{public}u).", permission.c_str(), id);
            if ((ret = AppManagerAccessClient::GetInstance().KillProcessesByAccessTokenId(id)) != ERR_OK) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "kill process failed, ret=%{public}d.", ret);
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
    if (infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Remote token can not update");
        return AccessTokenError::ERR_IDENTITY_CHECK_FAILED;
    }
    if ((flag == PERMISSION_ALLOW_THIS_TIME) && isGranted) {
        if (!TempPermissionObserver::GetInstance().IsAllowGrantTempPermission(id, permission)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Id:%{public}d fail to grant permission:%{public}s", id, permission.c_str());
            return ERR_IDENTITY_CHECK_FAILED;
        }
    }

#ifdef SUPPORT_SANDBOX_APP
    int32_t hapDlpType = infoPtr->GetDlpType();
    if (hapDlpType != DLP_COMMON) {
        int32_t permDlpMode = DlpPermissionSetManager::GetInstance().GetPermDlpMode(permission);
        if (!DlpPermissionSetManager::GetInstance().IsPermDlpModeAvailableToDlpHap(hapDlpType, permDlpMode)) {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s cannot to be granted to %{public}u", permission.c_str(), id);
            HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "UPDATE_PERMISSION_STATUS_ERROR",
                HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_CODE", DLP_CHECK_FAILED, "TOKENID", id, "PERM",
                permission, "BUNDLE_NAME", infoPtr->GetBundleName(), "INT_VAL1", hapDlpType, "INT_VAL2", permDlpMode);
            return AccessTokenError::ERR_IDENTITY_CHECK_FAILED;
        }
    }
#endif
    return ERR_OK;
}

int32_t PermissionManager::UpdatePermission(AccessTokenID tokenID, const std::string& permissionName,
    bool isGranted, uint32_t flag, bool needKill)
{
    int32_t ret = UpdateTokenPermissionState(tokenID, permissionName, isGranted, flag, needKill);
    if (ret != RET_SUCCESS) {
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

    // DFX
    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "UPDATE_PERMISSION",
        HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "TOKENID", tokenID, "PERMISSION_NAME",
        permissionName, "PERMISSION_FLAG", flag, "GRANTED_FLAG", isGranted);
    return RET_SUCCESS;
}

int32_t PermissionManager::CheckAndUpdatePermission(AccessTokenID tokenID, const std::string& permissionName,
    bool isGranted, uint32_t flag)
{
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permissionName: %{public}s, Invalid params!", permissionName.c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "No definition for permission: %{public}s!", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    if (!PermissionValidator::IsPermissionFlagValid(flag)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "flag: %{public}d, Invalid params!", flag);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    bool needKill = false;
    // To kill process when perm is revoke
    if (!isGranted && flag != PERMISSION_COMPONENT_SET) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Perm(%{public}s) is revoked, kill process(%{public}u).",
            permissionName.c_str(), tokenID);
        needKill = true;
    }

    return UpdatePermission(tokenID, permissionName, isGranted, flag, needKill);
}

int32_t PermissionManager::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: %{public}u, permissionName: %{public}s, flag: %{public}d",
        __func__, tokenID, permissionName.c_str(), flag);
    return CheckAndUpdatePermission(tokenID, permissionName, true, flag);
}

int32_t PermissionManager::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: %{public}u, permissionName: %{public}s, flag: %{public}d",
        __func__, tokenID, permissionName.c_str(), flag);
    return CheckAndUpdatePermission(tokenID, permissionName, false, flag);
}

int32_t PermissionManager::GrantPermissionForSpecifiedTime(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t onceTime)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: %{public}u, permissionName: %{public}s, onceTime: %{public}d",
        __func__, tokenID, permissionName.c_str(), onceTime);
    return ShortGrantManager::GetInstance().RefreshPermission(tokenID, permissionName, onceTime);
}

void PermissionManager::ScopeToString(
    const std::vector<AccessTokenID>& tokenIDs, const std::vector<std::string>& permList)
{
    std::stringstream str;
    copy(tokenIDs.begin(), tokenIDs.end(), std::ostream_iterator<uint32_t>(str, ", "));
    std::string tokenidStr = str.str();

    std::string permStr;
    permStr = accumulate(permList.begin(), permList.end(), std::string(" "));

    ACCESSTOKEN_LOG_INFO(LABEL, "TokenidStr = %{public}s permStr =%{public}s",
        tokenidStr.c_str(), permStr.c_str());
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenId %{public}d invalid!", tokenId);
    }
    std::set<std::string> permSet;
    for (const auto& permissionName : scopeSrc.permList) {
        if (PermissionDefinitionCache::GetInstance().HasDefinition(permissionName) &&
            permSet.count(permissionName) == 0) {
            scopeRes.permList.emplace_back(permissionName);
            permSet.insert(permissionName);
            continue;
        }
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission %{public}s invalid!", permissionName.c_str());
    }
    if ((scopeRes.tokenIDs.empty()) && (!scopeSrc.tokenIDs.empty())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Valid tokenid size is 0!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if ((scopeRes.permList.empty()) && (!scopeSrc.permList.empty())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Valid permission size is 0!");
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
    return CallbackManager::GetInstance().AddCallback(scope, callback);
}

int32_t PermissionManager::RemovePermStateChangeCallback(const sptr<IRemoteObject>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Called");
    return CallbackManager::GetInstance().RemoveCallback(callback);
}

bool PermissionManager::GetApiVersionByTokenId(AccessTokenID tokenID, int32_t& apiVersion)
{
    // only hap can do this
    AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&tokenID);
    ATokenTypeEnum tokenType = (ATokenTypeEnum)(idInner->type);
    if (tokenType != TOKEN_HAP) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Invalid token type %{public}d", tokenType);
        return false;
    }

    HapTokenInfo hapInfo;
    int ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, hapInfo);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Get hap token info error!");
        return false;
    }

    apiVersion = hapInfo.apiVersion;

    return true;
}

bool PermissionManager::IsPermissionVaild(const std::string& permissionName)
{
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "Invalid permissionName %{public}s", permissionName.c_str());
        return false;
    }

    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "Permission %{public}s has no definition ", permissionName.c_str());
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

    ACCESSTOKEN_LOG_INFO(LABEL,
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

void PermissionManager::NotifyUpdatedPermList(const std::vector<std::string>& grantedPermListBefore,
    const std::vector<std::string>& grantedPermListAfter, AccessTokenID tokenID)
{
    for (uint32_t i = 0; i < grantedPermListBefore.size(); i++) {
        ACCESSTOKEN_LOG_INFO(LABEL, "grantedPermListBefore[i] %{public}s.", grantedPermListBefore[i].c_str());
        auto it = find(grantedPermListAfter.begin(), grantedPermListAfter.end(), grantedPermListBefore[i]);
        if (it == grantedPermListAfter.end()) {
            CallbackManager::GetInstance().ExecuteCallbackAsync(
                tokenID, grantedPermListBefore[i], STATE_CHANGE_REVOKED);
            ParamUpdate(grantedPermListBefore[i], 0, true);
        }
    }
    for (uint32_t i = 0; i < grantedPermListAfter.size(); i++) {
        ACCESSTOKEN_LOG_INFO(LABEL, "grantedPermListAfter[i] %{public}s.", grantedPermListAfter[i].c_str());
        auto it = find(grantedPermListBefore.begin(), grantedPermListBefore.end(), grantedPermListAfter[i]);
        if (it == grantedPermListBefore.end()) {
            CallbackManager::GetInstance().ExecuteCallbackAsync(
                tokenID, grantedPermListAfter[i], STATE_CHANGE_GRANTED);
            ParamUpdate(grantedPermListAfter[i], 0, false);
        }
    }
}

bool PermissionManager::IsPermissionStateOrFlagMatched(const PermissionStatus& state1,
    const PermissionStatus& state2)
{
    return ((state1.grantStatus == state2.grantStatus) && (state1.grantFlag == state2.grantFlag));
}

void PermissionManager::GetStateOrFlagChangedList(std::vector<PermissionStatus>& stateListBefore,
    std::vector<PermissionStatus>& stateListAfter, std::vector<PermissionStatus>& stateChangeList)
{
    uint32_t size = stateListBefore.size();

    for (uint32_t i = 0; i < size; ++i) {
        PermissionStatus state1 = stateListBefore[i];
        PermissionStatus state2 = stateListAfter[i];

        if (!IsPermissionStateOrFlagMatched(state1, state2)) {
            stateChangeList.emplace_back(state2);
        }
    }
}

void PermissionManager::NotifyPermGrantStoreResult(bool result, uint64_t timestamp)
{
    grantEvent_.NotifyPermGrantStoreResult(result, timestamp);
}

void PermissionManager::AddNativePermToKernel(AccessTokenID tokenID,
    const std::vector<uint32_t>& opCodeList, const std::vector<bool>& statusList)
{
    int32_t ret = AddPermissionToKernel(tokenID, opCodeList, statusList);
    if (ret != ACCESS_TOKEN_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "AddPermissionToKernel(token=%{public}d), size=%{public}zu, err=%{public}d",
            tokenID, opCodeList.size(), ret);
    }
}

void PermissionManager::AddHapPermToKernel(AccessTokenID tokenID, const std::vector<std::string>& permList)
{
    std::vector<uint32_t> permCodeList;
    for (const auto &permission : permList) {
        uint32_t code;
        if (!TransferPermissionToOpcode(permission, code)) {
            continue;
        }
        permCodeList.emplace_back(code);
    }

    std::vector<uint32_t> opCodeList;
    std::vector<bool> statusList;
    HapTokenInfoInner::GetPermStatusListByTokenId(tokenID, permCodeList, opCodeList, statusList);
    int32_t ret = AddPermissionToKernel(tokenID, opCodeList, statusList);
    if (ret != ACCESS_TOKEN_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "AddPermissionToKernel(token=%{public}d), size=%{public}zu, err=%{public}d",
            tokenID, opCodeList.size(), ret);
    }
}

void PermissionManager::RemovePermFromKernel(AccessTokenID tokenID)
{
    int32_t ret = RemovePermissionFromKernel(tokenID);
    ACCESSTOKEN_LOG_INFO(LABEL,
        "RemovePermissionFromKernel(token=%{public}d), err=%{public}d", tokenID, ret);
}

void PermissionManager::SetPermToKernel(
    AccessTokenID tokenID, const std::string& permissionName, bool isGranted)
{
    uint32_t code;
    if (!TransferPermissionToOpcode(permissionName, code)) {
        return;
    }
    int32_t ret = SetPermissionToKernel(tokenID, code, isGranted);
    ACCESSTOKEN_LOG_INFO(LABEL,
        "SetPermissionToKernel(token=%{public}d, permission=(%{public}s), err=%{public}d",
        tokenID, permissionName.c_str(), ret);
}

bool IsAclSatisfied(const PermissionDef& permDef, const HapPolicy& policy)
{
    if (policy.apl < permDef.availableLevel) {
        if (!permDef.provisionEnable) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s provisionEnable is false.", permDef.permissionName.c_str());
            return false;
        }
        auto isAclExist = std::any_of(
            policy.aclRequestedList.begin(), policy.aclRequestedList.end(), [permDef](const auto &perm) {
            return permDef.permissionName == perm;
        });
        if (!isAclExist) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s need acl.", permDef.permissionName.c_str());
            return false;
        }
    }
    return true;
}

bool IsPermAvailableRangeSatisfied(const PermissionDef& permDef, const std::string& appDistributionType)
{
    if (permDef.availableType == ATokenAvailableTypeEnum::MDM) {
        if (appDistributionType == "none") {
            ACCESSTOKEN_LOG_INFO(LABEL, "Debug app use permission: %{public}s.",
                permDef.permissionName.c_str());
            return true;
        }
        if (appDistributionType != APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s is a mdm permission, the hap is not a mdm application.",
                permDef.permissionName.c_str());
            return false;
        }
    }
    return true;
}

bool IsUserGrantPermPreAuthorized(const std::vector<PreAuthorizationInfo> &list,
    const std::string &permissionName, bool &userCancelable)
{
    auto iter = std::find_if(list.begin(), list.end(), [&permissionName](const auto &info) {
            return info.permissionName == permissionName;
        });
    if (iter == list.end()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Permission(%{public}s) is not in the list", permissionName.c_str());
        return false;
    }

    userCancelable = iter->userCancelable;
    return true;
}

bool PermissionManager::InitDlpPermissionList(const std::string& bundleName, int32_t userId,
    std::vector<PermissionStatus>& initializedList)
{
    // get dlp original app
    AccessTokenIDEx tokenId = AccessTokenInfoManager::GetInstance().GetHapTokenID(userId, bundleName, 0);
    std::shared_ptr<HapTokenInfoInner> infoPtr =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId.tokenIdExStruct.tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Token %{public}u is invalid.", tokenId.tokenIdExStruct.tokenID);
        return false;
    }
    (void)infoPtr->GetPermissionStateList(initializedList);
    return true;
}

bool PermissionManager::InitPermissionList(const std::string& appDistributionType, const HapPolicy& policy,
    std::vector<PermissionStatus>& initializedList, HapInfoCheckResult& result)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Before, request perm list size: %{public}zu, preAuthorizationInfo size %{public}zu, "
        "ACLRequestedList size %{public}zu.",
        policy.permStateList.size(), policy.preAuthorizationInfo.size(), policy.aclRequestedList.size());

    for (auto state : policy.permStateList) {
        PermissionDef permDef;
        int32_t ret = PermissionManager::GetInstance().GetDefPermission(
            state.permissionName, permDef);
        if (ret != AccessToken::AccessTokenKitRet::RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Get definition of %{public}s failed, ret = %{public}d.",
                state.permissionName.c_str(), ret);
            continue;
        }
        if (!IsAclSatisfied(permDef, policy)) {
            result.permCheckResult.permissionName = state.permissionName;
            result.permCheckResult.rule = PERMISSION_ACL_RULE;
            ACCESSTOKEN_LOG_ERROR(LABEL, "Acl of %{public}s is invalid.", permDef.permissionName.c_str());
            return false;
        }

        // edm check
        if (!IsPermAvailableRangeSatisfied(permDef, appDistributionType)) {
            result.permCheckResult.permissionName = state.permissionName;
            result.permCheckResult.rule = PERMISSION_EDM_RULE;
            ACCESSTOKEN_LOG_ERROR(LABEL, "Available range of %{public}s is invalid.", permDef.permissionName.c_str());
            return false;
        }
        state.grantFlag = PERMISSION_DEFAULT_FLAG;
        state.grantStatus = PERMISSION_DENIED;

        if (permDef.grantMode == AccessToken::GrantMode::SYSTEM_GRANT) {
            state.grantFlag = PERMISSION_SYSTEM_FIXED;
            state.grantStatus = PERMISSION_GRANTED;
            initializedList.emplace_back(state);
            continue;
        }
        if (policy.preAuthorizationInfo.size() == 0) {
            initializedList.emplace_back(state);
            continue;
        }
        bool userCancelable = true;
        if (IsUserGrantPermPreAuthorized(policy.preAuthorizationInfo, state.permissionName, userCancelable)) {
            state.grantFlag = userCancelable ? PERMISSION_GRANTED_BY_POLICY : PERMISSION_SYSTEM_FIXED;
            state.grantStatus = PERMISSION_GRANTED;
        }
        initializedList.emplace_back(state);
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "After, request perm list size: %{public}zu.", initializedList.size());
    return true;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
