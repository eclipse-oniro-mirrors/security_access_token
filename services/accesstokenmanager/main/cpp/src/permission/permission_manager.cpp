/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "access_token_error.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "app_manager_access_client.h"
#include "callback_manager.h"
#ifdef SUPPORT_SANDBOX_APP
#include "dlp_permission_set_manager.h"
#endif
#include "ipc_skeleton.h"
#include "parameter.h"
#include "permission_definition_cache.h"
#include "permission_validator.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_modify_notifier.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "PermissionManager"};
static const char* PERMISSION_STATUS_CHANGE_KEY = "accesstoken.permission.change";
static constexpr int32_t VALUE_MAX_LEN = 32;
static constexpr int32_t ROOT_UID = 0;
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
    "ohos.permission.WRITE_CALL_LOG"
};
const uint32_t ELEMENT_NOT_FOUND = -1;
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "return default value, ret=%{public}d", ret);
        paramValue_ = 0;
        return;
    }
    paramValue_ = static_cast<uint64_t>(std::atoll(value));
}

PermissionManager::~PermissionManager()
{}

void PermissionManager::ClearAllSecCompGrantedPerm(const std::vector<AccessTokenID>& tokenIdList)
{
    for (const auto& tokenId : tokenIdList) {
        std::shared_ptr<HapTokenInfoInner> tokenInfoPtr =
            AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        if (tokenInfoPtr == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId is invalid, tokenId=%{public}u", tokenId);
            continue;
        }
        std::shared_ptr<PermissionPolicySet> permPolicySet = tokenInfoPtr->GetHapInfoPermissionPolicySet();
        if (permPolicySet != nullptr) {
            permPolicySet->ClearSecCompGrantedPerm();
        }
    }
}

void PermissionManager::AddDefPermissions(const std::vector<PermissionDef>& permList, AccessTokenID tokenId,
    bool updateFlag)
{
    std::vector<PermissionDef> permFilterList;
    PermissionValidator::FilterInvalidPermissionDef(permList, permFilterList);

    for (const auto& perm : permFilterList) {
        if (updateFlag) {
            PermissionDefinitionCache::GetInstance().Update(perm, tokenId);
            continue;
        }

        if (!PermissionDefinitionCache::GetInstance().HasDefinition(perm.permissionName)) {
            PermissionDefinitionCache::GetInstance().Insert(perm, tokenId);
        } else {
            ACCESSTOKEN_LOG_INFO(LABEL, "permission %{public}s has define",
                TransferPermissionDefToString(perm).c_str());
        }
    }
}

void PermissionManager::RemoveDefPermissions(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: %{public}u", __func__, tokenID);
    std::shared_ptr<HapTokenInfoInner> tokenInfo =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (tokenInfo == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params(tokenID: %{public}u)!", tokenID);
        return;
    }
    std::string bundleName = tokenInfo->GetBundleName();
    PermissionDefinitionCache::GetInstance().DeleteByBundleName(bundleName);
}

int PermissionManager::VerifyHapAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    std::shared_ptr<HapTokenInfoInner> tokenInfoPtr =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (tokenInfoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "can not find tokenInfo!");
        return PERMISSION_DENIED;
    }
    std::shared_ptr<PermissionPolicySet> permPolicySet = tokenInfoPtr->GetHapInfoPermissionPolicySet();
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return PERMISSION_DENIED;
    }

    return permPolicySet->VerifyPermissionStatus(permissionName);
}

int PermissionManager::VerifyNativeAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    std::shared_ptr<NativeTokenInfoInner> tokenInfoPtr =
        AccessTokenInfoManager::GetInstance().GetNativeTokenInfoInner(tokenID);
    if (tokenInfoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "can not find tokenInfo!");
        return PERMISSION_DENIED;
    }

    NativeTokenInfo info;
    tokenInfoPtr->TranslateToNativeTokenInfo(info);
    if (!tokenInfoPtr->IsRemote() && !PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        if (PermissionDefinitionCache::GetInstance().IsHapPermissionDefEmpty()) {
            ACCESSTOKEN_LOG_INFO(LABEL, "permission definition set has not been installed!");
            if (AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenID) == TOKEN_NATIVE) {
                return PERMISSION_GRANTED;
            }
            return PERMISSION_DENIED;
        }
        ACCESSTOKEN_LOG_ERROR(LABEL, "no definition for permission: %{public}s!", permissionName.c_str());
        return PERMISSION_DENIED;
    }
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetNativePermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return PERMISSION_DENIED;
    }

    return permPolicySet->VerifyPermissionStatus(permissionName);
}

int PermissionManager::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    if (tokenID == INVALID_TOKENID) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", VERIFY_TOKEN_ID_ERROR, "CALLER_TOKENID",
            static_cast<AccessTokenID>(IPCSkeleton::GetCallingTokenID()), "PERMISSION_NAME", permissionName);
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID is invalid");
        return PERMISSION_DENIED;
    }

    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return PERMISSION_DENIED;
    }

    ATokenTypeEnum tokenType = AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenID);
    if ((tokenType == TOKEN_NATIVE) || (tokenType == TOKEN_SHELL)) {
        return VerifyNativeAccessToken(tokenID, permissionName);
    }
    if (tokenType == TOKEN_HAP) {
        return VerifyHapAccessToken(tokenID, permissionName);
    }
    ACCESSTOKEN_LOG_ERROR(LABEL, "invalid tokenType!");
    return PERMISSION_DENIED;
}

int PermissionManager::GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult)
{
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    // all permissions can be obtained.
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "no definition for permission: %{public}s!", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    return PermissionDefinitionCache::GetInstance().FindByPermissionName(permissionName, permissionDefResult);
}

int PermissionManager::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList)
{
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    permPolicySet->GetDefPermissions(permList);
    return RET_SUCCESS;
}

int PermissionManager::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called, tokenID: %{public}u, isSystemGrant: %{public}d",
        __func__, tokenID, isSystemGrant);
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    GrantMode mode = isSystemGrant ? SYSTEM_GRANT : USER_GRANT;
    std::vector<PermissionStateFull> tmpList;
    permPolicySet->GetPermissionStateFulls(tmpList);
    for (const auto& perm : tmpList) {
        PermissionDef permDef;
        GetDefPermission(perm.permissionName, permDef);
        if (permDef.grantMode == mode) {
            reqPermList.emplace_back(perm);
        }
    }
    return RET_SUCCESS;
}

static bool IsPermissionRequestedInHap(const std::vector<PermissionStateFull>& permsList,
    const std::string &permission, int32_t& status, uint32_t& flag)
{
    if (!PermissionDefinitionCache::GetInstance().HasHapPermissionDefinitionForHap(permission)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "no definition for hap permission: %{public}s!", permission.c_str());
        return false;
    }
    auto iter = std::find_if(permsList.begin(), permsList.end(), [permission](const PermissionStateFull& perm) {
        return permission == perm.permissionName;
    });
    if (iter == permsList.end()) {
        ACCESSTOKEN_LOG_WARN(LABEL, "can not find permission: %{public}s define!", permission.c_str());
        return false;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "find goal permission: %{public}s, status: %{public}d, flag: %{public}d",
        permission.c_str(), iter->grantStatus[0], iter->grantFlags[0]);
    status = iter->grantStatus[0];
    flag = static_cast<uint32_t>(iter->grantFlags[0]);
    return true;
}

static bool IsPermissionRestrictedByRules(const std::string& permission)
{
    // Several permission is not available to common apps.
    // Specified apps can get the permission by pre-authorization instead of Pop-ups.
    auto iterator = std::find(g_notDisplayedPerms.begin(), g_notDisplayedPerms.end(), permission);
    if (iterator != g_notDisplayedPerms.end()) {
        ACCESSTOKEN_LOG_WARN(LABEL, "permission is not available to common apps: %{public}s!", permission.c_str());
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

void PermissionManager::GetSelfPermissionState(const std::vector<PermissionStateFull>& permsList,
    PermissionListState& permState, int32_t apiVersion)
{
    int32_t goalGrantStatus;
    uint32_t goalGrantFlag;

    // api8 require vague location permission refuse directly because there is no vague location permission in api8
    if ((permState.permissionName == VAGUE_LOCATION_PERMISSION_NAME) && (apiVersion < ACCURATE_LOCATION_API_VERSION)) {
        permState.state = INVALID_OPER;
        return;
    }
    if (!IsPermissionRequestedInHap(permsList, permState.permissionName, goalGrantStatus, goalGrantFlag)) {
        permState.state = INVALID_OPER;
        return;
    }
    if (IsPermissionRestrictedByRules(permState.permissionName)) {
        permState.state = INVALID_OPER;
        return;
    }
    if (goalGrantStatus == PERMISSION_DENIED) {
        if ((goalGrantFlag & PERMISSION_POLICY_FIXED) != 0) {
            permState.state = SETTING_OPER;
            return;
        }

        if ((goalGrantFlag == PERMISSION_DEFAULT_FLAG) || ((goalGrantFlag & PERMISSION_USER_SET) != 0) ||
            ((goalGrantFlag & PERMISSION_COMPONENT_SET) != 0) || ((goalGrantFlag & PERMISSION_ALLOW_THIS_TIME) != 0)) {
            permState.state = DYNAMIC_OPER;
            return;
        }
        if ((goalGrantFlag & PERMISSION_USER_FIXED) != 0) {
            permState.state = SETTING_OPER;
            return;
        }
    }
    permState.state = PASS_OPER;
    return;
}

int PermissionManager::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: %{public}u, permissionName: %{public}s",
        __func__, tokenID, permissionName.c_str());
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "no definition for permission: %{public}s!", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    int32_t fullFlag;
    int32_t ret = permPolicySet->QueryPermissionFlag(permissionName, fullFlag);
    if (ret == RET_SUCCESS) {
        flag = permPolicySet->GetFlagWithoutSpecifiedElement(fullFlag, PERMISSION_GRANTED_BY_POLICY);
    }
    return ret;
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
    ACCESSTOKEN_LOG_INFO(LABEL, "isUpdated");
    int32_t changeType = isGranted ? GRANTED : REVOKED;

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
    AccessTokenID tokenID, const std::string& permissionName, bool isGranted, uint32_t flag)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    if (infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remote token can not update");
        return AccessTokenError::ERR_IDENTITY_CHECK_FAILED;
    }
    if (flag == PERMISSION_ALLOW_THIS_TIME) {
        if (isGranted) {
            if (!IsAllowGrantTempPermission(tokenID, permissionName)) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "grant permission failed, tokenID:%{public}d, permissionName:%{public}s",
                    tokenID, permissionName.c_str());
                return ERR_IDENTITY_CHECK_FAILED;
            }
        }
    }
    std::shared_ptr<PermissionPolicySet> permPolicySet = infoPtr->GetHapInfoPermissionPolicySet();
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
#ifdef SUPPORT_SANDBOX_APP
    int32_t hapDlpType = infoPtr->GetDlpType();
    if (hapDlpType != DLP_COMMON) {
        int32_t permDlpMode = DlpPermissionSetManager::GetInstance().GetPermDlpMode(permissionName);
        if (!DlpPermissionSetManager::GetInstance().IsPermDlpModeAvailableToDlpHap(hapDlpType, permDlpMode)) {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}u is not allowed to be granted permissionName %{public}s",
                tokenID, permissionName.c_str());
            return AccessTokenError::ERR_IDENTITY_CHECK_FAILED;
        }
    }
#endif
    int32_t statusBefore = permPolicySet->VerifyPermissionStatus(permissionName);
    int32_t ret = permPolicySet->UpdatePermissionStatus(permissionName, isGranted, flag);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    int32_t statusAfter = permPolicySet->VerifyPermissionStatus(permissionName);
    if (statusAfter != statusBefore) {
        NotifyWhenPermissionStateUpdated(tokenID, permissionName, isGranted, flag, infoPtr);
    }

#ifdef TOKEN_SYNC_ENABLE
    TokenModifyNotifier::GetInstance().NotifyTokenModify(tokenID);
#endif
    return RET_SUCCESS;
}

bool PermissionManager::IsAllowGrantTempPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    HapTokenInfo tokenInfo;
    if (AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, tokenInfo) != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid tokenId(%{public}d)", tokenID);
        return false;
    }
    bool isForeground = false;
    std::vector<AppStateData> foreGroundAppList;
    AppManagerAccessClient::GetInstance().GetForegroundApplications(foreGroundAppList);

    if (std::any_of(foreGroundAppList.begin(), foreGroundAppList.end(),
        [=](const auto& foreGroundApp) { return foreGroundApp.bundleName == tokenInfo.bundleName; })) {
        isForeground = true;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "get app state permissionName:%{public}s, isForeground:%{public}d",
        permissionName.c_str(), isForeground);
    bool userEnable = true;
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    int callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid == ROOT_UID) {
        userEnable = false;
    }
#endif
    if ((!userEnable) || (isForeground)) {
        TempPermissionObserver::GetInstance().AddTempPermTokenToList(tokenID, permissionName);
        return true;
    }
    return false;
}

int32_t PermissionManager::CheckAndUpdatePermission(AccessTokenID tokenID, const std::string& permissionName,
    bool isGranted, uint32_t flag)
{
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "no definition for permission: %{public}s!", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    if (!PermissionValidator::IsPermissionFlagValid(flag)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    int32_t ret = UpdateTokenPermissionState(tokenID, permissionName, isGranted, flag);
    if (ret != RET_SUCCESS) {
        return ret;
    }

#ifdef SUPPORT_SANDBOX_APP
    // The action of sharing would be taken place only if the grant operation or revoke operation equals to success.
    std::vector<AccessTokenID> tokenIdList;
    AccessTokenInfoManager::GetInstance().GetRelatedSandBoxHapList(tokenID, tokenIdList);
    for (const auto& id : tokenIdList) {
        (void)UpdateTokenPermissionState(id, permissionName, isGranted, flag);
    }
#endif
    return RET_SUCCESS;
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

void PermissionManager::ScopeToString(
    const std::vector<AccessTokenID>& tokenIDs, const std::vector<std::string>& permList)
{
    std::stringstream str;
    copy(tokenIDs.begin(), tokenIDs.end(), std::ostream_iterator<uint32_t>(str, ", "));
    std::string tokenidStr = str.str();

    std::string permStr;
    permStr = accumulate(permList.begin(), permList.end(), std::string(" "));

    ACCESSTOKEN_LOG_INFO(LABEL, "tokenidStr = %{public}s permStr =%{public}s",
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenId %{public}d invalid!", tokenId);
    }
    std::set<std::string> permSet;
    for (const auto& permissionName : scopeSrc.permList) {
        if (PermissionDefinitionCache::GetInstance().HasDefinition(permissionName) &&
            permSet.count(permissionName) == 0) {
            scopeRes.permList.emplace_back(permissionName);
            permSet.insert(permissionName);
            continue;
        }
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission %{public}s invalid!", permissionName.c_str());
    }
    if ((scopeRes.tokenIDs.empty()) && (!scopeSrc.tokenIDs.empty())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "valid tokenid size is 0!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if ((scopeRes.permList.empty()) && (!scopeSrc.permList.empty())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "valid permission size is 0!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    ScopeToString(scopeRes.tokenIDs, scopeRes.permList);
    return RET_SUCCESS;
}

int32_t PermissionManager::AddPermStateChangeCallback(
    const PermStateChangeScope& scope, const sptr<IRemoteObject>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called");
    PermStateChangeScope scopeRes;
    int32_t result = ScopeFilter(scope, scopeRes);
    if (result != RET_SUCCESS) {
        return result;
    }
    return CallbackManager::GetInstance().AddCallback(scope, callback);
}

int32_t PermissionManager::RemovePermStateChangeCallback(const sptr<IRemoteObject>& callback)
{
    return CallbackManager::GetInstance().RemoveCallback(callback);
}

bool PermissionManager::GetApiVersionByTokenId(AccessTokenID tokenID, int32_t& apiVersion)
{
    // only hap can do this
    AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&tokenID);
    ATokenTypeEnum tokenType = (ATokenTypeEnum)(idInner->type);
    if (tokenType != TOKEN_HAP) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid token type %{public}d", tokenType);
        return false;
    }

    HapTokenInfo hapInfo;
    int ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, hapInfo);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get hap token info error!");
        return false;
    }

    apiVersion = hapInfo.apiVersion;

    return true;
}

bool PermissionManager::IsPermissionVaild(const std::string& permissionName)
{
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "invalid permissionName %{public}s", permissionName.c_str());
        return false;
    }

    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "permission %{public}s has no definition ", permissionName.c_str());
        return false;
    }
    return true;
}

bool PermissionManager::GetLocationPermissionIndex(std::vector<PermissionListStateParcel>& reqPermList,
    uint32_t& vagueIndex, uint32_t& accurateIndex, uint32_t& backIndex)
{
    int index = 0;
    bool hasFound = false;

    for (const auto& perm : reqPermList) {
        if (perm.permsState.permissionName == VAGUE_LOCATION_PERMISSION_NAME) {
            vagueIndex = index;
            hasFound = true;
        } else if (perm.permsState.permissionName == ACCURATE_LOCATION_PERMISSION_NAME) {
            accurateIndex = index;
            hasFound = true;
        } else if (perm.permsState.permissionName == BACKGROUND_LOCATION_PERMISSION_NAME) {
            backIndex = index;
            hasFound = true;
        }

        index++;

        if ((vagueIndex != ELEMENT_NOT_FOUND) &&
            (accurateIndex != ELEMENT_NOT_FOUND) &&
            (backIndex != ELEMENT_NOT_FOUND)) {
            break;
        }
    }

    ACCESSTOKEN_LOG_INFO(LABEL,
        "vague index is %{public}d, accurate index is %{public}d, background index is %{public}d!",
        vagueIndex, accurateIndex, backIndex);

    return hasFound;
}

bool PermissionManager::GetResByVaguePermission(std::vector<PermissionListStateParcel>& reqPermList,
    std::vector<PermissionStateFull>& permsList, int32_t apiVersion, bool hasVaguePermission, uint32_t index)
{
    if (index == ELEMENT_NOT_FOUND) {
        return false;
    }

    if (hasVaguePermission) {
        // get the state to return if the calling hap has vague location permission
        GetSelfPermissionState(permsList, reqPermList[index].permsState, apiVersion);
        return (static_cast<PermissionOper>(reqPermList[index].permsState.state) == DYNAMIC_OPER);
    } else {
        // refuse directly with invalid oper
        reqPermList[index].permsState.state = INVALID_OPER;
        ACCESSTOKEN_LOG_WARN(LABEL,
            "operate invaild, accurate or background location permission base on vague location permission");
        return false;
    }
}

// return: whether location permission need pop-up window or not
bool PermissionManager::LocationHandleWithoutVague(std::vector<PermissionListStateParcel>& reqPermList,
    std::vector<PermissionStateFull>& permsList, int32_t apiVersion, uint32_t accurateIndex, uint32_t backIndex)
{
    AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    // token type has ensured to be a hap when get the apiVersion
    bool hasPermission = PERMISSION_GRANTED == VerifyHapAccessToken(callingTokenID, VAGUE_LOCATION_PERMISSION_NAME);
    bool accurateRes = GetResByVaguePermission(reqPermList, permsList, apiVersion, hasPermission, accurateIndex);
    bool backRes = GetResByVaguePermission(reqPermList, permsList, apiVersion, hasPermission, backIndex);

    if (accurateIndex != ELEMENT_NOT_FOUND) {
        ACCESSTOKEN_LOG_INFO(LABEL, "accurate state is %{public}d.", reqPermList[accurateIndex].permsState.state);
    }
    if (backIndex != ELEMENT_NOT_FOUND) {
        ACCESSTOKEN_LOG_INFO(LABEL, "background state is %{public}d.", reqPermList[backIndex].permsState.state);
    }

    return (accurateRes || backRes);
}

bool PermissionManager::GetPermissionStatusAndFlag(const std::string& permissionName,
    const std::vector<PermissionStateFull>& permsList, int32_t& status, uint32_t& flag)
{
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "invalid permissionName %{public}s", permissionName.c_str());
        return false;
    }
    if (!PermissionDefinitionCache::GetInstance().HasHapPermissionDefinitionForHap(permissionName)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "permission %{public}s has no hap definition ", permissionName.c_str());
        return false;
    }
    auto iter = std::find_if(permsList.begin(), permsList.end(), [permissionName](const PermissionStateFull& perm) {
        return permissionName == perm.permissionName;
    });
    if (iter != permsList.end()) {
        status = iter->grantStatus[0];
        flag = static_cast<uint32_t>(iter->grantFlags[0]);

        ACCESSTOKEN_LOG_DEBUG(LABEL, "permission:%{public}s, status:%{public}d, flag:%{public}d!",
            permissionName.c_str(), status, flag);
        return true;
    }

    return false;
}

void PermissionManager::GetStateByStatusAndFlag(int32_t status, uint32_t flag, uint32_t index, int32_t& state)
{
    if (index == ELEMENT_NOT_FOUND) {
        return;
    }

    if (status == PERMISSION_DENIED) {
        // status -1 means permission has been refused or not set
        if ((flag == PERMISSION_DEFAULT_FLAG) || ((flag & PERMISSION_USER_SET) != 0) ||
            ((flag & PERMISSION_ALLOW_THIS_TIME) != 0)) {
            // flag 0 or 1 means permission has not been operated or valid only once
            state = DYNAMIC_OPER;
        } else if ((flag & PERMISSION_USER_FIXED) != 0) {
            // flag 2 means vague location has been operated, only can be changed by settings
            state = SETTING_OPER;
        }
    } else if (status == PERMISSION_GRANTED) {
        // status 0 means permission has been granted
        state = PASS_OPER;
    }
}

void PermissionManager::SetLocationPermissionState(std::vector<PermissionListStateParcel>& reqPermList, uint32_t index,
    int32_t state)
{
    if (index == ELEMENT_NOT_FOUND) {
        return;
    }

    reqPermList[index].permsState.state = state;
}

// return: whether location permission need pop-up window or not
bool PermissionManager::LocationHandleWithVague(std::vector<PermissionListStateParcel>& reqPermList,
    std::vector<PermissionStateFull>& permsList, uint32_t vagueIndex, uint32_t accurateIndex, uint32_t backIndex)
{
    int32_t vagueStatus = PERMISSION_DENIED;
    uint32_t vagueFlag = PERMISSION_DEFAULT_FLAG;
    int32_t vagueState = INVALID_OPER;
    int32_t accurateStatus = PERMISSION_DENIED;
    uint32_t accurateFlag = PERMISSION_DEFAULT_FLAG;
    int32_t accurateState = INVALID_OPER;
    int32_t backStatus = PERMISSION_DENIED;
    uint32_t backFlag = PERMISSION_DEFAULT_FLAG;
    int32_t backState = INVALID_OPER;

    bool vagueRes = GetPermissionStatusAndFlag(VAGUE_LOCATION_PERMISSION_NAME, permsList, vagueStatus, vagueFlag);
    bool accurateRes = GetPermissionStatusAndFlag(ACCURATE_LOCATION_PERMISSION_NAME, permsList, accurateStatus,
        accurateFlag);
    bool backRes = GetPermissionStatusAndFlag(BACKGROUND_LOCATION_PERMISSION_NAME, permsList, backStatus, backFlag);
    // need vague && (accurate || back)
    if (!vagueRes || (!accurateRes && !backRes)) {
        return false;
    }

    // vague location status -1 means vague location permission has been refused or not set
    if (vagueStatus == PERMISSION_DENIED) {
        if ((vagueFlag == PERMISSION_DEFAULT_FLAG) || ((vagueFlag & PERMISSION_USER_SET) != 0) ||
            ((vagueFlag & PERMISSION_ALLOW_THIS_TIME) != 0)) {
            // vague location flag 0 or 1 means permission has not been operated or valid only once
            vagueState = DYNAMIC_OPER;
            accurateState = accurateIndex != ELEMENT_NOT_FOUND ? DYNAMIC_OPER : INVALID_OPER;
            backState = backIndex != ELEMENT_NOT_FOUND ? DYNAMIC_OPER : INVALID_OPER;
        } else if ((vagueFlag & PERMISSION_USER_FIXED) != 0) {
            // vague location flag 2 means vague location has been operated, only can be changed by settings
            // so that accurate or background location is no need to operate
            vagueState = SETTING_OPER;
            accurateState = accurateIndex != ELEMENT_NOT_FOUND ? SETTING_OPER : INVALID_OPER;
            backState = backIndex != ELEMENT_NOT_FOUND ? SETTING_OPER : INVALID_OPER;
        }
    } else if (vagueStatus == PERMISSION_GRANTED) {
        // vague location status 0 means vague location permission has been granted
        // now flag 1 is not in use so return PASS_OPER, otherwise should judge by flag
        vagueState = PASS_OPER;
        GetStateByStatusAndFlag(accurateStatus, accurateFlag, accurateIndex, accurateState);
        GetStateByStatusAndFlag(backStatus, backFlag, backIndex, backState);
    }

    ACCESSTOKEN_LOG_INFO(LABEL,
        "vague state is %{public}d, accurate state is %{public}d, background state is %{public}d",
        vagueState, accurateState, backState);

    SetLocationPermissionState(reqPermList, vagueIndex, vagueState);
    SetLocationPermissionState(reqPermList, accurateIndex, accurateState);
    SetLocationPermissionState(reqPermList, backIndex, backState);

    return ((static_cast<PermissionOper>(vagueState) == DYNAMIC_OPER) ||
            (static_cast<PermissionOper>(accurateState) == DYNAMIC_OPER) ||
            (static_cast<PermissionOper>(backState) == DYNAMIC_OPER));
}

bool PermissionManager::LocationPermissionSpecialHandle(std::vector<PermissionListStateParcel>& reqPermList,
    std::vector<PermissionStateFull>& permsList, int32_t apiVersion)
{
    bool needRes = false;
    uint32_t vagueIndex = ELEMENT_NOT_FOUND;
    uint32_t accurateIndex = ELEMENT_NOT_FOUND;
    uint32_t backIndex = ELEMENT_NOT_FOUND;

    if (!GetLocationPermissionIndex(reqPermList, vagueIndex, accurateIndex, backIndex)) {
        return false;
    }

    if (vagueIndex == ELEMENT_NOT_FOUND) {
        // permission handle without vague location
        needRes = LocationHandleWithoutVague(reqPermList, permsList, apiVersion, accurateIndex, backIndex);
    } else {
        if ((accurateIndex == ELEMENT_NOT_FOUND) && (backIndex == ELEMENT_NOT_FOUND)) {
            // only vague location permission
            GetSelfPermissionState(permsList, reqPermList[vagueIndex].permsState, apiVersion);
            needRes = (static_cast<PermissionOper>(reqPermList[vagueIndex].permsState.state) == DYNAMIC_OPER);
        } else {
            // with foreground or background permission
            needRes = LocationHandleWithVague(reqPermList, permsList, vagueIndex, accurateIndex, backIndex);
        }
    }

    return needRes;
}

void PermissionManager::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    if (ClearUserGrantedPermission(tokenID) != RET_SUCCESS) {
        return;
    }
    std::vector<AccessTokenID> tokenIdList;
    AccessTokenInfoManager::GetInstance().GetRelatedSandBoxHapList(tokenID, tokenIdList);
    for (const auto& id : tokenIdList) {
        (void)ClearUserGrantedPermission(id);
    }
}

void PermissionManager::NotifyUpdatedPermList(const std::vector<std::string>& grantedPermListBefore,
    const std::vector<std::string>& grantedPermListAfter, AccessTokenID tokenID)
{
    for (uint32_t i = 0; i < grantedPermListBefore.size(); i++) {
        auto it = find(grantedPermListAfter.begin(), grantedPermListAfter.end(), grantedPermListBefore[i]);
        if (it == grantedPermListAfter.end()) {
            CallbackManager::GetInstance().ExecuteCallbackAsync(tokenID, grantedPermListBefore[i], REVOKED);
            ParamUpdate(grantedPermListBefore[i], 0, true);
        }
    }
    for (uint32_t i = 0; i < grantedPermListAfter.size(); i++) {
        auto it = find(grantedPermListBefore.begin(), grantedPermListBefore.end(), grantedPermListAfter[i]);
        if (it == grantedPermListBefore.end()) {
            CallbackManager::GetInstance().ExecuteCallbackAsync(tokenID, grantedPermListAfter[i], GRANTED);
            ParamUpdate(grantedPermListAfter[i], 0, false);
        }
    }
}

int32_t PermissionManager::ClearUserGrantedPermission(AccessTokenID tokenID)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "token %{public}u is invalid.", tokenID);
        return ERR_PARAM_INVALID;
    }
    if (infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "it is a remote hap token %{public}u!", tokenID);
        return ERR_IDENTITY_CHECK_FAILED;
    }
    std::shared_ptr<PermissionPolicySet> permPolicySet = infoPtr->GetHapInfoPermissionPolicySet();
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return ERR_PARAM_INVALID;
    }
    std::vector<std::string> grantedPermListBefore;
    permPolicySet->GetGrantedPermissionList(grantedPermListBefore);

    // reset permission.
    permPolicySet->ResetUserGrantPermissionStatus();
    // clear security component granted permission which is not requested in module.json.
    permPolicySet->ClearSecCompGrantedPerm();

#ifdef SUPPORT_SANDBOX_APP
    // update permission status with dlp permission rule.
    std::vector<PermissionStateFull> permListOfHap;
    permPolicySet->GetPermissionStateFulls(permListOfHap);
    DlpPermissionSetManager::GetInstance().UpdatePermStateWithDlpInfo(
        infoPtr->GetDlpType(), permListOfHap);
    permPolicySet->Update(permListOfHap);
#endif

    std::vector<std::string> grantedPermListAfter;
    permPolicySet->GetGrantedPermissionList(grantedPermListAfter);

    NotifyUpdatedPermList(grantedPermListBefore, grantedPermListAfter, tokenID);
    return RET_SUCCESS;
}

void PermissionManager::NotifyPermGrantStoreResult(bool result, uint64_t timestamp)
{
    grantEvent_.NotifyPermGrantStoreResult(result, timestamp);
}

std::string PermissionManager::TransferPermissionDefToString(const PermissionDef& inPermissionDef)
{
    std::string infos;
    infos.append(R"({"permissionName": ")" + inPermissionDef.permissionName + R"(")");
    infos.append(R"(, "bundleName": ")" + inPermissionDef.bundleName + R"(")");
    infos.append(R"(, "grantMode": )" + std::to_string(inPermissionDef.grantMode));
    infos.append(R"(, "availableLevel": )" + std::to_string(inPermissionDef.availableLevel));
    infos.append(R"(, "provisionEnable": )" + std::to_string(inPermissionDef.provisionEnable));
    infos.append(R"(, "distributedSceneEnable": )" + std::to_string(inPermissionDef.distributedSceneEnable));
    infos.append(R"(, "label": ")" + inPermissionDef.label + R"(")");
    infos.append(R"(, "labelId": )" + std::to_string(inPermissionDef.labelId));
    infos.append(R"(, "description": ")" + inPermissionDef.description + R"(")");
    infos.append(R"(, "descriptionId": )" + std::to_string(inPermissionDef.descriptionId));
    infos.append(R"(, "availableType": )" + std::to_string(inPermissionDef.availableType));
    infos.append("}");
    return infos;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
