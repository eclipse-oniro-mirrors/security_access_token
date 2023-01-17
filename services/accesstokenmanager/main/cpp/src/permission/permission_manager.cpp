/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
{
}

void PermissionManager::AddDefPermissions(const std::vector<PermissionDef>& permList, AccessTokenID tokenId,
    bool updateFlag)
{
    std::vector<PermissionDef> permFilterList;
    PermissionValidator::FilterInvalidPermissionDef(permList, permFilterList);

    for (const auto& perm : permFilterList) {
        if (updateFlag) {
            PermissionDefinitionCache::GetInstance().Update(perm);
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

    return permPolicySet->VerifyPermissStatus(permissionName);
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
    if (PermissionDefinitionCache::GetInstance().IsPermissionDefEmpty()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "permission definition set has not been installed!");
        if (info.apl >= APL_SYSTEM_BASIC) {
            return PERMISSION_GRANTED;
        }
        ACCESSTOKEN_LOG_INFO(LABEL, "native process apl is %{public}d!", info.apl);
        return PERMISSION_DENIED;
    }
    if (!tokenInfoPtr->IsRemote() && !PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "no definition for permission: %{public}s!", permissionName.c_str());
        return PERMISSION_DENIED;
    }
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetNativePermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return PERMISSION_DENIED;
    }

    return permPolicySet->VerifyPermissStatus(permissionName);
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
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "no definition for permission: %{public}s!", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIT;
    }
    return PermissionDefinitionCache::GetInstance().FindByPermissionName(permissionName, permissionDefResult);
}

int PermissionManager::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList)
{
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return RET_FAILED;
    }

    permPolicySet->GetDefPermissions(permList);
    return RET_SUCCESS;
}

int PermissionManager::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: %{public}u, isSystemGrant: %{public}d",
        __func__, tokenID, isSystemGrant);
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return RET_FAILED;
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

void PermissionManager::GetSelfPermissionState(std::vector<PermissionStateFull> permsList,
    PermissionListState &permState, int32_t apiVersion)
{
    bool foundGoal = false;
    int32_t goalGrantStatus;
    uint32_t goalGrantFlags;

    // api8 require vague location permission refuse directlty beause there is no vague location permission in api8
    if ((permState.permissionName == VAGUE_LOCATION_PERMISSION_NAME) &&
       (apiVersion < ACCURATE_LOCATION_API_VERSION)) {
        permState.state = INVALID_OPER;
        return;
    }

    auto iter = std::find_if(permsList.begin(), permsList.end(), [permState](const PermissionStateFull& perm) {
        return permState.permissionName == perm.permissionName;
    });
    if (iter != permsList.end()) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "find goal permission: %{public}s, status: %{public}d, flag: %{public}d",
            permState.permissionName.c_str(), iter->grantStatus[0], iter->grantFlags[0]);
        foundGoal = true;
        goalGrantStatus = iter->grantStatus[0];
        goalGrantFlags = static_cast<uint32_t>(iter->grantFlags[0]);
    }

    if (foundGoal == false) {
        ACCESSTOKEN_LOG_WARN(LABEL,
            "can not find permission: %{public}s define!", permState.permissionName.c_str());
        permState.state = INVALID_OPER;
        return;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permState.permissionName)) {
        ACCESSTOKEN_LOG_WARN(LABEL,
            "no definition for permission: %{public}s!", permState.permissionName.c_str());
        permState.state = INVALID_OPER;
        return;
    }

    if (goalGrantStatus == PERMISSION_DENIED) {
        if ((goalGrantFlags == PERMISSION_DEFAULT_FLAG) ||
            ((goalGrantFlags & PERMISSION_USER_SET) != 0)) {
            permState.state = DYNAMIC_OPER;
            return;
        }
        if ((goalGrantFlags & PERMISSION_USER_FIXED) != 0) {
            permState.state = SETTING_OPER;
            return;
        }
    }

    permState.state = PASS_OPER;
    return;
}

int PermissionManager::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, int& flag)
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
        return AccessTokenError::ERR_PERMISSION_NOT_EXIT;
    }
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return permPolicySet->QueryPermissionFlag(permissionName, flag);
}

void PermissionManager::ParamUpdate(const std::string& permissionName, uint32_t flag)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permParamSetLock_);
    if (PermissionDefinitionCache::GetInstance().IsUserGrantedPermission(permissionName) &&
        ((flag != PERMISSION_GRANTED_BY_POLICY) && (flag != PERMISSION_SYSTEM_FIXED))) {
        paramValue_++;
        int32_t res = SetParameter(PERMISSION_STATUS_CHANGE_KEY, std::to_string(paramValue_).c_str());
        if (res != 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "SetParameter failed %{public}d", res);
        }
    }
}
int32_t PermissionManager::UpdateTokenPermissionState(
    AccessTokenID tokenID, const std::string& permissionName, bool isGranted, int flag)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remote token can not update");
        return AccessTokenError::ERR_PERMISSION_OPERATE_FAILED;
    }

    std::shared_ptr<PermissionPolicySet> permPolicySet = infoPtr->GetHapInfoPermissionPolicySet();
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
#ifdef SUPPORT_SANDBOX_APP
    int32_t dlpType = infoPtr->GetDlpType();
    if (isGranted && dlpType != DLP_COMMON) {
        int32_t dlpMode = DlpPermissionSetManager::GetInstance().GetPermDlpMode(permissionName);
        if (DlpPermissionSetManager::GetInstance().IsPermStateNeedUpdate(dlpType, dlpMode)) {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}u is not allowed to be granted permissionName %{public}s",
                tokenID, permissionName.c_str());
            return AccessTokenError::ERR_PERMISSION_OPERATE_FAILED;
        }
    }
#endif
    bool isUpdated = false;
    int32_t ret =
        permPolicySet->UpdatePermissionStatus(permissionName, isGranted, static_cast<uint32_t>(flag), isUpdated);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    if (isUpdated) {
        ACCESSTOKEN_LOG_INFO(LABEL, "isUpdated");
        int32_t changeType = isGranted ? GRANTED : REVOKED;
        CallbackManager::GetInstance().ExecuteCallbackAsync(tokenID, permissionName, changeType);
        HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK_EVENT",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "CODE", USER_GRANT_PERMISSION_EVENT,
            "CALLER_TOKENID", tokenID, "PERMISSION_NAME", permissionName, "PERMISSION_GRANT_TYPE", changeType);
        grantEvent_.AddEvent(tokenID, permissionName, infoPtr->permUpdateTimestamp_);
        ParamUpdate(permissionName, static_cast<uint32_t>(flag));
    }

#ifdef TOKEN_SYNC_ENABLE
    TokenModifyNotifier::GetInstance().NotifyTokenModify(tokenID);
#endif
    return RET_SUCCESS;
}

int32_t PermissionManager::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: %{public}u, permissionName: %{public}s, flag: %{public}d",
        __func__, tokenID, permissionName.c_str(), flag);
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "no definition for permission: %{public}s!", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIT;
    }
    if (!PermissionValidator::IsPermissionFlagValid(flag)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return UpdateTokenPermissionState(tokenID, permissionName, true, flag);
}

int32_t PermissionManager::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: %{public}u, permissionName: %{public}s, flag: %{public}d",
        __func__, tokenID, permissionName.c_str(), flag);
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "no definition for permission: %{public}s!", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIT;
    }
    if (!PermissionValidator::IsPermissionFlagValid(flag)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return UpdateTokenPermissionState(tokenID, permissionName, false, flag);
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
    auto callbackScopePtr = std::make_shared<PermStateChangeScope>(scopeRes);
    if (callbackScopePtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callbackScopePtr is nullptr");
        return AccessTokenError::ERR_MALLOC_FAILED;
    }
    return CallbackManager::GetInstance().AddCallback(callbackScopePtr, callback);
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

bool PermissionManager::GetLocationPermissionIndex(std::vector<PermissionListStateParcel>& reqPermList,
    uint32_t& vagueIndex, uint32_t& accurateIndex)
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
        }

        index++;

        if ((vagueIndex != ELEMENT_NOT_FOUND) && (accurateIndex != ELEMENT_NOT_FOUND)) {
            break;
        }
    }

    ACCESSTOKEN_LOG_INFO(LABEL,
        "vague location permission index is %{public}d, accurate location permission index is %{public}d!",
        vagueIndex, accurateIndex);

    return hasFound;
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

bool PermissionManager::GetPermissionStatusAndFlag(const std::string& permissionName,
    const std::vector<PermissionStateFull>& permsList, int32_t& status, uint32_t& flag)
{
    if (!IsPermissionVaild(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid permission %{public}s", permissionName.c_str());
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

void PermissionManager::AllLocationPermissionHandle(std::vector<PermissionListStateParcel>& reqPermList,
    std::vector<PermissionStateFull> permsList, uint32_t vagueIndex, uint32_t accurateIndex)
{
    int32_t vagueStatus = PERMISSION_DENIED;
    uint32_t vagueFlag = PERMISSION_DEFAULT_FLAG;
    int32_t vagueState = INVALID_OPER;
    int32_t accurateStatus = PERMISSION_DENIED;
    uint32_t accurateFlag = PERMISSION_DEFAULT_FLAG;
    int32_t accurateState = INVALID_OPER;

    if (!GetPermissionStatusAndFlag(VAGUE_LOCATION_PERMISSION_NAME, permsList, vagueStatus, vagueFlag) ||
        !GetPermissionStatusAndFlag(ACCURATE_LOCATION_PERMISSION_NAME, permsList, accurateStatus, accurateFlag)) {
        return;
    }

    // vague location status -1 means vague location permission has been refused
    if (vagueStatus == PERMISSION_DENIED) {
        if ((vagueFlag == PERMISSION_DEFAULT_FLAG) || ((vagueFlag & PERMISSION_USER_SET) != 0)) {
            // vague location flag 0 or 1 means permission has not been operated or valid only once
            vagueState = DYNAMIC_OPER;
            accurateState = DYNAMIC_OPER;
        } else if ((vagueFlag & PERMISSION_USER_FIXED) != 0) {
            // vague location flag 2 means vague location has been operated, only can be changed by settings
            // so that accurate location is no need to operate
            vagueState = SETTING_OPER;
            accurateState = SETTING_OPER;
        }
    } else if (vagueStatus == PERMISSION_GRANTED) {
        // vague location status 0 means vague location permission has been accepted
        // now flag 1 is not in use so return PASS_OPER, otherwise should judge by flag
        vagueState = PASS_OPER;

        if (accurateStatus == PERMISSION_DENIED) {
            if ((accurateFlag == PERMISSION_DEFAULT_FLAG) || ((accurateFlag & PERMISSION_USER_SET) != 0)) {
                accurateState = DYNAMIC_OPER;
            } else if ((accurateFlag & PERMISSION_USER_FIXED) != 0) {
                accurateState = SETTING_OPER;
            }
        } else if (accurateStatus == PERMISSION_GRANTED) {
            accurateState = PASS_OPER;
        }
    }

    ACCESSTOKEN_LOG_DEBUG(LABEL,
        "vague location permission state is %{public}d, accurate location permission state is %{public}d",
        vagueState, accurateState);

    reqPermList[vagueIndex].permsState.state = vagueState;
    reqPermList[accurateIndex].permsState.state = accurateState;
}

bool PermissionManager::LocationPermissionSpecialHandle(std::vector<PermissionListStateParcel>& reqPermList,
    int32_t apiVersion, std::vector<PermissionStateFull> permsList, uint32_t vagueIndex, uint32_t accurateIndex)
{
    if ((vagueIndex != ELEMENT_NOT_FOUND) && (accurateIndex == ELEMENT_NOT_FOUND)) {
        // only vague location permission
        GetSelfPermissionState(permsList, reqPermList[vagueIndex].permsState, apiVersion);
        return (static_cast<PermissionOper>(reqPermList[vagueIndex].permsState.state) == DYNAMIC_OPER);
    }

    if ((vagueIndex == ELEMENT_NOT_FOUND) && (accurateIndex != ELEMENT_NOT_FOUND)) {
        // only accurate location permission refuse directly
        ACCESSTOKEN_LOG_ERROR(LABEL, "operate invaild, accurate location permission base on vague location permission");
        reqPermList[accurateIndex].permsState.state = INVALID_OPER;
        return false;
    }

    // all location permissions
    AllLocationPermissionHandle(reqPermList, permsList, vagueIndex, accurateIndex);
    return ((static_cast<PermissionOper>(reqPermList[vagueIndex].permsState.state) == DYNAMIC_OPER) ||
        (static_cast<PermissionOper>(reqPermList[accurateIndex].permsState.state) == DYNAMIC_OPER));
}

void PermissionManager::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: %{public}u", __func__, tokenID);
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return;
    }
    if (infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remote token can not clear.");
        return;
    }

    std::shared_ptr<PermissionPolicySet> permPolicySet = infoPtr->GetHapInfoPermissionPolicySet();
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return;
    }

    permPolicySet->ResetUserGrantPermissionStatus();
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
    infos.append("}");
    return infos;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
