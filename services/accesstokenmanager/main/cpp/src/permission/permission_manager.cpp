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

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "access_token_db.h"
#include "app_manager_access_client.h"
#include "callback_manager.h"
#ifdef SUPPORT_SANDBOX_APP
#include "dlp_permission_set_manager.h"
#endif
#include "ipc_skeleton.h"
#include "parameter.h"
#include "permission_definition_cache.h"
#include "permission_map.h"
#include "permission_validator.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_modify_notifier.h"
#endif
#include "perm_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "PermissionManager"};
static const char* PERMISSION_STATUS_CHANGE_KEY = "accesstoken.permission.change";
static constexpr int32_t VALUE_MAX_LEN = 32;
static constexpr int32_t ROOT_UID = 0;
static constexpr int32_t BASE_USER_RANGE = 200000;
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
constexpr const char* APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
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
    ACCESSTOKEN_LOG_INFO(LABEL, "permFilterList size: %{public}zu", permFilterList.size());
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID: %{public}d, can not find tokenInfo!", tokenID);
        return PERMISSION_DENIED;
    }
    std::shared_ptr<PermissionPolicySet> permPolicySet = tokenInfoPtr->GetHapInfoPermissionPolicySet();
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID: %{public}d, invalid params!", tokenID);
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
            ACCESSTOKEN_LOG_ERROR(LABEL, "token: %{public}d type error!", tokenID);
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

PermUsedTypeEnum PermissionManager::GetUserGrantedPermissionUsedType(
    AccessTokenID tokenID, const std::string& permissionName)
{
    if ((tokenID == INVALID_TOKENID) ||
        (TOKEN_HAP != AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenID))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID: %{public}d is invalid.", tokenID);
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }

    PermissionDef permissionDefResult;
    int ret = GetDefPermission(permissionName, permissionDefResult);
    if (RET_SUCCESS != ret) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Query permission info of %{public}s failed.", permissionName.c_str());
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    if (USER_GRANT != permissionDefResult.grantMode) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Not user grant for permission=%{public}s.", permissionName.c_str());
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }

    std::shared_ptr<HapTokenInfoInner> tokenInfoPtr =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (tokenInfoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID=%{public}d, can not find tokenInfo.", tokenID);
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    std::shared_ptr<PermissionPolicySet> permPolicySet = tokenInfoPtr->GetHapInfoPermissionPolicySet();
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID=%{public}d, invalid params.", tokenID);
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }

    return permPolicySet->GetUserGrantedPermissionUsedType(permissionName);
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
        ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID: %{public}d, invalid params!", tokenID);
        return PERMISSION_DENIED;
    }

    ATokenTypeEnum tokenType = AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenID);
    if ((tokenType == TOKEN_NATIVE) || (tokenType == TOKEN_SHELL)) {
        return VerifyNativeAccessToken(tokenID, permissionName);
    }
    if (tokenType == TOKEN_HAP) {
        return VerifyHapAccessToken(tokenID, permissionName);
    }
    ACCESSTOKEN_LOG_ERROR(LABEL, "tokenID: %{public}d, invalid tokenType!", tokenID);
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
    int32_t userID = IPCSkeleton::GetCallingUid() / BASE_USER_RANGE;

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

    if (FindPermRequestToggleStatusFromDb(userID, permState.permissionName)) {
        permState.state = SETTING_OPER;
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

void PermissionManager::PermDefToString(const PermissionDef& def, std::string& info) const
{
    info.append(R"(    {)");
    info.append("\n");
    info.append(R"(      "permissionName": ")" + def.permissionName + R"(")" + ",\n");
    info.append(R"(      "grantMode": )" + std::to_string(def.grantMode) + ",\n");
    info.append(R"(      "availableLevel": )" + std::to_string(def.availableLevel) + ",\n");
    info.append(R"(      "provisionEnable": )" + std::to_string(def.provisionEnable) + ",\n");
    info.append(R"(      "distributedSceneEnable": )" + std::to_string(def.distributedSceneEnable) + ",\n");
    info.append(R"(      "label": ")" + def.label + R"(")" + ",\n");
    info.append(R"(      "labelId": )" + std::to_string(def.labelId) + ",\n");
    info.append(R"(      "description": ")" + def.description + R"(")" + ",\n");
    info.append(R"(      "descriptionId": )" + std::to_string(def.descriptionId) + ",\n");
    info.append(R"(    })");
}

int32_t PermissionManager::DumpPermDefInfo(std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Get all permission definition info.");

    std::vector<GenericValues> permDefRes;

    dumpInfo.append(R"({)");
    dumpInfo.append("\n");
    dumpInfo.append(R"(  "permDefList": [)");
    dumpInfo.append("\n");
    AccessTokenDb::GetInstance().Find(AccessTokenDb::ACCESSTOKEN_PERMISSION_DEF, permDefRes);
    for (auto iter = permDefRes.begin(); iter != permDefRes.end(); iter++) {
        PermissionDef def;
        int32_t ret = DataTranslator::TranslationIntoPermissionDef(*iter, def);
        if (ret != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "PermDef is wrong.");
            return ret;
        }
        PermDefToString(def, dumpInfo);
        if (iter != (permDefRes.end() - 1)) {
            dumpInfo.append(",\n");
        }
        dumpInfo.append("\n");
    }
    dumpInfo.append("\n  ]\n");
    dumpInfo.append("}");
    return RET_SUCCESS;
}

bool PermissionManager::FindPermRequestToggleStatusFromDb(int32_t userID, const std::string& permissionName)
{
    std::vector<GenericValues> permRequestToggleStatusRes;

    AccessTokenDb::GetInstance().Find(AccessTokenDb::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS,
        permRequestToggleStatusRes);
    for (const GenericValues& permRequestToggleStatus: permRequestToggleStatusRes) {
        int32_t id = permRequestToggleStatus.GetInt(TokenFiledConst::FIELD_USER_ID);
        if (id != userID) {
            continue;
        }

        std::string permission = permRequestToggleStatus.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        if (permission == permissionName) {
            return true;
        }
    }

    return false;
}

void PermissionManager::AddPermRequestToggleStatusToDb(int32_t userID, const std::string& permissionName)
{
    std::vector<GenericValues> permRequestToggleStatusValues;
    GenericValues genericValues;

    genericValues.Put(TokenFiledConst::FIELD_USER_ID, userID);
    genericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
    permRequestToggleStatusValues.emplace_back(genericValues);

    AccessTokenDb::GetInstance().Add(AccessTokenDb::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS,
        permRequestToggleStatusValues);
}

void PermissionManager::DeletePermRequestToggleStatusFromDb(int32_t userID, const std::string& permissionName)
{
    GenericValues values;
    values.Put(TokenFiledConst::FIELD_USER_ID, userID);
    values.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);

    AccessTokenDb::GetInstance().Remove(AccessTokenDb::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, values);
}

int32_t PermissionManager::SetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t status,
    int32_t userID)
{
    if (userID == 0) {
        userID = IPCSkeleton::GetCallingUid() / BASE_USER_RANGE;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "UserID=%{public}u, permissionName=%{public}s, status=%{public}d", userID,
        permissionName.c_str(), status);
    if (!PermissionValidator::IsUserIdValid(userID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UserID is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission name is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "Permission=%{public}s is not defined.", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    if (PermissionDefinitionCache::GetInstance().IsSystemGrantedPermission(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Only support permissions of user_grant to set.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!PermissionValidator::IsToggleStatusValid(status)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Status is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    if (status == PermissionRequestToggleStatus::CLOSED) {
        AddPermRequestToggleStatusToDb(userID, permissionName);
    } else {
        DeletePermRequestToggleStatusFromDb(userID, permissionName);
    }

    HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERM_DIALOG_STATUS_INFO",
        HiviewDFX::HiSysEvent::EventType::STATISTIC, "USERID", userID, "PERMISSION_NAME", permissionName,
        "TOGGLE_STATUS", status);

    return 0;
}

int32_t PermissionManager::GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status,
    int32_t userID)
{
    if (userID == 0) {
        userID = IPCSkeleton::GetCallingUid() / BASE_USER_RANGE;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "UserID=%{public}u, permissionName=%{public}s", userID, permissionName.c_str());
    if (!PermissionValidator::IsUserIdValid(userID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "UserID is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission name is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "Permission=%{public}s is not defined.", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    if (PermissionDefinitionCache::GetInstance().IsSystemGrantedPermission(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Only support permissions of user_grant to get.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    bool ret = FindPermRequestToggleStatusFromDb(userID, permissionName);
    if (ret) {
        status = PermissionRequestToggleStatus::CLOSED;
    } else {
        status = PermissionRequestToggleStatus::OPEN;
    }

    return 0;
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
    AccessTokenInfoManager::GetInstance().ModifyHapPermStateFromDb(tokenID, permissionName);
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

bool PermissionManager::GetStateWithVaguePermission(std::vector<PermissionListStateParcel>& reqPermList,
    std::vector<PermissionStateFull>& permsList, int32_t apiVersion, const LocationIndex& locationIndex)
{
    bool needRes = false;
    GetSelfPermissionState(permsList, reqPermList[locationIndex.vagueIndex].permsState, apiVersion);
    needRes = reqPermList[locationIndex.vagueIndex].permsState.state == DYNAMIC_OPER;
    if (locationIndex.accurateIndex != PERMISSION_NOT_REQUSET) {
        // request accurate and vague permission, if vague has been set or invalid, accurate can't be requested
        GetSelfPermissionState(permsList, reqPermList[locationIndex.accurateIndex].permsState, apiVersion);
        if (reqPermList[locationIndex.accurateIndex].permsState.state == DYNAMIC_OPER &&
            ((reqPermList[locationIndex.vagueIndex].permsState.state == SETTING_OPER) ||
            (reqPermList[locationIndex.vagueIndex].permsState.state == INVALID_OPER))) {
            reqPermList[locationIndex.accurateIndex].permsState.state = INVALID_OPER;
        }
        needRes = needRes || (reqPermList[locationIndex.accurateIndex].permsState.state == DYNAMIC_OPER);
    }
    if (locationIndex.backIndex != PERMISSION_NOT_REQUSET) {
        // with back and vague permission
        // back state is SETTING_OPER when dynamic pop-up dialog appears and INVALID_OPER when it doesn't
        GetSelfPermissionState(permsList, reqPermList[locationIndex.backIndex].permsState, apiVersion);
        if (reqPermList[locationIndex.backIndex].permsState.state == DYNAMIC_OPER) {
            if (((locationIndex.accurateIndex != PERMISSION_NOT_REQUSET) &&
                (reqPermList[locationIndex.accurateIndex].permsState.state == DYNAMIC_OPER)) ||
                (reqPermList[locationIndex.vagueIndex].permsState.state == DYNAMIC_OPER)) {
                reqPermList[locationIndex.backIndex].permsState.state = SETTING_OPER;
            } else {
                reqPermList[locationIndex.backIndex].permsState.state = INVALID_OPER;
            }
        }
    }
    return needRes;
}

bool PermissionManager::GetLocationPermissionState(std::vector<PermissionListStateParcel>& reqPermList,
    std::vector<PermissionStateFull>& permsList, int32_t apiVersion)
{
    struct LocationIndex locationIndex;
    if (!GetLocationPermissionIndex(reqPermList, locationIndex)) {
        return false;
    }
    if (locationIndex.vagueIndex != PERMISSION_NOT_REQUSET) {
        return GetStateWithVaguePermission(reqPermList, permsList, apiVersion, locationIndex);
    }
    // permission handle without vague location, accurate and back can't be requested
    if (locationIndex.accurateIndex != PERMISSION_NOT_REQUSET) {
        reqPermList[locationIndex.accurateIndex].permsState.state = INVALID_OPER;
    }
    if (locationIndex.backIndex != PERMISSION_NOT_REQUSET) {
        reqPermList[locationIndex.backIndex].permsState.state = INVALID_OPER;
    }
    return false;
}

bool PermissionManager::GetStateWithVaguePermissionBackGroundVersion(
    std::vector<PermissionListStateParcel>& reqPermList,
    std::vector<PermissionStateFull>& permsList, int32_t apiVersion, const LocationIndex& locationIndex)
{
    bool needRes = false;
    GetSelfPermissionState(permsList, reqPermList[locationIndex.vagueIndex].permsState, apiVersion);
    needRes = reqPermList[locationIndex.vagueIndex].permsState.state == DYNAMIC_OPER;
    if (locationIndex.accurateIndex != PERMISSION_NOT_REQUSET) {
        // request accurate and vague permission, if vague has been set or invalid, accurate can't be requested
        GetSelfPermissionState(permsList, reqPermList[locationIndex.accurateIndex].permsState, apiVersion);
        if (reqPermList[locationIndex.accurateIndex].permsState.state == DYNAMIC_OPER &&
            ((reqPermList[locationIndex.vagueIndex].permsState.state == SETTING_OPER) ||
            (reqPermList[locationIndex.vagueIndex].permsState.state == INVALID_OPER))) {
            reqPermList[locationIndex.accurateIndex].permsState.state = INVALID_OPER;
        }
        needRes = needRes || (reqPermList[locationIndex.accurateIndex].permsState.state == DYNAMIC_OPER);
    }
    if (locationIndex.backIndex != PERMISSION_NOT_REQUSET) {
        // with back and vague permission, request back can not pop dynamic dialog
        reqPermList[locationIndex.vagueIndex].permsState.state = INVALID_OPER;
        if (locationIndex.accurateIndex != PERMISSION_NOT_REQUSET) {
            reqPermList[locationIndex.accurateIndex].permsState.state = INVALID_OPER;
        }
        reqPermList[locationIndex.backIndex].permsState.state = INVALID_OPER;
        needRes = false;
    }
    return needRes;
}

bool PermissionManager::GetLocationPermissionStateBackGroundVersion(std::vector<PermissionListStateParcel>& reqPermList,
    std::vector<PermissionStateFull>& permsList, int32_t apiVersion)
{
    struct LocationIndex locationIndex;
    if (!GetLocationPermissionIndex(reqPermList, locationIndex)) {
        return false;
    }
    if (locationIndex.vagueIndex != PERMISSION_NOT_REQUSET) {
        return GetStateWithVaguePermissionBackGroundVersion(reqPermList, permsList, apiVersion, locationIndex);
    }
    // permission handle without vague location, accurate and back can't be requested
    if (locationIndex.accurateIndex != PERMISSION_NOT_REQUSET) {
        reqPermList[locationIndex.accurateIndex].permsState.state = INVALID_OPER;
    }
    if (locationIndex.backIndex != PERMISSION_NOT_REQUSET) {
        reqPermList[locationIndex.backIndex].permsState.state = INVALID_OPER;
    }
    return false;
}

bool PermissionManager::LocationPermissionSpecialHandle(std::vector<PermissionListStateParcel>& reqPermList,
    std::vector<PermissionStateFull>& permsList, int32_t apiVersion)
{
    bool needRes = false;
    if (apiVersion < BACKGROUND_LOCATION_API_VERSION) {
        needRes = GetLocationPermissionState(reqPermList, permsList, apiVersion);
    } else {
        needRes = GetLocationPermissionStateBackGroundVersion(reqPermList, permsList, apiVersion);
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

    // clear
    AddPermToKernel(tokenID, permPolicySet);

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

void PermissionManager::AddPermToKernel(AccessTokenID tokenID, const std::shared_ptr<PermissionPolicySet>& policy)
{
    if (policy == nullptr) {
        return;
    }
    std::vector<uint32_t> opCodeList;
    std::vector<bool> statusList;
    policy->GetPermissionStateList(opCodeList, statusList);
    int32_t ret = AddPermissionToKernel(tokenID, opCodeList, statusList);
    ACCESSTOKEN_LOG_INFO(LABEL,
        "AddPermissionToKernel(token=%{public}d), size=%{public}zu, err=%{public}d", tokenID, opCodeList.size(), ret);
}

void PermissionManager::RemovePermFromKernel(AccessTokenID tokenID)
{
    int32_t ret = RemovePermissionFromKernel(tokenID);
    ACCESSTOKEN_LOG_INFO(LABEL,
        "RemovePermissionFromKernel(token=%{public}d), err=%{public}d", tokenID, ret);
}

void PermissionManager::SetPermToKernel(AccessTokenID tokenID, const std::string& permissionName, bool isGranted)
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

bool IsAclSatisfied(const PermissionDef& permDef, const HapPolicyParams& policy)
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
    if ((appDistributionType != APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM) &&
        permDef.availableType == ATokenAvailableTypeEnum::MDM) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s is a mdm permission, the hap is not a mdm application.",
            permDef.permissionName.c_str());
        return false;
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
    std::vector<PermissionStateFull>& initializedList)
{
    // get dlp original app
    AccessTokenIDEx tokenId = AccessTokenInfoManager::GetInstance().GetHapTokenID(userId, bundleName, 0);
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenId.tokenIdExStruct.tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return false;
    }
    permPolicySet->GetPermissionStateFulls(initializedList);
    return true;
}

bool PermissionManager::InitPermissionList(const std::string& appDistributionType,
    const HapPolicyParams& policy, std::vector<PermissionStateFull>& initializedList)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Before, request perm list size: %{public}zu, preAuthorizationInfo size %{public}zu.",
        policy.permStateList.size(), policy.preAuthorizationInfo.size());

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
            ACCESSTOKEN_LOG_ERROR(LABEL, "Acl of %{public}s is invalid.", permDef.permissionName.c_str());
            return false;
        }

        // edm check
        if (!IsPermAvailableRangeSatisfied(permDef, appDistributionType)) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Available range of %{public}s is invalid.", permDef.permissionName.c_str());
            return false;
        }
        state.grantFlags[0] = PERMISSION_DEFAULT_FLAG;
        state.grantStatus[0] = PERMISSION_DENIED;

        if (permDef.grantMode == AccessToken::GrantMode::SYSTEM_GRANT) {
            state.grantFlags[0] = PERMISSION_SYSTEM_FIXED;
            state.grantStatus[0] = PERMISSION_GRANTED;
            initializedList.emplace_back(state);
            continue;
        }
        if (policy.preAuthorizationInfo.size() == 0) {
            initializedList.emplace_back(state);
            continue;
        }
        bool userCancelable = true;
        if (IsUserGrantPermPreAuthorized(policy.preAuthorizationInfo, state.permissionName, userCancelable)) {
            state.grantFlags[0] = userCancelable ? PERMISSION_GRANTED_BY_POLICY : PERMISSION_SYSTEM_FIXED;
            state.grantStatus[0] = PERMISSION_GRANTED;
        }
        initializedList.emplace_back(state);
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "After, request perm list size: %{public}zu.", initializedList.size());
    return true;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
