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
#include "access_token.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "callback_manager.h"
#ifdef SUPPORT_SANDBOX_APP
#include "dlp_permission_set_manager.h"
#endif
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
}

PermissionManager& PermissionManager::GetInstance()
{
    static PermissionManager instance;
    return instance;
}

PermissionManager::PermissionManager()
{
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
        if (!PermissionValidator::IsPermissionDefValid(perm)) {
            ACCESSTOKEN_LOG_INFO(LABEL, "invalid permission definition info: %{public}s",
                TransferPermissionDefToString(perm).c_str());
            continue;
        }

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
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: %{public}u, permissionName: %{public}s", __func__,
        tokenID, permissionName.c_str());
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return PERMISSION_DENIED;
    }

    ATokenTypeEnum tokenType = AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenID);
    if (tokenType == TOKEN_NATIVE) {
        return VerifyNativeAccessToken(tokenID, permissionName);
    }
    if (tokenType == TOKEN_HAP) {
        return VerifyHapAccessToken(tokenID, permissionName);
    }
    ACCESSTOKEN_LOG_ERROR(LABEL, "invalid tokenType!");
    return PERMISSION_DENIED;
}

int PermissionManager::VerifyNativeToken(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: %{public}u, permissionName: %{public}s", __func__,
        tokenID, permissionName.c_str());

    PermissionDef permissionInfo;
    NativeTokenInfo nativeTokenInfo;
    int res = PermissionManager::GetDefPermission(permissionName, permissionInfo);
    if (res != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetDefPermission in %{public}s failed", __func__);
        return PERMISSION_DENIED;
    }
    res = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(tokenID, nativeTokenInfo);
    if (res != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetNativeTokenInfo in %{public}s failed", __func__);
        return PERMISSION_DENIED;
    }
    if (permissionInfo.availableLevel > nativeTokenInfo.apl) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

int PermissionManager::GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permissionName: %{public}s", __func__, permissionName.c_str());
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return RET_FAILED;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "no definition for permission: %{public}s!", permissionName.c_str());
        return RET_FAILED;
    }
    return PermissionDefinitionCache::GetInstance().FindByPermissionName(permissionName, permissionDefResult);
}

int PermissionManager::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: %{public}u", __func__, tokenID);
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
    PermissionListState &permState)
{
    bool foundGoal = false;
    int32_t goalGrantStatus;
    uint32_t goalGrantFlags;
    for (const auto& perm : permsList) {
        if (perm.permissionName == permState.permissionName) {
            ACCESSTOKEN_LOG_INFO(LABEL,
                "find goal permission: %{public}s!", permState.permissionName.c_str());
            foundGoal = true;
            goalGrantStatus = perm.grantStatus[0];
            goalGrantFlags = static_cast<uint32_t>(perm.grantFlags[0]);
            break;
        }
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

int PermissionManager::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: %{public}u, permissionName: %{public}s",
        __func__, tokenID, permissionName.c_str());
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return PERMISSION_DEFAULT_FLAG;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "no definition for permission: %{public}s!", permissionName.c_str());
        return PERMISSION_DEFAULT_FLAG;
    }
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return PERMISSION_DEFAULT_FLAG;
    }
    return permPolicySet->QueryPermissionFlag(permissionName);
}

void PermissionManager::UpdateTokenPermissionState(
    AccessTokenID tokenID, const std::string& permissionName, bool isGranted, int flag)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return;
    }
    if (infoPtr->IsRemote()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "remote token can not update");
        return;
    }

    std::shared_ptr<PermissionPolicySet> permPolicySet = infoPtr->GetHapInfoPermissionPolicySet();
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return;
    }
#ifdef SUPPORT_SANDBOX_APP
    int32_t dlpType = infoPtr->GetDlpType();
    if (isGranted && dlpType != DLP_COMMON) {
        int32_t dlpMode = DlpPermissionSetManager::GetInstance().GetPermDlpMode(permissionName);
        if (DlpPermissionSetManager::GetInstance().IsPermStateNeedUpdate(dlpType, dlpMode)) {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}u is not allowed to be granted permissionName %{public}s",
                tokenID, permissionName.c_str());
            return;
        }
    }
#endif
    bool isUpdated = permPolicySet->UpdatePermissionStatus(permissionName, isGranted, static_cast<uint32_t>(flag));
    if (isUpdated) {
        ACCESSTOKEN_LOG_INFO(LABEL, "isUpdated");
        int32_t changeType = isGranted ? GRANTED : REVOKED;
        CallbackManager::GetInstance().ExcuteCallbackAsync(tokenID, permissionName, changeType);
    }

#ifdef TOKEN_SYNC_ENABLE
    TokenModifyNotifier::GetInstance().NotifyTokenModify(tokenID);
#endif
}

void PermissionManager::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: %{public}u, permissionName: %{public}s, flag: %{public}d",
        __func__, tokenID, permissionName.c_str(), flag);
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "no definition for permission: %{public}s!", permissionName.c_str());
        return;
    }
    if (!PermissionValidator::IsPermissionFlagValid(flag)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return;
    }
    UpdateTokenPermissionState(tokenID, permissionName, true, flag);
}

void PermissionManager::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: %{public}u, permissionName: %{public}s, flag: %{public}d",
        __func__, tokenID, permissionName.c_str(), flag);
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "no definition for permission: %{public}s!", permissionName.c_str());
        return;
    }
    if (!PermissionValidator::IsPermissionFlagValid(flag)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "invalid params!");
        return;
    }
    UpdateTokenPermissionState(tokenID, permissionName, false, flag);
}

int32_t PermissionManager::AddPermStateChangeCallback(
    const PermStateChangeScope& scope, const sptr<IRemoteObject>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called");
    auto callbackScopePtr = std::make_shared<PermStateChangeScope>(scope);
    if (callbackScopePtr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callbackScopePtr is nullptr");
    }

    return CallbackManager::GetInstance().AddCallback(callbackScopePtr, callback);
}

int32_t PermissionManager::RemovePermStateChangeCallback(const sptr<IRemoteObject>& callback)
{
    return CallbackManager::GetInstance().RemoveCallback(callback);
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
