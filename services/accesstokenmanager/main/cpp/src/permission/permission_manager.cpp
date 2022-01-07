/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "permission_definition_cache.h"
#include "permission_validator.h"

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

void PermissionManager::AddDefPermissions(const std::vector<PermissionDef>& permList)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permList size: %{public}d", __func__, permList.size());
    for (auto perm : permList) {
        if (!PermissionValidator::IsPermissionDefValid(perm)) {
            ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s: invalid permission definition info: %{public}s", __func__,
                TransferPermissionDefToString(perm).c_str());
        } else {
            PermissionDefinitionCache::GetInstance().Insert(perm);
        }
    }
}

void PermissionManager::RemoveDefPermissions(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: 0x%{public}x", __func__, tokenID);
    std::shared_ptr<HapTokenInfoInner> tokenInfo =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (tokenInfo == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: invalid params(tokenID: 0x%{public}x)!", __func__, tokenID);
        return;
    }
    std::string bundleName = tokenInfo->GetBundleName();
    PermissionDefinitionCache::GetInstance().DeleteByBundleName(bundleName);
}

int PermissionManager::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: 0x%{public}x, permissionName: %{public}s", __func__,
        tokenID, permissionName.c_str());
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: invalid params!", __func__);
        return PERMISSION_DENIED;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "%{public}s: no definition for permission: %{public}s!", __func__, permissionName.c_str());
        return PERMISSION_DENIED;
    }
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: invalid params!", __func__);
        return PERMISSION_DENIED;
    }

    std::vector<PermissionStateFull> permList = permPolicySet->permStateList_;
    for (auto perm : permList) {
        if (perm.permissionName == permissionName) {
            return QueryPermissionStatus(perm);
        }
    }
    return PERMISSION_DENIED;
}

int PermissionManager::GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, permissionName: %{public}s", __func__, permissionName.c_str());
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: invalid params!", __func__);
        return RET_FAILED;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "%{public}s: no definition for permission: %{public}s!", __func__, permissionName.c_str());
        return RET_FAILED;
    }
    return PermissionDefinitionCache::GetInstance().FindByPermissionName(permissionName, permissionDefResult);
}

int PermissionManager::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: 0x%{public}x", __func__, tokenID);
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: invalid params!", __func__);
        return RET_FAILED;
    }
    std::vector<PermissionDef> permListGet = permPolicySet->permList_;
    permList.assign(permListGet.begin(), permListGet.end());
    return RET_SUCCESS;
}

int PermissionManager::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: 0x%{public}x, isSystemGrant: %{public}d",
        __func__, tokenID, isSystemGrant);
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: invalid params!", __func__);
        return RET_FAILED;
    }

    GrantMode mode = isSystemGrant ? SYSTEM_GRANT : USER_GRANT;
    std::vector<PermissionStateFull> permList = permPolicySet->permStateList_;
    for (auto perm : permList) {
        PermissionDef permDef;
        GetDefPermission(perm.permissionName, permDef);
        if (permDef.grantMode == mode) {
            reqPermList.emplace_back(perm);
        }
    }
    return RET_SUCCESS;
}

int PermissionManager::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: 0x%{public}x, permissionName: %{public}s",
        __func__, tokenID, permissionName.c_str());
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: invalid params!", __func__);
        return DEFAULT_PERMISSION_FLAGS;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "%{public}s: no definition for permission: %{public}s!", __func__, permissionName.c_str());
        return DEFAULT_PERMISSION_FLAGS;
    }
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: invalid params!", __func__);
        return DEFAULT_PERMISSION_FLAGS;
    }

    std::vector<PermissionStateFull> permList = permPolicySet->permStateList_;
    for (auto perm : permList) {
        if (perm.permissionName == permissionName) {
            return QueryPermissionFlag(perm);
        }
    }
    return DEFAULT_PERMISSION_FLAGS;
}


int PermissionManager::UpdatePermissionStatus(PermissionStateFull& permStat, bool isGranted, int flag)
{
    if (permStat.isGeneral == true) {
        permStat.grantStatus[0] = isGranted ? PERMISSION_GRANTED : PERMISSION_DENIED;
        permStat.grantFlags[0] = flag;
    }
    return RET_FAILED;
}

void PermissionManager::UpdateTokenPermissionState(
    AccessTokenID tokenID, const std::string& permissionName, bool isGranted, int flag)
{
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: invalid params!", __func__);
        return;
    }

    std::vector<PermissionStateFull>& permList = permPolicySet->permStateList_;
    for (auto& perm : permList) {
        if (perm.permissionName == permissionName) {
            UpdatePermissionStatus(perm, isGranted, flag);
            break;
        }
    }
}

void PermissionManager::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: 0x%{public}x, permissionName: %{public}s, flag: %{public}d",
        __func__, tokenID, permissionName.c_str(), flag);
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: invalid params!", __func__);
        return;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "%{public}s: no definition for permission: %{public}s!", __func__, permissionName.c_str());
        return;
    }
    if (!PermissionValidator::IsPermissionFlagValid(flag)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: invalid params!", __func__);
        return;
    }
    UpdateTokenPermissionState(tokenID, permissionName, true, flag);
}

void PermissionManager::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: 0x%{public}x, permissionName: %{public}s, flag: %{public}d",
        __func__, tokenID, permissionName.c_str(), flag);
    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: invalid params!", __func__);
        return;
    }
    if (!PermissionDefinitionCache::GetInstance().HasDefinition(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(
            LABEL, "%{public}s: no definition for permission: %{public}s!", __func__, permissionName.c_str());
        return;
    }
    if (!PermissionValidator::IsPermissionFlagValid(flag)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: invalid params!", __func__);
        return;
    }
    UpdateTokenPermissionState(tokenID, permissionName, false, flag);
}

void PermissionManager::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: 0x%{public}x", __func__, tokenID);
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenID);
    if (permPolicySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: invalid params!", __func__);
        return;
    }

    std::vector<PermissionStateFull>& permList = permPolicySet->permStateList_;
    for (auto& perm : permList) {
        PermissionDef permDef;
        bool isGranted;
        GetDefPermission(perm.permissionName, permDef);
        isGranted = (permDef.grantMode == SYSTEM_GRANT) ? true : false;
        UpdatePermissionStatus(perm, isGranted, DEFAULT_PERMISSION_FLAGS);
    }
}

int PermissionManager::QueryPermissionFlag(const PermissionStateFull& permStat)
{
    if (permStat.isGeneral == true) {
        return permStat.grantFlags[0];
    }
    return DEFAULT_PERMISSION_FLAGS;
}

int PermissionManager::QueryPermissionStatus(const PermissionStateFull& permStat)
{
    if (permStat.isGeneral == true) {
        return permStat.grantStatus[0];
    }
    return PERMISSION_DENIED;
}

std::string PermissionManager::TransferPermissionDefToString(const PermissionDef& inPermissionDef)
{
    std::string infos;
    infos.append(R"({"permissionName": ")" + inPermissionDef.permissionName + R"(")");
    infos.append(R"(, "bundleName": ")" + inPermissionDef.bundleName + R"(")");
    infos.append(R"(, "grantMode": )" + std::to_string(inPermissionDef.grantMode));
    infos.append(R"(, "availableScope": )" + std::to_string(inPermissionDef.availableScope));
    infos.append(R"(, "label": ")" + inPermissionDef.label + R"(")");
    infos.append(R"(, "labelId": )" + std::to_string(inPermissionDef.labelId));
    infos.append(R"(, "description": ")" + inPermissionDef.description + R"(")");
    infos.append(R"(, "descriptionId": )" + std::to_string(inPermissionDef.descriptionId));
    infos.append("}");
    return infos;
}
} // namespace AccessToken
} // namespace Security
}
