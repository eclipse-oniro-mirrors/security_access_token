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
#include "permission_validator.h"

#include <set>

#include "access_token.h"
#include "accesstoken_log.h"
#include "data_validator.h"
#include "permission_definition_cache.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool PermissionValidator::IsGrantModeValid(int grantMode)
{
    return grantMode == GrantMode::SYSTEM_GRANT || grantMode == GrantMode::USER_GRANT;
}

bool PermissionValidator::IsGrantStatusValid(int grantStatus)
{
    return grantStatus == PermissionState::PERMISSION_GRANTED || grantStatus == PermissionState::PERMISSION_DENIED;
}

bool PermissionValidator::IsPermissionFlagValid(uint32_t flag)
{
    return DataValidator::IsPermissionFlagValid(flag);
}

bool PermissionValidator::IsPermissionNameValid(const std::string& permissionName)
{
    return DataValidator::IsPermissionNameValid(permissionName);
}

bool PermissionValidator::IsUserIdValid(const int32_t userID)
{
    return DataValidator::IsUserIdValid(userID);
}

bool PermissionValidator::IsToggleStatusValid(const uint32_t status)
{
    return DataValidator::IsToggleStatusValid(status);
}

bool PermissionValidator::IsPermissionDefValid(const PermissionDef& permDef)
{
    if (!DataValidator::IsLabelValid(permDef.label)) {
        LOGE(AT_DOMAIN, AT_TAG, "Label invalid.");
        return false;
    }
    if (!DataValidator::IsDescValid(permDef.description)) {
        LOGE(AT_DOMAIN, AT_TAG, "Desc invalid.");
        return false;
    }
    if (!DataValidator::IsBundleNameValid(permDef.bundleName)) {
        LOGE(AT_DOMAIN, AT_TAG, "BundleName invalid.");
        return false;
    }
    if (!DataValidator::IsPermissionNameValid(permDef.permissionName)) {
        LOGE(AT_DOMAIN, AT_TAG, "PermissionName invalid.");
        return false;
    }
    if (!IsGrantModeValid(permDef.grantMode)) {
        LOGE(AT_DOMAIN, AT_TAG, "GrantMode invalid.");
        return false;
    }
    if (!DataValidator::IsAvailableTypeValid(permDef.availableType)) {
        LOGE(AT_DOMAIN, AT_TAG, "AvailableType invalid.");
        return false;
    }
    if (!DataValidator::IsAplNumValid(permDef.availableLevel)) {
        LOGE(AT_DOMAIN, AT_TAG, "AvailableLevel invalid.");
        return false;
    }
    return true;
}

bool PermissionValidator::IsPermissionAvailable(ATokenTypeEnum tokenType, const std::string& permissionName)
{
    LOGD(AT_DOMAIN, AT_TAG, "TokenType is %{public}d.", tokenType);
    if (tokenType == TOKEN_HAP) {
        if (!PermissionDefinitionCache::GetInstance().HasHapPermissionDefinitionForHap(permissionName)) {
            LOGE(AT_DOMAIN, AT_TAG, "%{public}s is not defined for hap.", permissionName.c_str());
            return false;
        }
    }
    // permission request for TOKEN_NATIVE process is going to be check when the permission request way is normalized.
    return true;
}

bool PermissionValidator::IsPermissionStateValid(const PermissionStateFull& permState)
{
    if (!DataValidator::IsPermissionNameValid(permState.permissionName)) {
        return false;
    }
    size_t resDevIdSize = permState.resDeviceID.size();
    size_t grantStatSize = permState.grantStatus.size();
    size_t grantFlagSize = permState.grantFlags.size();
    if ((grantStatSize != resDevIdSize) || (grantFlagSize != resDevIdSize)) {
        LOGE(AT_DOMAIN, AT_TAG,
            "list size is invalid, grantStatSize %{public}zu, grantFlagSize %{public}zu, resDevIdSize %{public}zu.",
            grantStatSize, grantFlagSize, resDevIdSize);
        return false;
    }
    for (uint32_t i = 0; i < resDevIdSize; i++) {
        if (!IsGrantStatusValid(permState.grantStatus[i]) ||
            !IsPermissionFlagValid(permState.grantFlags[i])) {
            LOGE(AT_DOMAIN, AT_TAG, "GrantStatus or grantFlags is invalid");
            return false;
        }
    }
    return true;
}

void PermissionValidator::FilterInvalidPermissionDef(
    const std::vector<PermissionDef>& permList, std::vector<PermissionDef>& result)
{
    std::set<std::string> permDefSet;
    for (auto it = permList.begin(); it != permList.end(); ++it) {
        std::string permName = it->permissionName;
        if (!IsPermissionDefValid(*it) || permDefSet.count(permName) != 0) {
            continue;
        }
        permDefSet.insert(permName);
        result.emplace_back(*it);
    }
}

void PermissionValidator::DeduplicateResDevID(const PermissionStateFull& permState, PermissionStateFull& result)
{
    std::set<std::string> resDevId;
    auto stateIter = permState.grantStatus.begin();
    auto flagIter = permState.grantFlags.begin();
    for (auto it = permState.resDeviceID.begin(); it != permState.resDeviceID.end(); ++it, ++stateIter, ++flagIter) {
        if (resDevId.count(*it) != 0) {
            continue;
        }
        resDevId.insert(*it);
        result.resDeviceID.emplace_back(*it);
        result.grantStatus.emplace_back(*stateIter);
        result.grantFlags.emplace_back(*flagIter);
    }
    result.permissionName = permState.permissionName;
    result.isGeneral = permState.isGeneral;
}

void PermissionValidator::FilterInvalidPermissionState(ATokenTypeEnum tokenType, bool doPermAvailableCheck,
    const std::vector<PermissionStateFull>& permList, std::vector<PermissionStateFull>& result)
{
    std::set<std::string> permStateSet;
    for (auto it = permList.begin(); it != permList.end(); ++it) {
        std::string permName = it->permissionName;
        PermissionStateFull res;
        if (!IsPermissionStateValid(*it) || permStateSet.count(permName) != 0) {
            continue;
        }
        if (doPermAvailableCheck && !IsPermissionAvailable(tokenType, permName)) {
            continue;
        }
        DeduplicateResDevID(*it, res);
        permStateSet.insert(permName);
        result.emplace_back(res);
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
