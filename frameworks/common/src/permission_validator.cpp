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
#include "accesstoken_common_log.h"
#include "data_validator.h"
#include "permission_map.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

bool PermissionValidator::IsGrantModeValid(int grantMode)
{
    return grantMode == GrantMode::SYSTEM_GRANT || grantMode == GrantMode::USER_GRANT ||
        grantMode == GrantMode::MANUAL_SETTINGS;
}

bool PermissionValidator::IsGrantStatusValid(int grantStatus)
{
    return grantStatus == PermissionState::PERMISSION_GRANTED || grantStatus == PermissionState::PERMISSION_DENIED;
}

bool PermissionValidator::IsPermissionFlagValid(uint32_t flag)
{
    return DataValidator::IsPermissionFlagValid(flag);
}

bool PermissionValidator::IsPermissionFlagValidForAdmin(uint32_t flag)
{
    return DataValidator::IsPermissionFlagValidForAdmin(flag);
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Label invalid.");
        return false;
    }
    if (!DataValidator::IsDescValid(permDef.description)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Desc invalid.");
        return false;
    }
    if (!DataValidator::IsBundleNameValid(permDef.bundleName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "BundleName invalid.");
        return false;
    }
    if (!DataValidator::IsPermissionNameValid(permDef.permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName invalid.");
        return false;
    }
    if (!IsGrantModeValid(permDef.grantMode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GrantMode invalid.");
        return false;
    }
    if (!DataValidator::IsAvailableTypeValid(permDef.availableType)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AvailableType invalid.");
        return false;
    }
    if (!DataValidator::IsAplNumValid(permDef.availableLevel)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AvailableLevel invalid.");
        return false;
    }
    return true;
}

bool PermissionValidator::IsPermissionAvailable(ATokenTypeEnum tokenType, const std::string& permissionName)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "TokenType is %{public}d.", tokenType);
    if (tokenType == TOKEN_HAP) {
        if (!IsPermissionValidForHap(permissionName)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "%{public}s is not defined for hap.", permissionName.c_str());
            return false;
        }
    }
    // permission request for TOKEN_NATIVE process is going to be check when the permission request way is normalized.
    return true;
}

bool PermissionValidator::IsPermissionStateValid(const PermissionStatus& permState)
{
    if (!DataValidator::IsPermissionNameValid(permState.permissionName)) {
        return false;
    }
    if (!IsGrantStatusValid(permState.grantStatus) || !IsPermissionFlagValid(permState.grantFlag)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GrantStatus or grantFlag is invalid");
        return false;
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

void PermissionValidator::FilterInvalidPermissionState(ATokenTypeEnum tokenType, bool doPermAvailableCheck,
    const std::vector<PermissionStatus>& permList, std::vector<PermissionStatus>& result)
{
    std::set<std::string> permStateSet;
    for (auto it = permList.begin(); it != permList.end(); ++it) {
        std::string permName = it->permissionName;
        PermissionStatus res = *it;
        if (!IsPermissionStateValid(res) || permStateSet.count(permName) != 0) {
            continue;
        }
        if (doPermAvailableCheck && !IsPermissionAvailable(tokenType, permName)) {
            continue;
        }
        permStateSet.insert(permName);
        result.emplace_back(res);
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
