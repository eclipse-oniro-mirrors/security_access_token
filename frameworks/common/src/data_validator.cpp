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

#include "data_validator.h"

#include "access_token.h"
#include "accesstoken_common_log.h"
#include "permission_used_request.h"
#include "permission_used_type.h"
#include "privacy_param.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

bool DataValidator::IsBundleNameValid(const std::string& bundleName)
{
    return !bundleName.empty() && (bundleName.length() <= MAX_LENGTH);
}

bool DataValidator::IsLabelValid(const std::string& label)
{
    return label.length() <= MAX_LENGTH;
}

bool DataValidator::IsDescValid(const std::string& desc)
{
    return desc.length() <= MAX_LENGTH;
}

bool DataValidator::IsPermissionNameValid(const std::string& permissionName)
{
    if (permissionName.empty() || (permissionName.length() > MAX_LENGTH)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid perm length(%{public}d).", static_cast<int32_t>(permissionName.length()));
        return false;
    }
    return true;
}

bool DataValidator::IsUserIdValid(const int userId)
{
    return userId >= 0;
}

bool DataValidator::IsAclExtendedMapSizeValid(const std::map<std::string, std::string>& aclExtendedMap)
{
    if (aclExtendedMap.size() > MAX_EXTENDED_MAP_SIZE) {
        return false;
    }
    return true;
}

bool DataValidator::IsAclExtendedMapContentValid(const std::string& permissionName, const std::string& value)
{
    if (!IsPermissionNameValid(permissionName)) {
        return false;
    }

    if (value.empty() || (value.length() > MAX_VALUE_LENGTH)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid value length(%{public}d).", static_cast<int32_t>(value.length()));
        return false;
    }
    return true;
}

bool DataValidator::IsToggleStatusValid(const uint32_t status)
{
    return ((status == PermissionRequestToggleStatus::CLOSED) ||
            (status == PermissionRequestToggleStatus::OPEN));
}

bool DataValidator::IsAppIDDescValid(const std::string& appIDDesc)
{
    return !appIDDesc.empty() && (appIDDesc.length() <= MAX_APPIDDESC_LENGTH);
}

bool DataValidator::IsDomainValid(const std::string& domain)
{
    return !domain.empty() && (domain.length() <= MAX_LENGTH);
}

bool DataValidator::IsAplNumValid(const int apl)
{
    return (apl == APL_NORMAL || apl == APL_SYSTEM_BASIC || apl == APL_SYSTEM_CORE);
}

bool DataValidator::IsAvailableTypeValid(const int availableType)
{
    return (availableType == NORMAL || availableType == MDM);
}

bool DataValidator::IsProcessNameValid(const std::string& processName)
{
    return !processName.empty() && (processName.length() <= MAX_LENGTH);
}

bool DataValidator::IsDeviceIdValid(const std::string& deviceId)
{
    if (deviceId.empty() || (deviceId.length() > MAX_LENGTH)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid deviceId length(%{public}d).", static_cast<int32_t>(deviceId.length()));
        return false;
    }
    return true;
}

bool DataValidator::IsDcapValid(const std::string& dcap)
{
    return !dcap.empty() && (dcap.length() <= MAX_DCAP_LENGTH);
}

bool DataValidator::IsPermissionFlagValid(uint32_t flag)
{
    uint32_t unmaskedFlag =
        flag & (~PermissionFlag::PERMISSION_GRANTED_BY_POLICY);
    return unmaskedFlag == PermissionFlag::PERMISSION_DEFAULT_FLAG ||
        unmaskedFlag == PermissionFlag::PERMISSION_USER_SET ||
        unmaskedFlag == PermissionFlag::PERMISSION_USER_FIXED ||
        unmaskedFlag == PermissionFlag::PERMISSION_SYSTEM_FIXED ||
        unmaskedFlag == PermissionFlag::PERMISSION_COMPONENT_SET ||
        unmaskedFlag == PermissionFlag::PERMISSION_POLICY_FIXED ||
        unmaskedFlag == PermissionFlag::PERMISSION_ALLOW_THIS_TIME;
}

bool DataValidator::IsTokenIDValid(AccessTokenID id)
{
    if (id == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid token.");
        return false;
    }
    return true;
}

bool DataValidator::IsDlpTypeValid(int dlpType)
{
    return ((dlpType == DLP_COMMON) || (dlpType == DLP_READ) || (dlpType == DLP_FULL_CONTROL));
}

bool DataValidator::IsPermissionUsedFlagValid(uint32_t flag)
{
    return ((flag == FLAG_PERMISSION_USAGE_SUMMARY) ||
            (flag == FLAG_PERMISSION_USAGE_DETAIL) ||
            (flag == FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_LOCKED) ||
            (flag == FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_UNLOCKED) ||
            (flag == FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_BACKGROUND) ||
            (flag == FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_FOREGROUND));
}

bool DataValidator::IsPermissionUsedTypeValid(uint32_t type)
{
    if ((type != NORMAL_TYPE) && (type != PICKER_TYPE) && (type != SECURITY_COMPONENT_TYPE)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid type(%{public}d).", type);
        return false;
    }
    return true;
}

bool DataValidator::IsPolicyTypeValid(uint32_t type)
{
    PolicyType policyType = static_cast<PolicyType>(type);
    if ((policyType != EDM) && (policyType != PRIVACY) && (policyType != TEMPORARY)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid type(%{public}d).", type);
        return false;
    }
    return true;
}

bool DataValidator::IsCallerTypeValid(uint32_t type)
{
    CallerType callerType = static_cast<CallerType>(type);
    if ((callerType != MICROPHONE) && (callerType != CAMERA)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid type(%{public}d).", type);
        return false;
    }
    return true;
}

bool DataValidator::IsHapCaller(AccessTokenID id)
{
    AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&id);
    ATokenTypeEnum type = static_cast<ATokenTypeEnum>(idInner->type);
    if (type != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Not hap(%{public}d).", id);
        return false;
    }
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
