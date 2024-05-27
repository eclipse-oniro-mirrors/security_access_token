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
#include "permission_used_request.h"
#include "permission_used_type.h"
#include "privacy_param.h"
#include <stdint.h>

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
    return !permissionName.empty() && (permissionName.length() <= MAX_LENGTH);
}

bool DataValidator::IsUserIdValid(const int userId)
{
    return userId >= 0;
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
    return !deviceId.empty() && (deviceId.length() <= MAX_LENGTH);
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
    return id != 0;
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
    return ((type == NORMAL_TYPE) || (type == PICKER_TYPE) || (type == SECURITY_COMPONENT_TYPE));
}

bool DataValidator::IsPolicyTypeValid(uint32_t type)
{
    PolicyType policyType = static_cast<PolicyType>(type);
    return ((policyType == EDM) || (policyType == PRIVACY) || (policyType == TEMPORARY));
}

bool DataValidator::IsCallerTypeValid(uint32_t type)
{
    CallerType callerType = static_cast<CallerType>(type);
    return ((callerType == MICROPHONE) || (callerType == CAMERA));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
