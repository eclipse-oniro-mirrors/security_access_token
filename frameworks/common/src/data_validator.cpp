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

#include "data_validator.h"
#include "access_token.h"

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

bool DataValidator::IsPermissionFlagValid(int flag)
{
    uint32_t unmaskedFlag =
        static_cast<uint32_t>(flag) & (~PermissionFlag::PERMISSION_GRANTED_BY_POLICY);

    return unmaskedFlag == PermissionFlag::PERMISSION_DEFAULT_FLAG ||
    unmaskedFlag == PermissionFlag::PERMISSION_USER_SET ||
    unmaskedFlag == PermissionFlag::PERMISSION_USER_FIXED ||
    unmaskedFlag == PermissionFlag::PERMISSION_SYSTEM_FIXED;
}

bool DataValidator::IsTokenIDValid(AccessTokenID id)
{
    return id != 0;
}

bool DataValidator::IsDlpTypeValid(int dlpType)
{
    return ((dlpType == DLP_COMMON) || (dlpType == DLP_READ) || (dlpType == DLP_FULL_CONTROL));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
