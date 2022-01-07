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

#include "data_validator.h"
#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
bool DataValidator::IsBundleNameValid(const std::string& bundleName)
{
    return !bundleName.empty() && (bundleName.length() <= MAX_LENGTH);
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
    return !appIDDesc.empty() && (appIDDesc.length() <= MAX_LENGTH);
}

bool DataValidator::IsDomainValid(const std::string& domain)
{
    return !domain.empty() && (domain.length() <= MAX_LENGTH);
}

bool DataValidator::IsAplNumValid(const int apl)
{
    return (apl == APL_NORMAL || apl == APL_SYSTEM_BASIC || apl == APL_SYSTEM_CORE);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
