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

#include "privacy_kit.h"

#include <string>
#include <vector>

#include "accesstoken_log.h"
#include "privacy_manager_client.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyKit"};
} // namespace

int PrivacyKit::AddPermissionUsedRecord(AccessTokenID tokenID, const std::string& permissionName, int successCount, int failCount)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called, tokenID=0x%{public}x, permissionName=%{public}s, \
        successCount=%{public}d, failCount=%{public}d", __func__, tokenID, permissionName.c_str(), successCount, failCount);
    return PrivacyManagerClient::GetInstance().AddPermissionUsedRecord(tokenID, permissionName, successCount, failCount);
}

int PrivacyKit::StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called, tokenID=0x%{public}x, permissionName=%{public}s",
        __func__, tokenID, permissionName.c_str());
    return PrivacyManagerClient::GetInstance().StartUsingPermission(tokenID, permissionName);
}

int PrivacyKit::StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called, tokenID=0x%{public}x, permissionName=%{public}s",
        __func__, tokenID, permissionName.c_str());
    return PrivacyManagerClient::GetInstance().StopUsingPermission(tokenID, permissionName);
}

int PrivacyKit::RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called", __func__);
    return PrivacyManagerClient::GetInstance().RemovePermissionUsedRecords(tokenID, deviceID);
}

int PrivacyKit::GetPermissionUsedRecords(const PermissionUsedRequest& request, PermissionUsedResult& result)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called", __func__);
    return PrivacyManagerClient::GetInstance().GetPermissionUsedRecords(request, result);
}

int PrivacyKit::GetPermissionUsedRecords(const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called", __func__);
    return PrivacyManagerClient::GetInstance().GetPermissionUsedRecords(request, callback);
}

std::string PrivacyKit::DumpRecordInfo(const std::string& bundleName, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "%{public}s called, bundleName=%{public}s, permissionName=%{public}s",
        __func__, bundleName.c_str(), permissionName.c_str());
    return PrivacyManagerClient::GetInstance().DumpRecordInfo(bundleName, permissionName);
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
