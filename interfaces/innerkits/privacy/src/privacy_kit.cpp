/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "constant_common.h"
#include "data_validator.h"
#include "privacy_error.h"
#include "privacy_manager_client.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyKit"};
} // namespace

int32_t PrivacyKit::AddPermissionUsedRecord(AccessTokenID tokenID, const std::string& permissionName,
    int32_t successCount, int32_t failCount, bool asyncMode)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID=0x%{public}x, permissionName=%{public}s,",
        tokenID, permissionName.c_str());
    if (!DataValidator::IsTokenIDValid(tokenID) || !DataValidator::IsPermissionNameValid(permissionName) ||
        (successCount < 0 || failCount < 0)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "parameter is invalid");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().AddPermissionUsedRecord(
        tokenID, permissionName, successCount, failCount, asyncMode);
}

int32_t PrivacyKit::StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID=0x%{public}x, permissionName=%{public}s",
        tokenID, permissionName.c_str());
    if (!DataValidator::IsTokenIDValid(tokenID) || !DataValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "parameter is invalid");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().StartUsingPermission(tokenID, permissionName);
}

int32_t PrivacyKit::StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName,
    const std::shared_ptr<StateCustomizedCbk>& callback)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID=0x%{public}x, permissionName=%{public}s, callback",
        tokenID, permissionName.c_str());
    if (!DataValidator::IsTokenIDValid(tokenID) || !DataValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "parameter is invalid");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().StartUsingPermission(tokenID, permissionName, callback);
}

int32_t PrivacyKit::StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID=0x%{public}x, permissionName=%{public}s",
        tokenID, permissionName.c_str());
    if (!DataValidator::IsTokenIDValid(tokenID) || !DataValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "parameter is invalid");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().StopUsingPermission(tokenID, permissionName);
}

int32_t PrivacyKit::RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID=0x%{public}x, deviceID=%{public}s",
        tokenID, ConstantCommon::EncryptDevId(deviceID).c_str());
    if (!DataValidator::IsTokenIDValid(tokenID) && !DataValidator::IsDeviceIdValid(deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "parameter is invalid");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().RemovePermissionUsedRecords(tokenID, deviceID);
}

static bool IsPermissionFlagValid(const PermissionUsedRequest& request)
{
    int64_t begin = request.beginTimeMillis;
    int64_t end = request.endTimeMillis;
    if ((begin < 0) || (end < 0) || (begin > end)) {
        return false;
    }
    return DataValidator::IsPermissionUsedFlagValid(request.flag);
}

int32_t PrivacyKit::GetPermissionUsedRecords(const PermissionUsedRequest& request, PermissionUsedResult& result)
{
    if (!IsPermissionFlagValid(request)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().GetPermissionUsedRecords(request, result);
}

int32_t PrivacyKit::GetPermissionUsedRecords(
    const PermissionUsedRequest& request, const sptr<OnPermissionUsedRecordCallback>& callback)
{
    if (!IsPermissionFlagValid(request)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().GetPermissionUsedRecords(request, callback);
}

int32_t PrivacyKit::RegisterPermActiveStatusCallback(const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback)
{
    return PrivacyManagerClient::GetInstance().RegisterPermActiveStatusCallback(callback);
}

int32_t PrivacyKit::UnRegisterPermActiveStatusCallback(const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback)
{
    return PrivacyManagerClient::GetInstance().UnRegisterPermActiveStatusCallback(callback);
}

bool PrivacyKit::IsAllowedUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    if (!DataValidator::IsTokenIDValid(tokenID) && !DataValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "parameter is invalid");
        return false;
    }
    return PrivacyManagerClient::GetInstance().IsAllowedUsingPermission(tokenID, permissionName);
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
int32_t PrivacyKit::RegisterSecCompEnhance(const SecCompEnhanceData& enhance)
{
    return PrivacyManagerClient::GetInstance().RegisterSecCompEnhance(enhance);
}

int32_t PrivacyKit::GetSecCompEnhance(int32_t pid, SecCompEnhanceData& enhance)
{
    return PrivacyManagerClient::GetInstance().GetSecCompEnhance(pid, enhance);
}

int32_t PrivacyKit::GetSpecialSecCompEnhance(const std::string& bundleName,
    std::vector<SecCompEnhanceData>& enhanceList)
{
    return PrivacyManagerClient::GetInstance().
        GetSpecialSecCompEnhance(bundleName, enhanceList);
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
