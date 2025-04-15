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

#include "constant_common.h"
#include "data_validator.h"
#include "privacy_error.h"
#include "privacy_manager_client.h"
#include "time_util.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const int64_t MERGE_TIMESTAMP = 200; // 200ms
std::mutex g_lockCache;
struct RecordCache {
    int32_t successCount = 0;
    int64_t timespamp = 0;
};
std::map<std::string, RecordCache> g_recordMap;
}
static std::string GetRecordUniqueStr(const AddPermParamInfo& record)
{
    return std::to_string(record.tokenId) + "_" + record.permissionName + "_" + std::to_string(record.type);
}

bool FindAndInsertRecord(const AddPermParamInfo& record)
{
    std::lock_guard<std::mutex> lock(g_lockCache);
    std::string newRecordStr = GetRecordUniqueStr(record);
    int64_t curTimestamp = TimeUtil::GetCurrentTimestamp();
    auto iter = g_recordMap.find(newRecordStr);
    if (iter == g_recordMap.end()) {
        g_recordMap[newRecordStr].successCount = record.successCount;
        g_recordMap[newRecordStr].timespamp = curTimestamp;
        return false;
    }
    if (curTimestamp - iter->second.timespamp >= MERGE_TIMESTAMP) {
        g_recordMap[newRecordStr].successCount = record.successCount;
        g_recordMap[newRecordStr].timespamp = curTimestamp;
        return false;
    }
    if (iter->second.successCount == 0 && record.successCount != 0) {
        g_recordMap[newRecordStr].successCount += record.successCount;
        g_recordMap[newRecordStr].timespamp = curTimestamp;
        return false;
    }
    g_recordMap[newRecordStr].successCount += record.successCount;
    g_recordMap[newRecordStr].timespamp = curTimestamp;
    return true;
}

int32_t PrivacyKit::AddPermissionUsedRecord(AccessTokenID tokenID, const std::string& permissionName,
    int32_t successCount, int32_t failCount, bool asyncMode)
{
    AddPermParamInfo info;
    info.tokenId = tokenID;
    info.permissionName = permissionName;
    info.successCount = successCount;
    info.failCount = failCount;
    return AddPermissionUsedRecord(info, asyncMode);
}

int32_t PrivacyKit::AddPermissionUsedRecord(const AddPermParamInfo& info, bool asyncMode)
{
    if ((!DataValidator::IsTokenIDValid(info.tokenId)) ||
        (!DataValidator::IsPermissionNameValid(info.permissionName)) ||
        (info.successCount < 0 || info.failCount < 0) ||
        (!DataValidator::IsPermissionUsedTypeValid(info.type))) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsHapCaller(info.tokenId)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }

    if (!FindAndInsertRecord(info)) {
        int32_t ret = PrivacyManagerClient::GetInstance().AddPermissionUsedRecord(info, asyncMode);
        if (ret == PrivacyError::PRIVACY_TOGGELE_RESTRICTED) {
            std::lock_guard<std::mutex> lock(g_lockCache);
            std::string recordStr = GetRecordUniqueStr(info);
            g_recordMap.erase(recordStr);
            return RET_SUCCESS;
        }
        return ret;
    }

    return RET_SUCCESS;
}

int32_t PrivacyKit::SetPermissionUsedRecordToggleStatus(int32_t userID, bool status)
{
    if (!DataValidator::IsUserIdValid(userID)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().SetPermissionUsedRecordToggleStatus(userID, status);
}

int32_t PrivacyKit::GetPermissionUsedRecordToggleStatus(int32_t userID, bool& status)
{
    if (!DataValidator::IsUserIdValid(userID)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().GetPermissionUsedRecordToggleStatus(userID, status);
}

int32_t PrivacyKit::StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName, int32_t pid,
    PermissionUsedType type)
{
    if ((!DataValidator::IsTokenIDValid(tokenID)) ||
        (!DataValidator::IsPermissionNameValid(permissionName)) ||
        (!DataValidator::IsPermissionUsedTypeValid(type))) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsHapCaller(tokenID)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().StartUsingPermission(tokenID, pid, permissionName, type);
}

int32_t PrivacyKit::StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName,
    const std::shared_ptr<StateCustomizedCbk>& callback, int32_t pid, PermissionUsedType type)
{
    if ((!DataValidator::IsTokenIDValid(tokenID)) ||
        (!DataValidator::IsPermissionNameValid(permissionName)) ||
        (!DataValidator::IsPermissionUsedTypeValid(type))) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsHapCaller(tokenID)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().StartUsingPermission(tokenID, pid, permissionName, callback, type);
}

int32_t PrivacyKit::StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName, int32_t pid)
{
    if (!DataValidator::IsTokenIDValid(tokenID) || !DataValidator::IsPermissionNameValid(permissionName)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsHapCaller(tokenID)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().StopUsingPermission(tokenID, pid, permissionName);
}

int32_t PrivacyKit::RemovePermissionUsedRecords(AccessTokenID tokenID)
{
    if (!DataValidator::IsTokenIDValid(tokenID)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsHapCaller(tokenID)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().RemovePermissionUsedRecords(tokenID);
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

bool PrivacyKit::IsAllowedUsingPermission(AccessTokenID tokenID, const std::string& permissionName, int32_t pid)
{
    if (!DataValidator::IsTokenIDValid(tokenID) && !DataValidator::IsPermissionNameValid(permissionName)) {
        return false;
    }
    return PrivacyManagerClient::GetInstance().IsAllowedUsingPermission(tokenID, permissionName, pid);
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
int32_t PrivacyKit::RegisterSecCompEnhance(const SecCompEnhanceData& enhance)
{
    return PrivacyManagerClient::GetInstance().RegisterSecCompEnhance(enhance);
}

int32_t PrivacyKit::UpdateSecCompEnhance(int32_t pid, uint32_t seqNum)
{
    return PrivacyManagerClient::GetInstance().UpdateSecCompEnhance(pid, seqNum);
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

int32_t PrivacyKit::GetPermissionUsedTypeInfos(const AccessTokenID tokenId, const std::string& permissionName,
    std::vector<PermissionUsedTypeInfo>& results)
{
    if (permissionName.empty()) {
        return PrivacyManagerClient::GetInstance().GetPermissionUsedTypeInfos(tokenId, permissionName, results);
    }

    if (!DataValidator::IsPermissionNameValid(permissionName)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().GetPermissionUsedTypeInfos(tokenId, permissionName, results);
}

int32_t PrivacyKit::SetMutePolicy(uint32_t policyType, uint32_t callerType, bool isMute, AccessTokenID tokenID)
{
    if (!DataValidator::IsPolicyTypeValid(policyType) ||
        !DataValidator::IsCallerTypeValid(callerType) ||
        (tokenID == 0)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().SetMutePolicy(policyType, callerType, isMute, tokenID);
}

int32_t PrivacyKit::SetHapWithFGReminder(uint32_t tokenId, bool isAllowed)
{
    if (!DataValidator::IsTokenIDValid(tokenId)) {
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return PrivacyManagerClient::GetInstance().SetHapWithFGReminder(tokenId, isAllowed);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
