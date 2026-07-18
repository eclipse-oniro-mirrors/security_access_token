/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "permission_request_toggle_manager.h"

#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_info_utils.h"
#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
#include "account_error_no.h"
#include "os_account_manager_lite.h"
#endif
#include "hisysevent_adapter.h"
#include "ipc_skeleton.h"
#include "permission_map.h"
#include "permission_validator.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const char* APP_TRACKING_CONSENT = "ohos.permission.APP_TRACKING_CONSENT";
constexpr int32_t LEGACY_SUBPROFILE_ID = -1;

#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
int32_t ValidateSubProfileIdForToggle(int32_t userID, int32_t subProfileId)
{
    if (subProfileId < 0) {
        return RET_SUCCESS;
    }
    int32_t localUserId = LEGACY_SUBPROFILE_ID;
    int32_t ret = OHOS::AccountSA::OsAccountManagerLite::GetOsAccountLocalIdForSubProfile(
        subProfileId, localUserId);
    if (ret == ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SubProfile does not exist, subProfileId=%{public}d.", subProfileId);
        return AccessTokenError::ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST;
    }
    if (ret != ERR_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get userid failed, err=%{public}d.", ret);
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return (localUserId == userID) ? RET_SUCCESS : AccessTokenError::ERR_PERMISSION_REQUEST_TOGGLE_SUBPROFILE_NOT_EXIST;
}

int32_t ValidateStorageModeConflict(int32_t userID, const std::string& permissionName, int32_t subProfileId)
{
    std::vector<GenericValues> records;
    int32_t ret = PermissionRequestToggleManager::GetInstance().FindPermRequestToggleStatusRecordsFromDb(
        userID, permissionName, LEGACY_SUBPROFILE_ID, records);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    const int32_t targetSubProfileId = (subProfileId >= 0) ? LEGACY_SUBPROFILE_ID : 0;
    return std::any_of(records.begin(), records.end(), [targetSubProfileId, subProfileId](const auto& item) {
        const int32_t recordSubProfileId = item.GetInt(TokenFiledConst::FIELD_SUB_PROFILE_ID);
        return (subProfileId >= 0) ? (recordSubProfileId == targetSubProfileId) :
            (recordSubProfileId >= targetSubProfileId);
    }) ? AccessTokenError::ERR_PERMISSION_REQUEST_TOGGLE_STORAGE_MODE_CONFLICT : RET_SUCCESS;
}
#endif

uint32_t GetDefaultToggleStatus(const std::string& permissionName)
{
    return (permissionName == APP_TRACKING_CONSENT) ? PermissionRequestToggleStatus::CLOSED :
        PermissionRequestToggleStatus::OPEN;
}
}

PermissionRequestToggleManager& PermissionRequestToggleManager::GetInstance()
{
    static PermissionRequestToggleManager instance;
    return instance;
}

int32_t PermissionRequestToggleManager::ValidatePermissionForToggle(
    const std::string& permissionName, int32_t userID) const
{
    if (!PermissionValidator::IsUserIdValid(userID) || !PermissionValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid parameter.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!IsDefinedPermissionInner(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission is not defined.");
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    if (!IsUserGrantPermission(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Only support permissions of user_grant.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return RET_SUCCESS;
}

int32_t PermissionRequestToggleManager::AddPermRequestToggleStatusToDb(
    int32_t userID, const std::string& permissionName, int32_t subProfileId, uint32_t status)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_USER_ID, userID);
    condition.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
    condition.Put(TokenFiledConst::FIELD_SUB_PROFILE_ID, subProfileId);

    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateDelInfoToVec(
        AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, condition, delInfoVec);

    std::vector<GenericValues> values;
    condition.Put(TokenFiledConst::FIELD_REQUEST_TOGGLE_STATUS, static_cast<int32_t>(status));
    values.emplace_back(condition);

    std::vector<AddInfo> addInfoVec;
    AccessTokenInfoUtils::GenerateAddInfoToVec(
        AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, values, addInfoVec);

    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "DeleteAndInsertHap failed, ret %{public}d.", ret);
        return ret;
    }
    return RET_SUCCESS;
}

int32_t PermissionRequestToggleManager::DeletePermRequestToggleStatusFromDb(
    int32_t userID, const std::string& permissionName, int32_t subProfileId)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_USER_ID, userID);
    condition.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
    condition.Put(TokenFiledConst::FIELD_SUB_PROFILE_ID, subProfileId);

    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateDelInfoToVec(
        AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, condition, delInfoVec);
    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, {});
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Delete request toggle status failed, ret=%{public}d.", ret);
    }
    return ret;
}

int32_t PermissionRequestToggleManager::FindPermRequestToggleStatusRecordsFromDb(
    int32_t userID, const std::string& permissionName, int32_t subProfileId, std::vector<GenericValues>& result,
    bool queryAllSubProfileRecords) const
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_USER_ID, userID);
    conditionValue.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
    if (!queryAllSubProfileRecords && subProfileId > LEGACY_SUBPROFILE_ID) {
        conditionValue.Put(TokenFiledConst::FIELD_SUB_PROFILE_ID, subProfileId);
    }
    return AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, conditionValue,
        result);
}

int32_t PermissionRequestToggleManager::SetPermissionRequestToggleStatus(
    const std::string& permissionName, uint32_t status, int32_t userID, int32_t subProfileId)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UserID=%{public}u, permission=%{public}s, status=%{public}d, "
        "subProfileId=%{public}d", userID, permissionName.c_str(), status, subProfileId);
    int32_t ret = ValidatePermissionForToggle(permissionName, userID);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    if (!PermissionValidator::IsToggleStatusValid(status)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid status.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
    subProfileId = (subProfileId < 0) ? LEGACY_SUBPROFILE_ID : subProfileId;
    ret = ValidateSubProfileIdForToggle(userID, subProfileId);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    ret = ValidateStorageModeConflict(userID, permissionName, subProfileId);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Validate storage mode conflict failed, err=%{public}d.", ret);
        return ret;
    }
#else
    subProfileId = LEGACY_SUBPROFILE_ID;
#endif

    const uint32_t defaultStatus = GetDefaultToggleStatus(permissionName);
    ret = (status == defaultStatus) ? DeletePermRequestToggleStatusFromDb(userID, permissionName, subProfileId) :
        AddPermRequestToggleStatusToDb(userID, permissionName, subProfileId, status);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    ReportPermDialogStatusEvent(userID, permissionName, status);

    return RET_SUCCESS;
}

int32_t PermissionRequestToggleManager::FindPermRequestToggleStatusFromDb(
    int32_t userID, const std::string& permissionName, int32_t subProfileId, uint32_t& status)
{
    const uint32_t defaultStatus = GetDefaultToggleStatus(permissionName);
    std::vector<GenericValues> records;
    int32_t ret = FindPermRequestToggleStatusRecordsFromDb(
        userID, permissionName, subProfileId, records, subProfileId != LEGACY_SUBPROFILE_ID);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    if (records.empty()) {
        status = defaultStatus;
        return RET_SUCCESS;
    }

    if (subProfileId == LEGACY_SUBPROFILE_ID) {
        if ((records.size() > 1) ||
            (records[0].GetInt(TokenFiledConst::FIELD_SUB_PROFILE_ID) != LEGACY_SUBPROFILE_ID)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Storage mode conflict, subProfile record exists.");
            return AccessTokenError::ERR_PERMISSION_REQUEST_TOGGLE_LEGACY_QUERY_CONFLICT;
        }
        status = static_cast<uint32_t>(records[0].GetInt(TokenFiledConst::FIELD_REQUEST_TOGGLE_STATUS));
        return RET_SUCCESS;
    }

    uint32_t legacyStatus = defaultStatus;
    for (const auto& item : records) {
        const int32_t currentSubProfileId = item.GetInt(TokenFiledConst::FIELD_SUB_PROFILE_ID);
        const uint32_t currentStatus = static_cast<uint32_t>(item.GetInt(TokenFiledConst::FIELD_REQUEST_TOGGLE_STATUS));
        if (currentSubProfileId == subProfileId) {
            status = currentStatus;
            return RET_SUCCESS;
        }
        if (currentSubProfileId == LEGACY_SUBPROFILE_ID) {
            legacyStatus = currentStatus;
        }
    }
    status = legacyStatus;
    return RET_SUCCESS;
}

int32_t PermissionRequestToggleManager::GetPermissionRequestToggleStatus(
    const std::string& permissionName, uint32_t& status, int32_t userID, int32_t subProfileId)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "UserID=%{public}u, permissionName=%{public}s, subProfileId=%{public}d",
        userID, permissionName.c_str(), subProfileId);
    int32_t ret = ValidatePermissionForToggle(permissionName, userID);
    if (ret != RET_SUCCESS) {
        return ret;
    }
#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
    subProfileId = (subProfileId < 0) ? LEGACY_SUBPROFILE_ID : subProfileId;
    ret = ValidateSubProfileIdForToggle(userID, subProfileId);
    if (ret != RET_SUCCESS) {
        return ret;
    }
#else
    subProfileId = LEGACY_SUBPROFILE_ID;
#endif

    return FindPermRequestToggleStatusFromDb(userID, permissionName, subProfileId, status);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
