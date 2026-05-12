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
#include "hisysevent_adapter.h"
#include "ipc_skeleton.h"
#include "permission_map.h"
#include "permission_validator.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t BASE_USER_RANGE = 200000;
static const char* APP_TRACKING_CONSENT = "ohos.permission.APP_TRACKING_CONSENT";
}

PermissionRequestToggleManager& PermissionRequestToggleManager::GetInstance()
{
    static PermissionRequestToggleManager instance;
    return instance;
}

int32_t PermissionRequestToggleManager::ResolveUserId(int32_t userID) const
{
    if (userID != 0) {
        return userID;
    }
    return IPCSkeleton::GetCallingUid() / BASE_USER_RANGE;
}

int32_t PermissionRequestToggleManager::ValidatePermissionForToggle(
    const std::string& permissionName, int32_t userID) const
{
    if (!PermissionValidator::IsUserIdValid(userID) || !PermissionValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid parameter(userId=%{public}d, perm=%{public}s).",
            userID, permissionName.c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!IsDefinedPermission(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission=%{public}s is not defined.", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    if (!IsUserGrantPermission(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Only support permissions of user_grant.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return RET_SUCCESS;
}

int32_t PermissionRequestToggleManager::AddPermRequestToggleStatusToDb(
    int32_t userID, const std::string& permissionName, int32_t status)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_USER_ID, userID);
    condition.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);

    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateDelInfoToVec(
        AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, condition, delInfoVec);

    std::vector<GenericValues> values;
    condition.Put(TokenFiledConst::FIELD_REQUEST_TOGGLE_STATUS, status);
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

int32_t PermissionRequestToggleManager::SetPermissionRequestToggleStatus(
    const std::string& permissionName, uint32_t status, int32_t userID)
{
    userID = ResolveUserId(userID);

    LOGI(ATM_DOMAIN, ATM_TAG, "UserID=%{public}u, permission=%{public}s, status=%{public}d", userID,
        permissionName.c_str(), status);
    int32_t ret = ValidatePermissionForToggle(permissionName, userID);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    if (!PermissionValidator::IsToggleStatusValid(status)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid status(userId=%{public}d, perm=%{public}s, status=%{public}d).",
            userID, permissionName.c_str(), status);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    ret = AddPermRequestToggleStatusToDb(userID, permissionName, status);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    ReportPermDialogStatusEvent(userID, permissionName, status);

    return RET_SUCCESS;
}

int32_t PermissionRequestToggleManager::FindPermRequestToggleStatusFromDb(
    int32_t userID, const std::string& permissionName)
{
    std::vector<GenericValues> result;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_USER_ID, userID);
    conditionValue.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);

    (void)AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_REQUEST_TOGGLE_STATUS, conditionValue,
        result);
    if (result.empty()) {
        return (permissionName == APP_TRACKING_CONSENT) ?
            PermissionRequestToggleStatus::CLOSED : PermissionRequestToggleStatus::OPEN;
    }
    return result[0].GetInt(TokenFiledConst::FIELD_REQUEST_TOGGLE_STATUS);
}

int32_t PermissionRequestToggleManager::GetPermissionRequestToggleStatus(
    const std::string& permissionName, uint32_t& status, int32_t userID)
{
    userID = ResolveUserId(userID);

    LOGI(ATM_DOMAIN, ATM_TAG, "UserID=%{public}u, permissionName=%{public}s", userID, permissionName.c_str());
    int32_t ret = ValidatePermissionForToggle(permissionName, userID);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    status = static_cast<uint32_t>(FindPermRequestToggleStatusFromDb(userID, permissionName));
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
