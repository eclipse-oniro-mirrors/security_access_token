/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "delete_bundle_manager.h"

#include <algorithm>
#include "accesstoken_common_log.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_utils.h"
#include "data_validator.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
#ifdef SPM_DATA_ENABLE
constexpr int32_t UNAVAILABLE_UID = -1;
#endif
static const uint32_t TOKEN_RESERVED_FLAG = 0x0004;

DeleteBundleManager::DeleteBundleManager() = default;

DeleteBundleManager::~DeleteBundleManager() = default;

DeleteBundleManager& DeleteBundleManager::GetInstance()
{
    static DeleteBundleManager instance;
    return instance;
}

void DeleteBundleManager::GenerateHapTokenDelInfoVec(
    AccessTokenID tokenID,
    const std::string& bundleName,
    std::vector<DelInfo>& delInfoVec,
    bool includePermissionState)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));

    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_INFO, condition, delInfoVec);

    if (includePermissionState) {
        AccessTokenInfoUtils::GenerateDelInfoToVec(
            AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition, delInfoVec);
    }

    AccessTokenInfoUtils::GenerateDelInfoToVec(
        AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, condition, delInfoVec);
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, condition, delInfoVec);

    if (AccessTokenInfoUtils::IsSystemResource(bundleName)) {
        AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, condition, delInfoVec);
    }
}

int32_t DeleteBundleManager::DeleteReservedToken(AccessTokenID tokenID, const std::string& bundleName)
{
    if (!AccessTokenIDManager::GetInstance().IsReservedTokenId(tokenID)) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteReservedToken: tokenID=%{public}u, bundleName = %{public}s",
        tokenID, bundleName.c_str());
    // Query database to verify bundleName matches
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    std::vector<GenericValues> tokenResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, condition, tokenResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to query token %{public}u from db, err %{public}d.", tokenID, ret);
        return ret;
    }

    if (!tokenResults.empty()) {
        // Verify bundleName matches
        std::string actualBundleName = tokenResults[0].GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
        if (actualBundleName != bundleName) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "BundleName mismatch: tokenID=%{public}u, expected bundleName=%{public}s, actual bundleName=%{public}s",
                tokenID, bundleName.c_str(), actualBundleName.c_str());
            return AccessTokenError::ERR_PARAM_INVALID;
        }
    }
    // If tokenResults is empty, it's a no-op (idempotent operation)

    // 3. Delete from database: ACCESSTOKEN_HAP_INFO and ACCESSTOKEN_PERMISSION_STATE
    std::vector<DelInfo> delInfoVec;
    GenerateHapTokenDelInfoVec(tokenID, bundleName, delInfoVec, true);

    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, {});
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to delete reserved token %{public}u from db, err %{public}d.",
            tokenID, ret);
        return ret;
    }

    // 4. Clear ReservedTokenId
    AccessTokenIDManager::GetInstance().RemoveReservedTokenId(tokenID);
    return RET_SUCCESS;
}

int32_t DeleteBundleManager::RemoveHapTokenInfoFromDb(
    const std::shared_ptr<HapTokenInfoInner>& info, ReservedType type, AccessTokenID id)
{
    AccessTokenID tokenID = info->GetTokenID();

    std::vector<DelInfo> delInfoVec;
    bool includePermissionState = (type != ReservedType::RESERVED_DATA);
    GenerateHapTokenDelInfoVec(tokenID, info->GetBundleName(), delInfoVec, includePermissionState);

    std::vector<AddInfo> addInfoVec;
    if (type != ReservedType::NONE) {
        // Update with reserved flag when type is RESERVED_IDENTITY or RESERVED_DATA
        std::vector<GenericValues> addValues;
        info->GenerateHapInfoValues("", APL_INVALID, addValues); // appid will be refreshed by reinstalled
        if (!addValues.empty()) {
            addValues[0].Remove(TokenFiledConst::FIELD_TOKEN_ATTR);
            addValues[0].Put(TokenFiledConst::FIELD_TOKEN_ATTR,
                static_cast<int32_t>(info->GetAttr() | TOKEN_RESERVED_FLAG));
#ifdef SPM_DATA_ENABLE
            addValues[0].Remove(TokenFiledConst::FIELD_RESERVED);
            addValues[0].Put(TokenFiledConst::FIELD_RESERVED, static_cast<int32_t>(type));
            if (type == ReservedType::RESERVED_IDENTITY) {
                addValues[0].Remove(TokenFiledConst::FIELD_UID);
                addValues[0].Put(TokenFiledConst::FIELD_UID, static_cast<int32_t>(UNAVAILABLE_UID));
            }
#endif
            if (id != tokenID) {
                addValues[0].Remove(TokenFiledConst::FIELD_TOKEN_ID);
                addValues[0].Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(id));
            }
            AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_INFO, addValues, addInfoVec);
        }
    }
    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Id %{public}d DeleteAndInsertHap failed, ret %{public}d.", tokenID, ret);
        return ret;
    }
    return RET_SUCCESS;
}

int32_t DeleteBundleManager::TryCleanBundleInfo(const std::shared_ptr<HapTokenInfoInner>& info)
{
#ifdef SPM_DATA_ENABLE
    std::string bundleName = info->GetBundleName();

    // Query hap_token_info_table for all tokens of this bundle.
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    std::vector<GenericValues> tokenResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, condition, tokenResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to query tokens for bundle %{public}s.", bundleName.c_str());
        return ret;
    }

    // If any token has reserved=0 (active), bundle info must be kept.
    bool needCleanBundleId = true;
    bool needCleanBundleInfo = true;
    int32_t bundleId = UNAVAILABLE_UID;
    (void)AccessTokenIDManager::GetInstance().ExtractBundleId(info->GetUid(), bundleId);

    for (const auto &result : tokenResults) {
        if (AccessTokenInfoUtils::GetReservedTokenTypeDBValue(result) == ReservedType::NONE) {
            needCleanBundleInfo = false;
        }
        if (bundleId == UNAVAILABLE_UID) {
            continue;
        }
        int32_t curBundleId = 0;
        if (AccessTokenIDManager::GetInstance().ExtractBundleId(
            result.GetInt(TokenFiledConst::FIELD_UID), curBundleId) &&
            (bundleId == curBundleId)) {
            needCleanBundleId = false;
        }
    }

    if (needCleanBundleId && info->GetUid() != -1) { // -1: unavaliable uid
        AccessTokenIDManager::GetInstance().RemoveBundleId(info->GetUid());
    }

    if (!needCleanBundleInfo) {
        return RET_SUCCESS;
    }

    // Delete hap_info_table entry.
    GenericValues packageCondition;
    packageCondition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);

    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateDelInfoToVec(
        AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, packageCondition, delInfoVec);
    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, {});
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to delete bundle info for %{public}s, err %{public}d.",
            bundleName.c_str(), ret);
    }
    return ret;
#else
    return RET_SUCCESS;
#endif
}

int32_t DeleteBundleManager::DeleteDataByTokenId(AccessTokenID tokenID, const std::string& bundleName)
{
    // Generate delete info vector for all tables related to this token
    std::vector<DelInfo> delInfoVec;
    GenerateHapTokenDelInfoVec(tokenID, bundleName, delInfoVec, true);

    // Delete from database
    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, {});
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to delete data for token %{public}u, err %{public}d.",
            tokenID, ret);
        return ret;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Successfully deleted all data for token %{public}u.", tokenID);
    return RET_SUCCESS;
}

int32_t DeleteBundleManager::DeleteBundleAndAllTokens(const std::string& bundleName,
    std::vector<AccessTokenID>& activeTokens)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteBundleAndAllTokens: bundleName = %{public}s", bundleName.c_str());
    // 1. Check if there are any non-reserved tokens for this bundle
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    std::vector<GenericValues> tokenResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, condition, tokenResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to query tokens for bundle %{public}s, err %{public}d.",
            bundleName.c_str(), ret);
        return ret;
    }

    // Check for non-reserved tokens
    std::vector<AccessTokenID> tokens;
    activeTokens.clear();
    for (const auto& result : tokenResults) {
        if (AccessTokenInfoUtils::GetReservedTokenTypeDBValue(result) == ReservedType::NONE) {
            LOGW(ATM_DOMAIN, ATM_TAG,
                "Bundle %{public}s has active tokens (reserved=0), cannot delete all reserved tokens.",
                bundleName.c_str());
            // Collect active tokens (reserved=0) that need cache cleanup
            AccessTokenID tokenID = static_cast<AccessTokenID>(result.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
            activeTokens.emplace_back(tokenID);
        }
        AccessTokenID tokenID = static_cast<AccessTokenID>(result.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
        tokens.emplace_back(tokenID);
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteBundleAndAllTokens: bundleName = %{public}s, token size = %{public}zu," \
        "active size = %{public}zu",
        bundleName.c_str(), tokens.size(), activeTokens.size());

    // 2. Delete all reserved tokens for this bundle
    std::vector<DelInfo> delInfoVec;
    for (const auto& tokenID : tokens) {
        // Delete from database: ACCESSTOKEN_HAP_INFO and ACCESSTOKEN_PERMISSION_STATE
        GenerateHapTokenDelInfoVec(tokenID, bundleName, delInfoVec, true);
    }

#ifdef SPM_DATA_ENABLE
    // 3. Delete ACCESSTOKEN_HAP_PACKAGE_INFO
    GenericValues packageCondition;
    packageCondition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    AccessTokenInfoUtils::GenerateDelInfoToVec(
        AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, packageCondition, delInfoVec);
#endif

    // 4. trigger delete
    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, {});
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to delete bundlename %{public}s, err %{public}d.",
            bundleName.c_str(), ret);
        return ret;
    }

    // Clear ReservedTokenId for reserved tokens (reserved != 0)
    for (const auto& tokenID : tokens) {
        // Only release ReservedTokenId for reserved tokens
        // Active tokens (reserved=0) will be handled by caller via cache cleanup
        if (std::find(activeTokens.begin(), activeTokens.end(), tokenID) == activeTokens.end()) {
            AccessTokenIDManager::GetInstance().RemoveReservedTokenId(tokenID);
        }
    }
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
