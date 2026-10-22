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

#include "automation_control_switch_manager.h"

#include <chrono>
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_info_utils.h"
#include "atm_data_type.h"
#include "data_validator.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "token_field_const.h"
#include "tokenid_attributes.h"
#include "automation_control_types.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t AUTOMATION_CONTROL_STATUS_DISABLED = 0;
constexpr int32_t AUTOMATION_CONTROL_STATUS_ENABLED = 1;

std::string BuildTargetStatusLogString(const std::vector<uint32_t>& tokenIds,
    const std::vector<int32_t>& statusList)
{
    std::string str;
    for (size_t i = 0; i < tokenIds.size(); ++i) {
        str += std::to_string(tokenIds[i]) + ":" + std::to_string((i < statusList.size()) ? statusList[i] : 0) + " ";
    }
    return str;
}

std::string BuildIntVectorLogString(const std::vector<int32_t>& values)
{
    std::string str;
    for (size_t i = 0; i < values.size(); ++i) {
        str += std::to_string(values[i]) + " ";
    }
    return str;
}
}

AutomationControlSwitchManager& AutomationControlSwitchManager::GetInstance()
{
    static AutomationControlSwitchManager instance;
    return instance;
}

bool AutomationControlSwitchManager::IsHapTokenIdExist(AccessTokenID tokenId) const
{
    auto info = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    return info != nullptr && !info->IsRemote();
}

std::string AutomationControlSwitchManager::ResolveBundleName(AccessTokenID tokenId) const
{
    TokenIdStatus status;
    auto info = AccessTokenInfoManager::GetInstance().GetHapTokenInfoAndStatus(tokenId, status);
    if (info != nullptr && !info->IsRemote() && status == TokenIdStatus::ACTIVE) {
        return info->GetBundleName();
    }
    return "";
}

void AutomationControlSwitchManager::BuildSetBatch(uint32_t controllerTokenId,
    const std::vector<uint32_t>& targetTokenIds, const std::vector<int32_t>& statusList,
    std::vector<int32_t>& results, SetBatchData& batch)
{
    int64_t timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::vector<GenericValues> addValues;

    for (size_t i = 0; i < targetTokenIds.size(); ++i) {
        uint32_t targetId = targetTokenIds[i];
        int32_t inStatus = (i < statusList.size()) ? statusList[i] : 0;
        if (!IsHapTokenIdExist(targetId)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Target tokenId %{public}u not exist or not HAP.", targetId);
            results.emplace_back(static_cast<int32_t>(AUTOMATION_CONTROL_SET_TOKEN_ID_NOT_EXIST));
            continue;
        }

        int32_t status = (inStatus == AUTOMATION_CONTROL_ENABLED)
            ? AUTOMATION_CONTROL_STATUS_ENABLED : AUTOMATION_CONTROL_STATUS_DISABLED;

        GenericValues condition;
        condition.Put(TokenFiledConst::FIELD_AUTOMATION_SOURCE_TOKEN_ID,
            static_cast<int32_t>(controllerTokenId));
        condition.Put(TokenFiledConst::FIELD_AUTOMATION_TARGET_TOKEN_ID,
            static_cast<int32_t>(targetId));
        AccessTokenInfoUtils::GenerateDelInfoToVec(
            AtmDataType::ACCESSTOKEN_CONTROL_SWITCH, condition, batch.delInfoVec);

        GenericValues addValue;
        addValue.Put(TokenFiledConst::FIELD_AUTOMATION_SOURCE_TOKEN_ID, static_cast<int32_t>(controllerTokenId));
        addValue.Put(TokenFiledConst::FIELD_AUTOMATION_TARGET_TOKEN_ID, static_cast<int32_t>(targetId));
        addValue.Put(TokenFiledConst::FIELD_AUTOMATION_STATUS, status);
        addValue.Put(TokenFiledConst::FIELD_AUTOMATION_TIMESTAMP, timestamp);
        addValues.emplace_back(addValue);

        batch.validList.emplace_back(targetId, status);
        results.emplace_back(static_cast<int32_t>(AUTOMATION_CONTROL_SET_SUCCESS));
    }

    AccessTokenInfoUtils::GenerateAddInfoToVec(
        AtmDataType::ACCESSTOKEN_CONTROL_SWITCH, addValues, batch.addInfoVec);
}

int32_t AutomationControlSwitchManager::SetAutomationControlStatus(uint32_t controllerTokenId,
    const std::vector<uint32_t>& targetTokenIds, const std::vector<int32_t>& statusList,
    std::vector<int32_t>& results)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "controller=%{public}u, targets=%{public}s",
        controllerTokenId, BuildTargetStatusLogString(targetTokenIds, statusList).c_str());
    results.clear();
    results.reserve(targetTokenIds.size());

    if (controllerTokenId == 0 || !DataValidator::IsListSizeValid(targetTokenIds.size())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "invalid param: controller=0 or list invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (targetTokenIds.size() != statusList.size()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Size mismatch: targets=%{public}zu, status=%{public}zu.",
            targetTokenIds.size(), statusList.size());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    for (int32_t s : statusList) {
        if (s != AUTOMATION_CONTROL_DISABLED && s != AUTOMATION_CONTROL_ENABLED) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Invalid status: %{public}d, must be 0(DISABLED) or 1(ENABLED).", s);
            return AccessTokenError::ERR_PARAM_INVALID;
        }
    }
    if (!IsHapTokenIdExist(controllerTokenId)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Controller tokenId %{public}u not exist or not HAP.", controllerTokenId);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    std::lock_guard<std::mutex> lock(switchCacheMutex_);
    // Lazy load: fetch controller data from DB if not yet cached
    if (switchCache_.find(controllerTokenId) == switchCache_.end()) {
        int32_t loadRet = LoadControllerFromDb(controllerTokenId);
        if (loadRet != RET_SUCCESS) {
            return loadRet;
        }
    }

    SetBatchData batch;
    BuildSetBatch(controllerTokenId, targetTokenIds, statusList, results, batch);

    if (!batch.validList.empty()) {
        int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(batch.delInfoVec, batch.addInfoVec);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "DeleteAndInsertValues failed, ret=%{public}d.", ret);
            results.clear();
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }

        for (const auto& [targetId, status] : batch.validList) {
            switchCache_[controllerTokenId][targetId] = status;
        }
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Set success results=%{public}s", BuildIntVectorLogString(results).c_str());
    return RET_SUCCESS;
}

int32_t AutomationControlSwitchManager::GetAutomationControlTargets(uint32_t controllerTokenId,
    std::vector<uint32_t>& targetTokenIds, std::vector<int32_t>& statusList,
    std::vector<std::string>& bundleNames)
{
    targetTokenIds.clear();
    statusList.clear();
    bundleNames.clear();
    if (!IsHapTokenIdExist(controllerTokenId)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Controller tokenId %{public}u not exist or not HAP.", controllerTokenId);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    std::lock_guard<std::mutex> lock(switchCacheMutex_);
    // Lazy load: fetch controller data from DB if not yet cached
    if (switchCache_.find(controllerTokenId) == switchCache_.end()) {
        int32_t loadRet = LoadControllerFromDb(controllerTokenId);
        if (loadRet != RET_SUCCESS) {
            return loadRet;
        }
    }
    auto it = switchCache_.find(controllerTokenId);
    if (it == switchCache_.end()) {
        return RET_SUCCESS;
    }
    for (const auto& [targetId, status] : it->second) {
        std::string name = ResolveBundleName(targetId);
        // Skip non-ACTIVE tokens (e.g. RESERVED after uninstall-with-data-retain)
        if (name.empty()) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Target tokenId %{public}u skipped: not ACTIVE in HapTokenInfo.", targetId);
            continue;
        }
        targetTokenIds.emplace_back(targetId);
        statusList.emplace_back(status);
        bundleNames.emplace_back(name);
    }
    return RET_SUCCESS;
}

int32_t AutomationControlSwitchManager::GetAutomationControlControllers(uint32_t targetTokenId,
    std::vector<uint32_t>& controllerTokenIds, std::vector<std::string>& bundleNames)
{
    controllerTokenIds.clear();
    bundleNames.clear();
    if (!IsHapTokenIdExist(targetTokenId)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Target tokenId %{public}u not exist or not HAP.", targetTokenId);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_AUTOMATION_TARGET_TOKEN_ID,
        static_cast<int32_t>(targetTokenId));
    condition.Put(TokenFiledConst::FIELD_AUTOMATION_STATUS, AUTOMATION_CONTROL_STATUS_ENABLED);
    std::vector<GenericValues> records;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_CONTROL_SWITCH, condition, records);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Find controllers failed, target=%{public}u, ret=%{public}d.", targetTokenId, ret);
        return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
    }
    for (const auto& record : records) {
        AccessTokenID controllerId = static_cast<AccessTokenID>(
            record.Get(TokenFiledConst::FIELD_AUTOMATION_SOURCE_TOKEN_ID).GetInt());
        std::string name = ResolveBundleName(controllerId);
        // Skip non-ACTIVE tokens (e.g. RESERVED after uninstall-with-data-retain)
        if (name.empty()) {
            LOGW(ATM_DOMAIN, ATM_TAG,
                "Controller tokenId %{public}u skipped: not ACTIVE in HapTokenInfo.", controllerId);
            continue;
        }
        controllerTokenIds.emplace_back(controllerId);
        bundleNames.emplace_back(name);
    }
    return RET_SUCCESS;
}

void AutomationControlSwitchManager::ClearByTokenId(uint32_t tokenId)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ClearByTokenId=%{public}u.", tokenId);
    std::lock_guard<std::mutex> lock(switchCacheMutex_);
    switchCache_.erase(tokenId);
    for (auto& [controller, innerMap] : switchCache_) {
        innerMap.erase(tokenId);
    }
}

int32_t AutomationControlSwitchManager::LoadControllerFromDb(AccessTokenID controllerId)
{
    // Caller already holds switchCacheMutex_
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_AUTOMATION_SOURCE_TOKEN_ID,
        static_cast<int32_t>(controllerId));
    std::vector<GenericValues> records;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_CONTROL_SWITCH, condition, records);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "LoadControllerFromDb failed, controller=%{public}u, ret=%{public}d.",
            controllerId, ret);
        return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
    }
    switchCache_[controllerId].clear();
    for (const auto& record : records) {
        AccessTokenID targetId = static_cast<AccessTokenID>(
            record.Get(TokenFiledConst::FIELD_AUTOMATION_TARGET_TOKEN_ID).GetInt());
        int32_t status = record.Get(TokenFiledConst::FIELD_AUTOMATION_STATUS).GetInt();
        switchCache_[controllerId][targetId] = status;
    }
    return RET_SUCCESS;
}

int32_t AutomationControlSwitchManager::CheckAccess(uint32_t controllerTokenId,
    const std::vector<uint32_t>& targetList, std::vector<int32_t>& decisionResults)
{
    decisionResults.clear();
    decisionResults.reserve(targetList.size());

    if (controllerTokenId == 0 || !DataValidator::IsListSizeValid(targetList.size())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "invalid param: controller=0 or list invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!IsHapTokenIdExist(controllerTokenId)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Controller tokenId %{public}u not exist or not HAP.", controllerTokenId);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    std::lock_guard<std::mutex> lock(switchCacheMutex_);
    // Lazy load: fetch controller data from DB if not yet cached
    if (switchCache_.find(controllerTokenId) == switchCache_.end()) {
        int32_t loadRet = LoadControllerFromDb(controllerTokenId);
        if (loadRet != RET_SUCCESS) {
            return loadRet;
        }
    }
    auto it = switchCache_.find(controllerTokenId);
    for (uint32_t targetId : targetList) {
        if (!IsHapTokenIdExist(targetId)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Target tokenId %{public}u not exist or not HAP.", targetId);
            decisionResults.emplace_back(static_cast<int32_t>(TARGET_NOT_EXIST));
            continue;
        }
        if (it == switchCache_.end()) {
            decisionResults.emplace_back(static_cast<int32_t>(POPUP_NEEDED));
            continue;
        }
        auto innerIt = it->second.find(targetId);
        if (innerIt == it->second.end()) {
            decisionResults.emplace_back(static_cast<int32_t>(POPUP_NEEDED));
        } else if (innerIt->second == AUTOMATION_CONTROL_STATUS_ENABLED) {
            decisionResults.emplace_back(static_cast<int32_t>(NO_POPUP_NEEDED_GRANTED));
        } else {
            decisionResults.emplace_back(static_cast<int32_t>(NO_POPUP_NEEDED_DENIED));
        }
    }
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
