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

#include "migration_verify_helper.h"

#include <memory>
#include <unordered_map>

#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_kit.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_info_utils.h"
#include "data_validator.h"
#include "hap_sign_verify_manager.h"
#include "hap_sign_verify_helper.h"
#include "hap_token_info_inner.h"
#include "permission_constraint_check.h"
#include "permission_data_brief.h"
#include "spm_data_kernel_common.h"
#include "table_item.h"
#include "token_field_const.h"
#include "time_util.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int INVALID_USERID = -1;
}

const TrustedBundleInfoInner& GetBaselineVerifiedInfo(const VerifiedMigrationBundle& verifiedBundle)
{
    return verifiedBundle.verifiedInfos.front();
}

int32_t MigrationVerifyHelper::DoVerifyMigratedBundle(const MigratedInfoIdl& migratedInfo,
    VerifiedMigrationBundle& verifiedBundle)
{
    HapSignVerifyManager& verifyManager = HapSignVerifyManager::GetInstance();
    std::vector<TrustedBundleInfoInner> verifiedInfos;
    int32_t ret = RET_SUCCESS;
    for (const auto& hapPath : migratedInfo.pathList.hapPaths) {
        TrustedBundleInfoInner trustedBundleInfo;
        bool isChanged = false;
        ret = verifyManager.CheckHapsSignInfo(hapPath, Security::Verify::VerifyType::Fast,
            INVALID_USERID, trustedBundleInfo, isChanged);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "CheckHapsSignInfo failed, ret=%{public}d.", ret);
            return ret;
        }
        verifiedInfos.emplace_back(trustedBundleInfo);
    }

    ret = verifyManager.CheckMultipleHaps(verifiedInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "CheckMultipleHaps failed, ret=%{public}d.", ret);
        return ret;
    }
    std::string verifiedBundleName = verifiedInfos.front().GetBundleName();
    if (verifiedBundleName != migratedInfo.bundleName) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, verified bundleName mismatch.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    ret = verifyManager.BuildHapPolicy(verifiedInfos, verifiedBundle.policy, verifiedBundle.installParam);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "BuildHapPolicy failed, ret=%{public}d.", ret);
        return ret;
    }

    HapInfoCheckResult checkResult;
    verifiedBundle.verifiedInfos = verifiedInfos;
    ret = verifyManager.CheckPermissionRequestValid(GetBaselineVerifiedInfo(verifiedBundle),
        verifiedBundle.policy, checkResult);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "CheckPermissionRequestValid failed, ret=%{public}d.", ret);
    }
    return ret;
}

int32_t MigrationVerifyHelper::BuildBundleSignInfo(const MigratedInfoIdl& migratedInfo,
    const VerifiedMigrationBundle& verifiedBundle, BundleSignInfo& bundleSignInfo)
{
    size_t verifiedSize = verifiedBundle.verifiedInfos.size();
    if (migratedInfo.pathList.hapPaths.size() != verifiedSize) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    bundleSignInfo.bundleName = migratedInfo.bundleName;
    bundleSignInfo.isPreInstalled = migratedInfo.pathList.isPreInstalled;
    for (size_t i = 0; i < verifiedSize; ++i) {
        const auto& verifiedInfo = verifiedBundle.verifiedInfos[i];
        bundleSignInfo.moduleNameList.emplace_back(verifiedInfo.GetModuleName());
        bundleSignInfo.pathList.emplace_back(migratedInfo.pathList.hapPaths[i]);
        bundleSignInfo.bundleType.emplace_back(static_cast<uint32_t>(verifiedInfo.GetBundleType()));

        std::vector<uint8_t> persistData;
        if ((verifiedInfo.bootstrapInfo != nullptr) && (verifiedInfo.bootstrapInfo->GetSize() > 0)) {
            uint8_t* data = verifiedInfo.bootstrapInfo->Dump();
            if (data == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Dump bootstrap info failed.");
                return AccessTokenError::ERR_MALLOC_FAILED;
            }
            size_t persistSize = static_cast<size_t>(verifiedInfo.bootstrapInfo->GetSize());
            persistData.assign(data, data + persistSize);
            delete[] data;
        }
        bundleSignInfo.persistDataList.emplace_back(persistData);
    }
    return RET_SUCCESS;
}

int32_t MigrationVerifyHelper::DoBundleInfoOperations(const BundleSignInfo& bundleSignInfo)
{
    std::vector<GenericValues> addValues;
    int32_t ret = bundleSignInfo.ToGenericValues(addValues);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "BundleSignInfo.ToGenericValues failed for %{public}s, ret=%{public}d.",
            bundleSignInfo.bundleName.c_str(), ret);
        return ret;
    }
    std::vector<GenericValues> conditions;
    conditions.reserve(addValues.size());
    for (size_t i = 0;i < addValues.size(); ++i) {
        const auto& value = addValues[i];
        GenericValues cond;
        cond.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleSignInfo.bundleName);
        cond.Put(TokenFiledConst::FIELD_PATH, value.GetString(TokenFiledConst::FIELD_PATH));
        cond.Put(TokenFiledConst::FIELD_MODULE_NAME, GetPlaceholderModuleName(i));
        conditions.emplace_back(cond);
    }
    ret = AccessTokenDbOperator::Modify(
        AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, addValues, conditions);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Replace sign info failed for %{public}s, ret=%{public}d.",
            bundleSignInfo.bundleName.c_str(), ret);
    }
    return RET_SUCCESS;
}

void MigrationVerifyHelper::PrepareHapInfoOperations(const BundleParam& param, const HapPolicy& policy,
    const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos)
{
    std::vector<VariantValue> tokenIdValues;
    tokenIdValues.reserve(cachedInfos.size());
    for (const auto& infoPtr : cachedInfos) {
        tokenIdValues.emplace_back(
            static_cast<int32_t>(infoPtr->GetHapInfoBasic().tokenID));
    }
    std::vector<GenericValues> dbResults;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_INFO, TokenFiledConst::FIELD_TOKEN_ID, tokenIdValues, dbResults);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Batch query hap info failed, ret=%{public}d, skip fix.", ret);
        return;
    }

    std::vector<HapTokenInfoItem> items;
    HapTokenInfoItem::LoadFromDB(dbResults, items);
    std::unordered_map<int32_t, size_t> itemIndexByTokenId;
    for (size_t idx = 0; idx < items.size(); ++idx) {
        itemIndexByTokenId[static_cast<int32_t>(items[idx].tokenId)] = idx;
    }

    for (const auto& infoPtr : cachedInfos) {
        HapTokenInfo hapInfo = infoPtr->GetHapInfoBasic();
        std::vector<GenericValues> hapAddValues;
        auto it = itemIndexByTokenId.find(static_cast<int32_t>(hapInfo.tokenID));
        if (it == itemIndexByTokenId.end()) {
            infoPtr->GenerateHapInfoValues(param.appId, policy.apl, hapAddValues);
        } else {
            HapTokenInfoItem& item = items[it->second];
            bool isFixed = false;
            PermissionConstraintCheck::FixPersistentHapInfo(param, policy, item, isFixed);
            if (!isFixed) {
                continue;
            }
            item.BuildAddValue(hapAddValues);
        }

        GenericValues condition;
        condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(hapInfo.tokenID));
        delInfoVec_.emplace_back(DelInfo {AtmDataType::ACCESSTOKEN_HAP_INFO, condition});
        addInfoVec_.emplace_back(AddInfo {AtmDataType::ACCESSTOKEN_HAP_INFO, hapAddValues});
        LOGI(ATM_DOMAIN, ATM_TAG, "Fixed hap info for tokenId=%{public}u.", hapInfo.tokenID);
    }
}

MigrationVerifyHelper& MigrationVerifyHelper::GetInstance()
{
    static MigrationVerifyHelper instance;
    return instance;
}

int32_t MigrationVerifyHelper::PersistDbInfo(const MigratedInfoIdl& migratedInfo,
    const VerifiedMigrationBundle& verifiedBundle,
    const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos)
{
    BundleSignInfo bundleSignInfo;
    int32_t ret = BuildBundleSignInfo(migratedInfo, verifiedBundle, bundleSignInfo);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "BuildBundleSignInfo failed for %{public}s, ret=%{public}d.",
            migratedInfo.bundleName.c_str(), ret);
        return ret;
    }
    
    ret = DoBundleInfoOperations(bundleSignInfo);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    PrepareHapInfoOperations(verifiedBundle.installParam, verifiedBundle.policy, cachedInfos);

    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec_, addInfoVec_);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Hap info DB persist failed for %{public}s, ret=%{public}d.",
            migratedInfo.bundleName.c_str(), ret);
    }
    return ret;
}

int32_t MigrationVerifyHelper::AddKernelData(const BundleNoCachedInfo& noCachedInfo,
    const std::vector<PermissionWithValue>& extendPermList,
    const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos,
    const std::vector<std::vector<BriefPermData>>& permBriefDataPerToken,
    std::unique_ptr<AddSpmDataTask>& kernelTask)
{
    if (!PermissionKernelUtils::IsKernelSupportSpm()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Spm kernel ops is not supported in current system.");
        kernelTask = nullptr;
        return RET_SUCCESS;
    }
    std::vector<HapTokenInfo> hapInfoCache;
    hapInfoCache.reserve(cachedInfos.size());
    std::vector<SpmDataParam> params;
    params.reserve(cachedInfos.size());
    for (size_t i = 0; i < cachedInfos.size(); ++i) {
        hapInfoCache.emplace_back(cachedInfos[i]->GetHapInfoBasic());
        params.emplace_back(SpmDataParam { hapInfoCache.back(), noCachedInfo,
            permBriefDataPerToken[i], extendPermList });
    }

    kernelTask = std::make_unique<AddSpmDataTask>(params);
    if (kernelTask == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Create AddSpmDataTask failed.");
        return AccessTokenError::ERR_MALLOC_FAILED;
    }
    uint32_t errIndex = 0;
    return kernelTask->Add(errIndex);
}

void MigrationVerifyHelper::FixBriefPermDataPerToken(const VerifiedMigrationBundle& verifiedBundle,
    const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos,
    BundleNoCachedInfo& noCached,
    std::vector<std::vector<BriefPermData>>& fixedPermBriefPerToken)
{
    auto& delInfoVec = GetInstance().delInfoVec_;
    auto& addInfoVec = GetInstance().addInfoVec_;
    std::shared_ptr<BundleInfoInner> innerInfo = std::make_shared<BundleInfoInner>();
    AccessTokenInfoUtils::BuildBundleFullInfo(
        verifiedBundle.installParam, verifiedBundle.policy, innerInfo, noCached);

    fixedPermBriefPerToken.reserve(cachedInfos.size());
    for (const auto& infoPtr : cachedInfos) {
        HapTokenInfo hapInfo = infoPtr->GetHapInfoBasic();
        std::vector<BriefPermData> existingData;
        PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(
            hapInfo.tokenID, existingData);
        bool tokenFixed = false;
        int32_t dlpType = infoPtr->GetDlpType();
        PermissionConstraintCheck::FixBriefPermData(
            *innerInfo, dlpType, existingData, tokenFixed);
        if (tokenFixed) {
            GenericValues delCondition;
            delCondition.Put(TokenFiledConst::FIELD_TOKEN_ID,
                static_cast<int32_t>(hapInfo.tokenID));
            delInfoVec.emplace_back(DelInfo {AtmDataType::ACCESSTOKEN_PERMISSION_STATE, delCondition});

            std::vector<GenericValues> newPermValues =
                BuildPermStateValues(hapInfo.tokenID, existingData);
            addInfoVec.emplace_back(AddInfo {AtmDataType::ACCESSTOKEN_PERMISSION_STATE, newPermValues});
        }
        fixedPermBriefPerToken.emplace_back(std::move(existingData));
    }
}

std::vector<GenericValues> MigrationVerifyHelper::BuildPermStateValues(
    AccessTokenID tokenId, const std::vector<BriefPermData>& data)
{
    std::vector<GenericValues> result;
    int64_t timestamp = TimeUtil::GetCurrentTimestamp();
    for (const auto& item : data) {
        std::string permissionName = TransferOpcodeToPermission(item.permCode);
        if (permissionName.empty()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Unknown permCode=%{public}u for tokenId=%{public}u, skip.",
                item.permCode, tokenId);
            continue;
        }
        GenericValues value;
        value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
        value.Put(TokenFiledConst::FIELD_DEVICE_ID, "PHONE-001");
        value.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
        value.Put(TokenFiledConst::FIELD_GRANT_STATE, static_cast<int32_t>(item.status));
        value.Put(TokenFiledConst::FIELD_GRANT_FLAG, static_cast<int32_t>(item.flag));
        value.Put(TokenFiledConst::FIELD_TIMESTAMP, static_cast<int64_t>(timestamp));
        result.emplace_back(value);
    }
    return result;
}

int32_t MigrationVerifyHelper::VerifyMigratedBundle(const MigratedInfoIdl& migratedInfo,
    const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Verification begin for %{public}s.", migratedInfo.bundleName.c_str());
    delInfoVec_.clear();
    addInfoVec_.clear();

    // 1. Verify the bundle
    VerifiedMigrationBundle verifiedBundle;
    int32_t ret = DoVerifyMigratedBundle(migratedInfo, verifiedBundle);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "VerifyMigratedBundle failed for %{public}s, ret=%{public}d.",
            migratedInfo.bundleName.c_str(), ret);
            return ret;
    }
        
    // 2. Fix briefPermData per token, generate perm DB operations.
    BundleNoCachedInfo noCached;
    std::vector<std::vector<BriefPermData>> fixedPermBriefPerToken;
    FixBriefPermDataPerToken(verifiedBundle, cachedInfos, noCached, fixedPermBriefPerToken);

    // 3. Add kernel data with pre-built noCached and extendPermList.
    std::vector<PermissionWithValue> extendPermList;
    HapSignVerifyHelper::BuildExtendPermListFromPolicy(verifiedBundle.policy, extendPermList);
    std::unique_ptr<AddSpmDataTask> kernelTask;
    ret = AddKernelData(noCached, extendPermList, cachedInfos, fixedPermBriefPerToken, kernelTask);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AddKernelData failed for %{public}s, ret=%{public}d.",
            migratedInfo.bundleName.c_str(), ret);
        return ret;
    }

    // 4. Build signing info and persist all info to DB
    ret = PersistDbInfo(migratedInfo, verifiedBundle, cachedInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PersistSignDbInfo failed for %{public}s, rolling back kernel data, ret=%{public}d.",
            migratedInfo.bundleName.c_str(), ret);
        if (kernelTask != nullptr) {
            kernelTask->Rollback();
        }
        return ret;
    }

    // 5. Update permission cache with per-token fixed briefPermData.
    for (size_t i = 0; i < cachedInfos.size() && i < fixedPermBriefPerToken.size(); ++i) {
        HapTokenInfo hapInfo = cachedInfos[i]->GetHapInfoBasic();
        PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(
            hapInfo.tokenID, fixedPermBriefPerToken[i]);
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Verification finished for %{public}s.", migratedInfo.bundleName.c_str());
    return RET_SUCCESS;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
