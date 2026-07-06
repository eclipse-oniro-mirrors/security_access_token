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

#include <algorithm>
#include <cctype>
#include <memory>
#include <unordered_map>

#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_kit.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_info_utils.h"
#include "accesstoken_id_manager.h"
#include "data_validator.h"
#include "hap_sign_verify_manager.h"
#include "hap_sign_verify_helper.h"
#include "hap_token_info_inner.h"
#include "permission_constraint_check.h"
#include "permission_data_brief.h"
#include "permission_kernel_utils.h"
#include "parameters.h"
#include "spm_data_kernel_common.h"
#include "table_item.h"
#include "token_field_const.h"
#include "time_util.h"
#include "hisysevent_adapter.h"
#include "spm_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int INVALID_USERID = -1;

bool IsPlaceholderModuleName(const std::string& moduleName)
{
    size_t moduleNameMinSize = 2; // placeholder module name should be at least 2 characters, e.g. "#0"
    if (moduleName.size() < moduleNameMinSize || moduleName[0] != '#') {
        return false;
    }
    return std::all_of(moduleName.begin() + 1, moduleName.end(), [](unsigned char ch) {
        return std::isdigit(ch) != 0;
    });
}
}

const TrustedBundleInfoInner& GetBaselineVerifiedInfo(const VerifiedMigrationBundle& verifiedBundle)
{
    return verifiedBundle.verifiedInfos.front();
}

int32_t MigrationVerifyHelper::DoVerifyMigratedBundle(const BundleInfoItems& bundleInfo,
    VerifiedMigrationBundle& verifiedBundle)
{
    HapSignVerifyManager& verifyManager = HapSignVerifyManager::GetInstance();
    std::vector<TrustedBundleInfoInner> verifiedInfos;
    int32_t ret = RET_SUCCESS;
    for (const auto& moduleInfo : bundleInfo.moduleInfoItems) {
        if (moduleInfo.path.empty()) {
            continue;
        }
        TrustedBundleInfoInner trustedBundleInfo;
        bool isChanged = false;
        ret = verifyManager.CheckHapsSignInfo(
            HapSignVerifyManager::MakeVerifyParams(
                moduleInfo.path, Security::Verify::VerifyType::Fast, INVALID_USERID),
            false, trustedBundleInfo, isChanged);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "CheckHapsSignInfo failed, ret=%{public}d.", ret);
            return ERR_HAP_SIGN_VERIFY_FAILED;
        }
        verifiedInfos.emplace_back(trustedBundleInfo);
    }
    if (verifiedInfos.empty()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "No valid hap path found for %{public}s during post verify.",
            bundleInfo.bundleName.c_str());
        return ERR_PARAM_INVALID;
    }

    ret = verifyManager.CheckMultipleHaps(verifiedInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "CheckMultipleHaps failed, ret=%{public}d.", ret);
        return ret;
    }
    std::string verifiedBundleName = verifiedInfos.front().GetBundleName();
    if (verifiedBundleName != bundleInfo.bundleName) {
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

int32_t MigrationVerifyHelper::BuildBundleSignInfo(const BundleInfoItems& bundleInfo,
    const VerifiedMigrationBundle& verifiedBundle, BundleSignInfo& bundleSignInfo)
{
    size_t verifiedSize = verifiedBundle.verifiedInfos.size();
    if (bundleInfo.moduleInfoItems.size() != verifiedSize) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    bundleSignInfo.bundleName = bundleInfo.bundleName;
    bundleSignInfo.isPreInstalled = bundleInfo.isPreInstalled;
    for (size_t i = 0; i < verifiedSize; ++i) {
        const auto& verifiedInfo = verifiedBundle.verifiedInfos[i];
        bundleSignInfo.moduleNameList.emplace_back(verifiedInfo.GetModuleName());
        bundleSignInfo.pathList.emplace_back(bundleInfo.moduleInfoItems[i].path);
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
            data = nullptr;
        }
        bundleSignInfo.persistDataList.emplace_back(persistData);
    }
    return RET_SUCCESS;
}

int32_t MigrationVerifyHelper::DoBundleInfoOperations(const BundleInfoItems& bundleInfo,
    const BundleSignInfo& bundleSignInfo)
{
    std::vector<GenericValues> addValues;
    int32_t ret = bundleSignInfo.ToGenericValues(addValues);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "BundleSignInfo.ToGenericValues failed for %{public}s, ret=%{public}d.",
            bundleSignInfo.bundleName.c_str(), ret);
        return ret;
    }
    if (bundleInfo.moduleInfoItems.size() != addValues.size()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Bundle module count mismatch for %{public}s, db=%{public}zu, verified=%{public}zu.",
            bundleSignInfo.bundleName.c_str(), bundleInfo.moduleInfoItems.size(), addValues.size());
        return ERR_PARAM_INVALID;
    }
    std::vector<GenericValues> conditions;
    conditions.reserve(addValues.size());
    for (size_t i = 0; i < addValues.size(); ++i) {
        const auto& value = addValues[i];
        GenericValues cond;
        cond.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleSignInfo.bundleName);
        cond.Put(TokenFiledConst::FIELD_PATH, value.GetString(TokenFiledConst::FIELD_PATH));
        cond.Put(TokenFiledConst::FIELD_MODULE_NAME, bundleInfo.moduleInfoItems[i].moduleName);
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
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, TokenFiledConst::FIELD_TOKEN_ID, tokenIdValues, dbResults);
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
            continue;
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
        delInfoVec_.emplace_back(DelInfo {AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition});
        addInfoVec_.emplace_back(AddInfo {AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, hapAddValues});
    }
}

MigrationVerifyHelper& MigrationVerifyHelper::GetInstance()
{
    static MigrationVerifyHelper instance;
    return instance;
}

void MigrationVerifyHelper::PostVerifyMigratedBundlesTask()
{
    GenericValues conditionValue;
    std::vector<GenericValues> dbResults;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, dbResults);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Query hap_info_table failed, ret=%{public}d.", ret);
        return;
    }

    std::vector<BundleInfoItems> bundleInfoItems;
    BundleInfoItems::LoadFromDB(dbResults, bundleInfoItems);
    for (const auto& bundleInfo : bundleInfoItems) {
        if (!NeedPostVerify(bundleInfo)) {
            continue;
        }

        std::vector<std::shared_ptr<HapTokenInfoInner>> cachedInfos;
        if (!BuildCachedInfos(bundleInfo.bundleName, cachedInfos)) {
            continue;
        }
        (void)HandleMigratedBundleTask(bundleInfo, cachedInfos);
    }
}

bool MigrationVerifyHelper::NeedPostVerify(const BundleInfoItems& bundleInfo) const
{
    if (bundleInfo.moduleInfoItems.empty()) {
        return false;
    }
    for (const auto& moduleInfo : bundleInfo.moduleInfoItems) {
        if (!IsPlaceholderModuleName(moduleInfo.moduleName)) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Bundle %{public}s has non-placeholder module %{public}s, skip post verify.",
                bundleInfo.bundleName.c_str(), moduleInfo.moduleName.c_str());
            return false;
        }
    }
    return true;
}

bool MigrationVerifyHelper::BuildCachedInfos(const std::string& bundleName,
    std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos)
{
    std::vector<AccessTokenID> tokenIdList;
    int32_t ret = AccessTokenInfoManager::GetInstance().GetHapTokenIdListByBundleName(bundleName, tokenIdList);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "GetHapTokenIdListByBundleName failed for %{public}s, ret=%{public}d.",
            bundleName.c_str(), ret);
        return false;
    }

    cachedInfos.reserve(tokenIdList.size());
    for (auto tokenId : tokenIdList) {
        auto infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
        if (infoPtr == nullptr) {
            LOGW(ATM_DOMAIN, ATM_TAG, "GetHapTokenInfoInner failed for tokenId=%{public}u, bundle=%{public}s.",
                tokenId, bundleName.c_str());
            continue;
        }
        cachedInfos.emplace_back(infoPtr);
    }
    return !cachedInfos.empty();
}

int32_t MigrationVerifyHelper::PersistDbInfo(const BundleInfoItems& bundleInfo,
    const VerifiedMigrationBundle& verifiedBundle,
    const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos)
{
    BundleSignInfo bundleSignInfo;
    int32_t ret = BuildBundleSignInfo(bundleInfo, verifiedBundle, bundleSignInfo);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "BuildBundleSignInfo failed for %{public}s, ret=%{public}d.",
            bundleInfo.bundleName.c_str(), ret);
        return ret;
    }
    
    ret = DoBundleInfoOperations(bundleInfo, bundleSignInfo);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec_, addInfoVec_);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Hap info DB persist failed for %{public}s, ret=%{public}d.",
            bundleInfo.bundleName.c_str(), ret);
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
            permBriefDataPerToken[i], extendPermList, nullptr, false }); // false means not updateWithPerm
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

int32_t MigrationVerifyHelper::VerifyMigratedBundle(const BundleInfoItems& bundleInfo,
    const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Verification begin for %{public}s.", bundleInfo.bundleName.c_str());
    delInfoVec_.clear();
    addInfoVec_.clear();

    // 1. Verify the bundle
    VerifiedMigrationBundle verifiedBundle;
    int32_t ret = DoVerifyMigratedBundle(bundleInfo, verifiedBundle);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "VerifyMigratedBundle failed for %{public}s, ret=%{public}d.",
            bundleInfo.bundleName.c_str(), ret);
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
        if (ret == ERR_DATA_CONFLICT_WITH_KERNEL) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Data has loaded in kernel for %{public}s, ret=%{public}d.",
                bundleInfo.bundleName.c_str(), ret);
            return RET_SUCCESS;
        } else {
            LOGC(ATM_DOMAIN, ATM_TAG, "AddKernelData failed for %{public}s, ret=%{public}d.",
                bundleInfo.bundleName.c_str(), ret);
                return ret;
        }
    }

    // 4. Build signing info and persist all info to DB
    ret = PersistDbInfo(bundleInfo, verifiedBundle, cachedInfos);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "PersistSignDbInfo failed for %{public}s, rolling back kernel data, ret=%{public}d.",
            bundleInfo.bundleName.c_str(), ret);
        if (kernelTask != nullptr) {
            kernelTask->Rollback();
        }
        return ret;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Verification finished for %{public}s.", bundleInfo.bundleName.c_str());
    return RET_SUCCESS;
}

int32_t MigrationVerifyHelper::HandleMigratedBundleTask(const BundleInfoItems& bundleInfo,
    const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos)
{
    int32_t ret = VerifyMigratedBundle(bundleInfo, cachedInfos);
    if (ret != RET_SUCCESS) {
#ifndef ATM_TEST_ENABLE
        static bool isSpmEnforce = AccessTokenInfoUtils::IsSystemSpmEnforcing();
#else
        // Unit tests require this parameter to be changed on the
        bool isSpmEnforce = AccessTokenInfoUtils::IsSystemSpmEnforcing();
#endif
        LOGC(ATM_DOMAIN, ATM_TAG, "Verification failed for %{public}s, ret=%{public}d, spmEnforce=%{public}d.",
            bundleInfo.bundleName.c_str(), ret, static_cast<int>(isSpmEnforce));
        if (isSpmEnforce) {
            for (const auto& infoPtr : cachedInfos) {
                HapTokenInfo hapInfo = infoPtr->GetHapInfoBasic();
                AccessTokenInfoManager::GetInstance().CommitDeleteHapCache(
                    hapInfo.tokenID, bundleInfo.bundleName);
                PermissionKernelUtils::RemovePermFromKernel(hapInfo.tokenID);
                AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(hapInfo.tokenID, TokenIdStatus::UNTRUSTED);
            }
        }
    }
    ReportSysCommonEventError((int32_t)IAccessTokenManagerIpcCode::COMMAND_MIGRATE_INSTALLED_BUNDLES, ret);
    return ret;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
