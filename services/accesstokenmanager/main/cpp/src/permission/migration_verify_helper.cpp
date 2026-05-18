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

#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_info_manager.h"
#include "data_validator.h"
#include "foundation/bundlemanager/bundle_framework/interfaces/inner_api/appexecfwk_base/include/bundle_constants.h"
#include "hap_sign_verify_manager.h"
#include "hap_sign_verify_helper.h"
#include "hap_token_info_inner.h"
#include "permission_data_brief.h"
#include "spm_data_kernel_common.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int INVALID_USERID = -1;

const TrustedBundleInfoInner& GetBaselineVerifiedInfo(const VerifiedMigrationBundle& verifiedBundle)
{
    return verifiedBundle.verifiedInfos.front();
}

int32_t DoVerifyMigratedBundle(const MigratedInfoIdl& migratedInfo,
    VerifiedMigrationBundle& verifiedBundle)
{
    HapSignVerifyManager& verifyManager = HapSignVerifyManager::GetInstance();
    std::vector<TrustedBundleInfoInner> verifiedInfos;
    int32_t ret = RET_SUCCESS;
    for (const auto& hapPath : migratedInfo.pathList.hapPaths) {
        TrustedBundleInfoInner trustedBundleInfo;
        bool isChanged = false;
        ret = verifyManager.CheckHapsSignInfo(hapPath, Security::Verify::VerifyType::Fast, INVALID_USERID, trustedBundleInfo,
            isChanged);
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

int32_t BuildBundleSignInfo(const MigratedInfoIdl& migratedInfo,
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

int32_t AppendBundleSignDbInfo(const BundleSignInfo& bundleSignInfo,
    std::vector<GenericValues>& addValues)
{
    return bundleSignInfo.ToGenericValues(addValues);
}

int32_t PrepareBundleInfoOperations(const MigratedInfoIdl& migratedInfo,
    const BundleSignInfo& bundleSignInfo, std::vector<DelInfo>& delInfoVec,
    std::vector<AddInfo>& addInfoVec)
{
    GenericValues delCondition;
    delCondition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, migratedInfo.bundleName);
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO;
    delInfo.delValue = delCondition;
    delInfoVec.emplace_back(delInfo);

    std::vector<GenericValues> addValues;
    int32_t ret = AppendBundleSignDbInfo(bundleSignInfo, addValues);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "AppendBundleSignDbInfo failed for %{public}s, ret=%{public}d.",
            migratedInfo.bundleName.c_str(), ret);
        return ret;
    }

    if (!addValues.empty()) {
        AddInfo addInfo;
        addInfo.addType = AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO;
        addInfo.addValues = addValues;
        addInfoVec.emplace_back(addInfo);
    }
    return RET_SUCCESS;
}

void PrepareHapInfoOperations(const VerifiedMigrationBundle& verifiedBundle,
    const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos,
    std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec)
{
    std::string appId = verifiedBundle.installParam.appId;
    ATokenAplEnum apl = verifiedBundle.policy.apl;
    for (const auto& infoPtr : cachedInfos) {
        HapTokenInfo hapInfo = infoPtr->GetHapInfoBasic();
        GenericValues condition;
        condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(hapInfo.tokenID));
        DelInfo hapDelInfo;
        hapDelInfo.delType = AtmDataType::ACCESSTOKEN_HAP_INFO;
        hapDelInfo.delValue = condition;
        delInfoVec.emplace_back(hapDelInfo);

        std::vector<GenericValues> hapAddValues;
        infoPtr->GenerateHapInfoValues(appId, apl, hapAddValues);
        AddInfo hapAddInfo;
        hapAddInfo.addType = AtmDataType::ACCESSTOKEN_HAP_INFO;
        hapAddInfo.addValues = hapAddValues;
        addInfoVec.emplace_back(hapAddInfo);
    }
}
}

int32_t MigrationVerifyHelper::PersistSignDbInfo(const MigratedInfoIdl& migratedInfo,
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

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    
    ret = PrepareBundleInfoOperations(migratedInfo, bundleSignInfo, delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    PrepareHapInfoOperations(verifiedBundle, cachedInfos, delInfoVec, addInfoVec);

    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Sign info DB persist failed for %{public}s, ret=%{public}d.",
            migratedInfo.bundleName.c_str(), ret);
    }
    return ret;
}

int32_t MigrationVerifyHelper::AddKernelData(const VerifiedMigrationBundle& verifiedBundle,
    const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos,
    std::unique_ptr<AddSpmDataTask>& kernelTask)
{
    const auto& baselineInfo = GetBaselineVerifiedInfo(verifiedBundle);
    BundleNoCachedInfo noCachedInfo;
    noCachedInfo.apl = verifiedBundle.policy.apl;
    noCachedInfo.distributionType = baselineInfo.provisionInfo.distributionType;
    noCachedInfo.idType = baselineInfo.GetSpmIdType();
    noCachedInfo.ownerid = HapSignVerifyHelper::BuildOwnerId(
        baselineInfo.GetAppIdentifier());

    std::vector<BriefPermData> permBriefDataList;
    HapSignVerifyHelper::BuildPermBriefDataListFromPolicy(verifiedBundle.policy, permBriefDataList);

    std::vector<PermissionWithValue> extendPermList;
    HapSignVerifyHelper::BuildExtendPermListFromPolicy(verifiedBundle.policy, extendPermList);

    std::vector<SpmDataParam> params;
    params.reserve(cachedInfos.size());
    for (const auto& infoPtr : cachedInfos) {
        HapTokenInfo hapInfo = infoPtr->GetHapInfoBasic();
        params.emplace_back(SpmDataParam { hapInfo, noCachedInfo, permBriefDataList, extendPermList });
    }

    kernelTask = std::make_unique<AddSpmDataTask>(params);
    uint32_t errIndex = 0;
    return kernelTask->Add(errIndex);
}

int32_t MigrationVerifyHelper::VerifyMigratedBundle(const MigratedInfoIdl& migratedInfo,
    const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Verification begin for %{public}s.", migratedInfo.bundleName.c_str());

    // 1. Verify the bundle
    VerifiedMigrationBundle verifiedBundle;
    int32_t ret = DoVerifyMigratedBundle(migratedInfo, verifiedBundle);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "VerifyMigratedBundle failed for %{public}s, ret=%{public}d.",
            migratedInfo.bundleName.c_str(), ret);
        return ret;
    }

    // 2. Add kernel data from verified bundle info (kernel first)
    std::unique_ptr<AddSpmDataTask> kernelTask;
    ret = AddKernelData(verifiedBundle, cachedInfos, kernelTask);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AddKernelData failed for %{public}s, ret=%{public}d.",
            migratedInfo.bundleName.c_str(), ret);
        return ret;
    }

    // 3. Build signing info and persist to DB
    ret = PersistSignDbInfo(migratedInfo, verifiedBundle, cachedInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PersistSignDbInfo failed for %{public}s, rolling back kernel data, ret=%{public}d.",
            migratedInfo.bundleName.c_str(), ret);
        if (kernelTask != nullptr) {
            (void)kernelTask->Rollback();
        }
        return ret;
    }

    // 4. Update permission cache after kernel and DB both succeed
    for (const auto& infoPtr : cachedInfos) {
        HapTokenInfo hapInfo = infoPtr->GetHapInfoBasic();
        PermissionDataBrief::GetInstance().AddPermToBriefPermission(
            hapInfo.tokenID, verifiedBundle.policy.permStateList,
            verifiedBundle.policy.aclExtendedMap, true);
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Verification finished for %{public}s.", migratedInfo.bundleName.c_str());
    return RET_SUCCESS;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
