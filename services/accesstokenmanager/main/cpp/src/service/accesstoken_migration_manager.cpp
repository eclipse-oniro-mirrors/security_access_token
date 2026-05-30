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

#include "accesstoken_migration_manager.h"

#include <cinttypes>
#include <cerrno>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "bundle_sign_info.h"
#include "data_validator.h"
#include "interfaces/hap_verify.h"
#include "hisysevent_adapter.h"
#include "idl_common.h"
#ifdef IS_SUPPORT_HAP_RUNNING
#include "migration_verify_worker.h"
#include "migration_verify_helper.h"
#endif
#include "token_setproc.h"
#include "token_field_const.h"
#include "spm_setproc.h"
#include "spm_data_kernel_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const std::string BMS_MIGRATE_COMPLETED = "bms_migrate_completed";
const std::string SYSTEM_CONFIG_TRUE_VALUE = "1";
static constexpr uint32_t INVALID_HAP_UID = static_cast<uint32_t>(-1);
static constexpr size_t MAX_MIGRATED_INFO_SIZE = 50;
static constexpr size_t MAX_UID_LIST_SIZE = 102400;

int32_t AccessTokenMigrationManager::MarkMigrationCompleted()
{
    GenericValues delValue;
    delValue.Put(TokenFiledConst::FIELD_NAME, BMS_MIGRATE_COMPLETED);
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    delInfo.delValue = delValue;

    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_NAME, BMS_MIGRATE_COMPLETED);
    addValue.Put(TokenFiledConst::FIELD_VALUE, SYSTEM_CONFIG_TRUE_VALUE);
    AddInfo addInfo;
    addInfo.addType = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    addInfo.addValues.emplace_back(addValue);

    std::vector<DelInfo> delInfoVec = { delInfo };
    std::vector<AddInfo> addInfoVec = { addInfo };
    return AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
}

int32_t AccessTokenMigrationManager::ValidateMigratedInfo(const MigratedInfoIdl& migratedInfo)
{
    if (!DataValidator::IsBundleNameValid(migratedInfo.bundleName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, bundleName is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsStringListValid(migratedInfo.pathList.hapPaths)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, path list is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsListSizeValid(static_cast<uint32_t>(migratedInfo.hapBaseInfoList.size()))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, hapBaseInfoList size is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    size_t hapCount = migratedInfo.hapBaseInfoList.size();
    if (migratedInfo.uidList.size() != hapCount || migratedInfo.reservedTypeList.size() != hapCount) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, list sizes mismatch.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    std::unordered_set<int32_t> seenUids;
    seenUids.reserve(hapCount);
    for (size_t i = 0; i < hapCount; ++i) {
        const auto& hap = migratedInfo.hapBaseInfoList[i];
        if (hap.userID < 0 || hap.instIndex < 0 ||
            !DataValidator::IsBundleNameValid(hap.bundleName)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, hapBaseInfo is invalid.");
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        if (hap.bundleName != migratedInfo.bundleName) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Migrate installed bundles failed, bundleName mismatch in hap base info.");
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        int32_t uid = migratedInfo.uidList[i];
        if (!seenUids.emplace(uid).second) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Migrate installed bundles failed, duplicate uid %{public}d.", uid);
            ReportSysCommonEventError(
                static_cast<int32_t>(IAccessTokenManagerIpcCode::COMMAND_MIGRATE_INSTALLED_BUNDLES),
                AccessTokenError::ERR_MIGRATION_UID_DUPLICATED);
            return AccessTokenError::ERR_MIGRATION_UID_DUPLICATED;
        }
    }
    return RET_SUCCESS;
}

int32_t AccessTokenMigrationManager::GetCachedTokenInfo(AccessTokenID tokenId, const std::string& bundleName,
    std::shared_ptr<HapTokenInfoInner>& infoPtr)
{
    infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, tokenId %{public}u does not exist in cache.",
            tokenId);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (infoPtr->GetBundleName() != bundleName) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, bundleName mismatch.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return RET_SUCCESS;
}

int32_t AccessTokenMigrationManager::CheckCachedUid(const std::shared_ptr<HapTokenInfoInner>& infoPtr,
    int32_t uid)
{
    uint32_t cachedUid = infoPtr->GetUid();
    if ((cachedUid == INVALID_HAP_UID) || (cachedUid == static_cast<uint32_t>(uid))) {
        return RET_SUCCESS;
    }
    LOGC(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, cached uid %{public}u differs from migration uid "
        "%{public}d while migrating tokenId %{public}u.", cachedUid, uid, infoPtr->GetTokenID());
    ReportSysCommonEventError(
        static_cast<int32_t>(IAccessTokenManagerIpcCode::COMMAND_MIGRATE_INSTALLED_BUNDLES),
        AccessTokenError::ERR_MIGRATION_UID_EXISTED);
    return AccessTokenError::ERR_MIGRATION_UID_EXISTED;
}

int32_t AccessTokenMigrationManager::CreateNewTokenInfoForHap(
    PreparedMigrationBundle& preparedBundle, size_t index,
    std::shared_ptr<HapTokenInfoInner>& infoPtr)
{
    const auto& hapBaseInfo = preparedBundle.migratedInfo.hapBaseInfoList[index];
    int32_t uid = preparedBundle.migratedInfo.uidList[index];
    int32_t dlpFlag = 0;
    int32_t cloneFlag = (hapBaseInfo.instIndex) > 0 ? 1 : 0;
    AccessTokenID newTokenId = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(
        TOKEN_HAP, dlpFlag, cloneFlag, 0);
    if (newTokenId == 0) {
        LOGW(ATM_DOMAIN, ATM_TAG, "CreateAndRegisterTokenId failed during PrepareIdentityInfos.");
        return AccessTokenError::ERR_TOKENID_CREATE_FAILED;
    }
    infoPtr = std::make_shared<HapTokenInfoInner>();
    HapTokenInfo hapTokenInfo;
    hapTokenInfo.tokenID = newTokenId;
    hapTokenInfo.userID = hapBaseInfo.userID;
    hapTokenInfo.bundleName = hapBaseInfo.bundleName;
    hapTokenInfo.instIndex = hapBaseInfo.instIndex;
    hapTokenInfo.uid = static_cast<uint32_t>(uid);
    infoPtr->SetTokenBaseInfo(hapTokenInfo);
    infoPtr->SetMigrated(true);
    return RET_SUCCESS;
}

int32_t AccessTokenMigrationManager::PrepareIdentityInfos(PreparedMigrationBundle& preparedBundle)
{
    int32_t ret = RET_SUCCESS;
    const auto& migratedInfo = preparedBundle.migratedInfo;
    auto& cachedInfos = preparedBundle.cachedInfos;
    auto& newTokenFlags = preparedBundle.newTokenFlags;
    size_t hapCount = migratedInfo.hapBaseInfoList.size();
    cachedInfos.reserve(hapCount);
    newTokenFlags.reserve(hapCount);

    for (size_t i = 0; i < hapCount; ++i) {
        const auto& hapBaseInfo = migratedInfo.hapBaseInfoList[i];
        int32_t uid = migratedInfo.uidList[i];

        AccessTokenIDEx tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(
            hapBaseInfo.userID, hapBaseInfo.bundleName, hapBaseInfo.instIndex);
        AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
        std::shared_ptr<HapTokenInfoInner> infoPtr;
        bool isNewToken = false;

        if (tokenId == 0) {
            isNewToken = true;
            ret = CreateNewTokenInfoForHap(preparedBundle, i, infoPtr);
            if (ret != RET_SUCCESS) {
                return ret;
            }
            tokenId = infoPtr->GetTokenID();
            preparedBundle.migratedInfo.reservedTypeList[i] = ReservedTypeIdl::RESERVED_DATA;
        } else {
            ret = GetCachedTokenInfo(tokenId, migratedInfo.bundleName, infoPtr);
            if (ret != RET_SUCCESS) {
                return ret;
            }
        }

        ret = CheckCachedUid(infoPtr, uid);
        if (ret != RET_SUCCESS) {
            return ret;
        }

        LOGI(ATM_DOMAIN, ATM_TAG, "Prepare bundle %{public}s userId=%{public}d, instIndex=%{public}d, "
            "uid=%{public}d, tokenId=%{public}u, isNew=%{public}d.",
            migratedInfo.bundleName.c_str(), infoPtr->GetUserID(), infoPtr->GetInstIndex(),
            uid, tokenId, static_cast<int>(isNewToken));
        cachedInfos.emplace_back(infoPtr);
        newTokenFlags.emplace_back(isNewToken);
    }
    return RET_SUCCESS;
}

int32_t AccessTokenMigrationManager::PersistMigratedBundles(const PreparedMigrationBundle& preparedBundle)
{
    std::vector<DelInfo> delInfoVec;
    std::vector<GenericValues> hapInfoValues;

    for (const auto& info : preparedBundle.cachedInfos) {
        GenericValues delValue;
        delValue.Put(TokenFiledConst::FIELD_TOKEN_ID,
            static_cast<int32_t>(info->GetHapInfoBasic().tokenID));
        DelInfo delInfo;
        delInfo.delType = AtmDataType::ACCESSTOKEN_HAP_INFO;
        delInfo.delValue = delValue;
        delInfoVec.emplace_back(delInfo);
    }

    int32_t ret = AppendHapTokenDbInfo(preparedBundle, hapInfoValues);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    std::vector<AddInfo> addInfoVec;
    if (!hapInfoValues.empty()) {
        AddInfo addInfo;
        addInfo.addType = AtmDataType::ACCESSTOKEN_HAP_INFO;
        addInfo.addValues = hapInfoValues;
        addInfoVec.emplace_back(addInfo);
    }

    BundleSignInfo placeholderSign;
    placeholderSign.bundleName = preparedBundle.migratedInfo.bundleName;
    placeholderSign.isPreInstalled = preparedBundle.migratedInfo.pathList.isPreInstalled;
    Security::Verify::BootstrapInfo sentinelBootstrap = {};
    sentinelBootstrap.version = -1;
    for (const auto& hapPath : preparedBundle.migratedInfo.pathList.hapPaths) {
        placeholderSign.moduleNameList.emplace_back(MIGRATION_PLACEHOLDER_MODULE);
        placeholderSign.pathList.emplace_back(hapPath);
        placeholderSign.bundleType.emplace_back(0);
        uint8_t* dumped = sentinelBootstrap.Dump();
        std::vector<uint8_t> blob;
        if (dumped != nullptr) {
            blob.assign(dumped, dumped + sentinelBootstrap.GetSize());
            delete[] dumped;
        }
        placeholderSign.persistDataList.emplace_back(std::move(blob));
    }
    std::vector<GenericValues> signValues;
    if (placeholderSign.ToGenericValues(signValues) == RET_SUCCESS) {
        AddInfo signAddInfo;
        signAddInfo.addType = AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO;
        signAddInfo.addValues = signValues;
        addInfoVec.emplace_back(signAddInfo);
    }

    return AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
}

int32_t AccessTokenMigrationManager::ExecutePreparedMigration(PreparedMigrationBundle& preparedBundle)
{
    int32_t ret = PersistMigratedBundles(preparedBundle);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    
    for (size_t i = 0; i < preparedBundle.cachedInfos.size(); ++i) {
        preparedBundle.cachedInfos[i]->SetUid(static_cast<uint32_t>(preparedBundle.migratedInfo.uidList[i]));
        preparedBundle.cachedInfos[i]->SetMigrated(true);
    }
#ifdef IS_SUPPORT_HAP_RUNNING
    std::vector<std::shared_ptr<HapTokenInfoInner>> verifyInfos;
    for (size_t i = 0; i < preparedBundle.cachedInfos.size(); ++i) {
        if (i < preparedBundle.newTokenFlags.size() && preparedBundle.newTokenFlags[i]) {
            continue;
        }
        verifyInfos.emplace_back(preparedBundle.cachedInfos[i]);
    }
    if (!verifyInfos.empty()) {
        MigrationVerifyWorker::GetInstance().Submit(preparedBundle.migratedInfo, verifyInfos);
    }
#endif
    return RET_SUCCESS;
}

int32_t AccessTokenMigrationManager::MigrateSingleBundle(const MigratedInfoIdl& migratedInfo,
    BundleMigrateResultIdl& result)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Migration begin for bundle %{public}s, hapCount=%{public}zu.",
        migratedInfo.bundleName.c_str(), migratedInfo.hapBaseInfoList.size());

    // Phase 1: Validate all input data in one pass.
    int32_t ret = ValidateMigratedInfo(migratedInfo);

    // Phase 2: Pre-fill result with defaults matching hapBaseInfoList size.
    const size_t hapCount = migratedInfo.hapBaseInfoList.size();
    result.tokenIdList.resize(hapCount, INVALID_TOKENID);
    result.reservedTypeList.resize(hapCount, ReservedTypeIdl::NONE);
    if (ret != RET_SUCCESS) {
        result.errcode = ret;
        return ret;
    }

    // Phase 3: Prepare identity infos (kernel check + cache lookup / token creation).
    PreparedMigrationBundle preparedBundle;
    preparedBundle.migratedInfo = migratedInfo;
    ret = PrepareIdentityInfos(preparedBundle);

    // Phase 4: Fill actual token IDs and reserved types into result.
    for (size_t i = 0; i < hapCount; ++i) {
        if (i < preparedBundle.cachedInfos.size()) {
            AccessTokenIDEx tokenIdEx;
            tokenIdEx.tokenIdExStruct.tokenID = preparedBundle.cachedInfos[i]->GetTokenID();
            tokenIdEx.tokenIdExStruct.tokenAttr = preparedBundle.cachedInfos[i]->GetAttr();
            result.tokenIdList[i] = tokenIdEx.tokenIDEx;
            result.reservedTypeList[i] = preparedBundle.migratedInfo.reservedTypeList[i];
        }
    }
    if (ret != RET_SUCCESS) {
        result.errcode = ret;
        return ret;
    }

    // Phase 5: Persist to DB, update in-memory cache, submit async verification.
    ret = ExecutePreparedMigration(preparedBundle);
    result.errcode = ret;
    if (ret == RET_SUCCESS) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Migration finished for bundle %{public}s, hapCount=%{public}zu.",
            migratedInfo.bundleName.c_str(), hapCount);
    } else {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migration failed for bundle %{public}s, ret=%{public}d.",
            migratedInfo.bundleName.c_str(), ret);
    }
    return ret;
}

int32_t AccessTokenMigrationManager::AppendHapTokenDbInfo(
    const PreparedMigrationBundle& preparedBundle, std::vector<GenericValues>& addValues)
{
    for (size_t i = 0; i < preparedBundle.cachedInfos.size(); ++i) {
        AccessTokenID tokenId = preparedBundle.cachedInfos[i]->GetHapInfoBasic().tokenID;
        bool isNew = preparedBundle.newTokenFlags[i];

        size_t valueIndex = addValues.size();
        if (isNew) {
            preparedBundle.cachedInfos[i]->GenerateHapInfoValues(
                preparedBundle.migratedInfo.bundleName, ATokenAplEnum::APL_NORMAL, addValues);
        } else {
            auto it = dbRowCache_.find(static_cast<int32_t>(tokenId));
            if (it == dbRowCache_.end()) {
                LOGE(ATM_DOMAIN, ATM_TAG,
                    "Migrate installed bundles failed, tokenId %{public}u not found in DB cache.", tokenId);
                return ERR_DATABASE_OPERATE_FAILED;
            }
            addValues.emplace_back(it->second);
        }
        if (addValues.size() <= valueIndex) {
            continue;
        }

        addValues[valueIndex].Remove(TokenFiledConst::FIELD_UID);
        addValues[valueIndex].Put(TokenFiledConst::FIELD_UID, preparedBundle.migratedInfo.uidList[i]);
        addValues[valueIndex].Remove(TokenFiledConst::FIELD_MIGRATED);
        addValues[valueIndex].Put(TokenFiledConst::FIELD_MIGRATED, preparedBundle.migratedInfo.uidList[i]);
        ReservedTypeIdl reserved = preparedBundle.migratedInfo.reservedTypeList[i];
        addValues[valueIndex].Remove(TokenFiledConst::FIELD_RESERVED);
        addValues[valueIndex].Put(TokenFiledConst::FIELD_RESERVED, static_cast<int32_t>(reserved));
    }
    return RET_SUCCESS;
}

AccessTokenMigrationManager& AccessTokenMigrationManager::GetInstance()
{
    static AccessTokenMigrationManager instance;
    return instance;
}

void AccessTokenMigrationManager::Initialize()
{
    if (IsMigrationCompleted()) {
        AccessTokenIDManager::GetInstance().SetMigrationDone();
        LOGI(ATM_DOMAIN, ATM_TAG, "Migration was previously completed, flag set during initialization.");
    }
}

bool AccessTokenMigrationManager::IsMigrationCompleted() const
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_NAME, BMS_MIGRATE_COMPLETED);

    std::vector<GenericValues> results;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG, conditionValue, results);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Find migration completion record failed, ret=%{public}d.", ret);
        return false;
    }
    return !results.empty();
}

int32_t AccessTokenMigrationManager::MigrateInstalledBundles(
    const std::vector<MigratedInfoIdl>& migratedInfoList, std::vector<BundleMigrateResultIdl>& results)
{
    results.clear();
    if (migratedInfoList.size() > MAX_MIGRATED_INFO_SIZE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrated info list size %{public}zu exceeds limit.",
            migratedInfoList.size());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (IsMigrationCompleted()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "BMS migration already completed.");
        return AccessTokenError::ERR_MIGRATION_COMPLETED;
    }
    results.reserve(migratedInfoList.size());

    for (const auto& migratedInfo : migratedInfoList) {
        BundleMigrateResultIdl migrateResult;

        // Validate every UID in this bundle was registered via PreMigrateUIDList.
        bool uidMissing = false;
        for (int32_t uid : migratedInfo.uidList) {
            if (preMigratedUidSet_.find(uid) == preMigratedUidSet_.end()) {
                LOGE(ATM_DOMAIN, ATM_TAG,
                    "Migrate installed bundles failed, uid %{public}d not in pre-migrated set.", uid);
                uidMissing = true;
                break;
            }
        }
        if (uidMissing) {
            const size_t hapCount = migratedInfo.hapBaseInfoList.size();
            migrateResult.tokenIdList.resize(hapCount, INVALID_TOKENID);
            migrateResult.reservedTypeList.resize(hapCount, ReservedTypeIdl::NONE);
            migrateResult.errcode = AccessTokenError::ERR_PARAM_INVALID;
            results.emplace_back(std::move(migrateResult));
            continue;
        }

        int32_t singleRet = MigrateSingleBundle(migratedInfo, migrateResult);
        if (singleRet != RET_SUCCESS) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Bundle %{public}s migration failed, ret=%{public}d.",
                migratedInfo.bundleName.c_str(), singleRet);
        } else {
            for (int32_t uid : migratedInfo.uidList) {
                preMigratedUidSet_.erase(uid);
            }
        }
        results.emplace_back(std::move(migrateResult));
    }
    return RET_SUCCESS;
}

int32_t AccessTokenMigrationManager::PreMigrateUIDList(const std::vector<int32_t>& uidList)
{
    if (uidList.empty() || uidList.size() > MAX_UID_LIST_SIZE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Pre migrate uid list is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (IsMigrationCompleted()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "BMS migration already completed.");
        return AccessTokenError::ERR_MIGRATION_COMPLETED;
    }

    std::unordered_set<int32_t> seenUids;
    seenUids.reserve(uidList.size());
    for (int32_t uid : uidList) {
        if (!seenUids.emplace(uid).second) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Pre migrate uid list failed, duplicate uid %{public}d.", uid);
            return AccessTokenError::ERR_MIGRATION_UID_DUPLICATED;
        }
    }

    // Query all existing UIDs from the DB and reject any overlap with the incoming list.
    GenericValues emptyCondition;
    std::vector<GenericValues> dbResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, emptyCondition, dbResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PreMigrateUIDList query all hap info failed, ret=%{public}d.", ret);
        return ERR_DATABASE_OPERATE_FAILED;
    }
    for (const auto& row : dbResults) {
        int32_t existingUid = row.GetInt(TokenFiledConst::FIELD_UID);
        if (seenUids.count(existingUid) != 0) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "PreMigrateUIDList failed, uid %{public}d already exists in DB.", existingUid);
            return AccessTokenError::ERR_MIGRATION_UID_DUPLICATED;
        }
    }

    // Cache all hap info rows so MigrateInstalledBundles can skip LoadDbRowCache.
    std::unordered_map<int32_t, GenericValues> newCache;
    for (auto& row : dbResults) {
        int32_t tid = row.GetInt(TokenFiledConst::FIELD_TOKEN_ID);
        newCache[tid] = std::move(row);
    }
    dbRowCache_.swap(newCache);

    preMigratedUidSet_.insert(uidList.begin(), uidList.end());

    ret = AccessTokenIDManager::GetInstance().ImportInitialUids(uidList);
    if (ret == RET_SUCCESS) {
        LOGI(ATM_DOMAIN, ATM_TAG, "PreMigrateUIDList successful, count=%{public}zu.", uidList.size());
    }
    return ret;
}

int32_t AccessTokenMigrationManager::FinishMigration()
{
    if (IsMigrationCompleted()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "BMS migration already completed.");
        return AccessTokenError::ERR_MIGRATION_COMPLETED;
    }
    int32_t ret = MarkMigrationCompleted();
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Mark migration completed failed, ret=%{public}d.", ret);
        return ret;
    }
    AccessTokenIDManager::GetInstance().SetMigrationDone();
    dbRowCache_.clear();
    preMigratedUidSet_.clear();
    LOGI(ATM_DOMAIN, ATM_TAG, "BMS migration completed successfully.");
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
