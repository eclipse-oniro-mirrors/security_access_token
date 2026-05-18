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
#include "data_validator.h"
#include "hisysevent_adapter.h"
#include "idl_common.h"
#ifdef IS_SUPPORT_HAP_RUNNING
#include "migration_verify_worker.h"
#endif
#include "token_setproc.h"
#include "token_field_const.h"
#include "spm_setproc.h"
#include "spm_data_kernel_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
const std::string BMS_MIGRATE_COMPLETED = "bms_migrate_completed";
const std::string SYSTEM_CONFIG_TRUE_VALUE = "1";
static constexpr uint32_t INVALID_HAP_UID = static_cast<uint32_t>(-1);
static constexpr size_t MAX_MIGRATED_INFO_SIZE = 50;
static constexpr size_t MAX_UID_LIST_SIZE = 102400;

int32_t MarkMigrationCompleted()
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

void GenerateDelInfoToVec(AtmDataType type, const GenericValues& delValue, std::vector<DelInfo>& delInfoVec)
{
    DelInfo delInfo;
    delInfo.delType = type;
    delInfo.delValue = delValue;
    delInfoVec.emplace_back(delInfo);
}

void GenerateAddInfoToVec(AtmDataType type, const std::vector<GenericValues>& addValues,
    std::vector<AddInfo>& addInfoVec)
{
    if (addValues.empty()) {
        return;
    }
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues = addValues;
    addInfoVec.emplace_back(addInfo);
}

bool IsReservedTypeValid(ReservedTypeIdl reserved)
{
    return (reserved == ReservedTypeIdl::NONE) ||
        (reserved == ReservedTypeIdl::RESERVED_IDENTITY) ||
        (reserved == ReservedTypeIdl::RESERVED_DATA);
}

bool IsMigratedInfoShapeValid(const MigratedInfoIdl& migratedInfo)
{
    return DataValidator::IsBundleNameValid(migratedInfo.bundleName) &&
        DataValidator::IsStringListValid(migratedInfo.pathList.hapPaths) &&
        DataValidator::IsListSizeValid(static_cast<uint32_t>(migratedInfo.hapBaseInfoList.size())) &&
        (migratedInfo.uidList.size() == migratedInfo.hapBaseInfoList.size()) &&
        (migratedInfo.reservedTypeList.size() == migratedInfo.hapBaseInfoList.size());
}

int32_t ValidateMigratedInfoShape(const MigratedInfoIdl& migratedInfo)
{
    if (!IsMigratedInfoShapeValid(migratedInfo)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, path list, base infos,"
            " uid list, or reserved types is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return RET_SUCCESS;
}

int32_t ValidateReservedTypes(const MigratedInfoIdl& migratedInfo)
{
    for (const auto& reserved : migratedInfo.reservedTypeList) {
        if (!IsReservedTypeValid(reserved)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, reserved type is invalid.");
            return AccessTokenError::ERR_PARAM_INVALID;
        }
    }
    return RET_SUCCESS;
}

int32_t CheckHapBaseInfoBasic(const HapBaseInfoIdl& hapBaseInfo)
{
    if (hapBaseInfo.userID < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, userID is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!DataValidator::IsBundleNameValid(hapBaseInfo.bundleName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, hap bundleName is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (hapBaseInfo.instIndex < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, instIndex is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return RET_SUCCESS;
}

int32_t GetCachedTokenInfo(AccessTokenID tokenId, const std::string& bundleName,
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

int32_t CheckCachedUid(const std::shared_ptr<HapTokenInfoInner>& infoPtr, int32_t uid, AccessTokenID tokenId)
{
    uint32_t cachedUid = infoPtr->GetUid();
    if ((cachedUid == INVALID_HAP_UID) || (cachedUid == static_cast<uint32_t>(uid))) {
        return RET_SUCCESS;
    }

    LOGC(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, cached uid %{public}u differs from migration uid "
        "%{public}d while migrating tokenId %{public}u.", cachedUid, uid, tokenId);
    ReportSysCommonEventError(
        static_cast<int32_t>(IAccessTokenManagerIpcCode::COMMAND_MIGRATE_INSTALLED_BUNDLES),
        AccessTokenError::ERR_MIGRATION_UID_EXISTED);
    return AccessTokenError::ERR_MIGRATION_UID_EXISTED;
}

int32_t CheckUidIdleInKernel(int32_t uid)
{
    uint64_t uidRefcnt = 0;
    int32_t ret = SpmGetUidRefCnt(static_cast<uint32_t>(uid), &uidRefcnt);
    if (ret != RET_SUCCESS) {
        if (KernelDetail::IsKernelNotSupported(ret)) {
            LOGW(ATM_DOMAIN, ATM_TAG, "SpmGetUidRefCnt is not supported in current system.");
            return RET_SUCCESS;
        }
        LOGE(ATM_DOMAIN, ATM_TAG, "SpmGetUidRefCnt failed, ret=%{public}d.", ret);
        return ERR_KERNEL_COMMON_FAILED;
    }
    if (uidRefcnt != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, uid %{public}d has active kernel refcnt "
            "%{public}" PRIu64 ".", uid, uidRefcnt);
        return AccessTokenError::ERR_MIGRATION_UID_EXISTED;
    }
    return RET_SUCCESS;
}

int32_t CreateNewTokenInfoForHap(const HapBaseInfoIdl& hapBaseInfo, int32_t uid,
    PreparedMigrationBundle& preparedBundle, size_t index,
    std::shared_ptr<HapTokenInfoInner>& infoPtr)
{
    // Create token id immediately using migrated info, and set reservedType to RESERVED_DATA.
    preparedBundle.migratedInfo.reservedTypeList[index] = ReservedTypeIdl::RESERVED_DATA;

    int32_t dlpFlag = 0; // default DLP for migration
    int32_t cloneFlag = (hapBaseInfo.instIndex) > 0 ? 1 : 0;
    AccessTokenID newTokenId = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(
        TOKEN_HAP, dlpFlag, cloneFlag, 0);
    if (newTokenId == 0) {
        LOGW(ATM_DOMAIN, ATM_TAG, "CreateAndRegisterTokenId failed during ValidateAndCollectIdentityInfos.");
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
    return RET_SUCCESS;
}

int32_t ProcessSingleIdentityInfo(const MigratedInfoIdl& migratedInfo, size_t index,
    std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos,
    std::vector<bool>& newTokenFlags, PreparedMigrationBundle& preparedBundle)
{
    const auto& hapBaseInfo = migratedInfo.hapBaseInfoList[index];
    int32_t ret = CheckHapBaseInfoBasic(hapBaseInfo);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    if (hapBaseInfo.bundleName != migratedInfo.bundleName) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, bundleName mismatch in hap base info.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    int32_t uid = migratedInfo.uidList[index];

    AccessTokenIDEx tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(
        hapBaseInfo.userID, hapBaseInfo.bundleName, hapBaseInfo.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    std::shared_ptr<HapTokenInfoInner> infoPtr;
    bool isNewToken = false;
    
    ret = CheckUidIdleInKernel(uid);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    if (tokenId == 0) {
        isNewToken = true;
        ret = CreateNewTokenInfoForHap(hapBaseInfo, uid, preparedBundle, index, infoPtr);
        if (ret != RET_SUCCESS) {
            return ret;
        }
        tokenId = infoPtr->GetTokenID();
    } else {
        ret = GetCachedTokenInfo(tokenId, migratedInfo.bundleName, infoPtr);
        if (ret != RET_SUCCESS) {
            return ret;
        }
    }

    ret = CheckCachedUid(infoPtr, uid, tokenId);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Migrate bundle %{public}s with cached userId=%{public}d, instIndex=%{public}d, "
        "uid=%{public}d, tokenId=%{public}u, isNew=%{public}d.", migratedInfo.bundleName.c_str(),
        infoPtr->GetUserID(), infoPtr->GetInstIndex(), uid, tokenId, static_cast<int>(isNewToken));
    cachedInfos.emplace_back(infoPtr);
    newTokenFlags.emplace_back(isNewToken);
    return RET_SUCCESS;
}

int32_t ValidateAndCollectIdentityInfos(PreparedMigrationBundle& preparedBundle)
{
    const auto& migratedInfo = preparedBundle.migratedInfo;
    std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos = preparedBundle.cachedInfos;
    std::vector<bool>& newTokenFlags = preparedBundle.newTokenFlags;
    cachedInfos.clear();
    newTokenFlags.clear();
    cachedInfos.reserve(migratedInfo.hapBaseInfoList.size());
    newTokenFlags.reserve(migratedInfo.hapBaseInfoList.size());
    std::unordered_set<int32_t> seenUids;
    seenUids.reserve(migratedInfo.hapBaseInfoList.size());
    
    for (size_t index = 0; index < migratedInfo.hapBaseInfoList.size(); ++index) {
        int32_t uid = migratedInfo.uidList[index];
        if (!seenUids.emplace(uid).second) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Migrate installed bundles failed, duplicate uid %{public}d in one request.", uid);
            ReportSysCommonEventError(
                static_cast<int32_t>(IAccessTokenManagerIpcCode::COMMAND_MIGRATE_INSTALLED_BUNDLES),
                AccessTokenError::ERR_MIGRATION_UID_DUPLICATED);
            return AccessTokenError::ERR_MIGRATION_UID_DUPLICATED;
        }
        int32_t ret = ProcessSingleIdentityInfo(migratedInfo, index, cachedInfos,
            newTokenFlags, preparedBundle);
        if (ret != RET_SUCCESS) {
            return ret;
        }
    }
    return RET_SUCCESS;
}

int32_t ValidateMigratedInfo(const MigratedInfoIdl& migratedInfo)
{
    int32_t ret = ValidateMigratedInfoShape(migratedInfo);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    ret = ValidateReservedTypes(migratedInfo);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    return RET_SUCCESS;
}

int32_t PrepareMigrationBundle(const MigratedInfoIdl& migratedInfo, PreparedMigrationBundle& preparedBundle)
{
    preparedBundle.migratedInfo = migratedInfo;
    int32_t ret = ValidateMigratedInfo(migratedInfo);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    ret = ValidateAndCollectIdentityInfos(preparedBundle);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    return RET_SUCCESS;
}

void GenerateMigrationDelInfo(const std::vector<PreparedMigrationBundle>& preparedBundles,
    std::vector<DelInfo>& delInfoVec)
{
    for (const auto& preparedBundle : preparedBundles) {
        for (const auto& cachedInfo : preparedBundle.cachedInfos) {
            GenericValues delHapValue;
            delHapValue.Put(TokenFiledConst::FIELD_TOKEN_ID,
                static_cast<int32_t>(cachedInfo->GetHapInfoBasic().tokenID));
            GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_INFO, delHapValue, delInfoVec);
        }
    }
}

int32_t PersistMigratedBundles(const std::vector<PreparedMigrationBundle>& preparedBundles)
{
    std::vector<DelInfo> delInfoVec;
    std::vector<GenericValues> hapInfoValues;
    GenerateMigrationDelInfo(preparedBundles, delInfoVec);

    for (const auto& preparedBundle : preparedBundles) {
        int32_t ret = AccessTokenMigrationManager::GetInstance().AppendHapTokenDbInfo(
            preparedBundle, hapInfoValues);
        if (ret != RET_SUCCESS) {
            return ret;
        }
    }

    std::vector<AddInfo> addInfoVec;
    GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_INFO, hapInfoValues, addInfoVec);
    return AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
}

void UpdateMigratedCache(const std::vector<PreparedMigrationBundle>& preparedBundles)
{
    for (const auto& preparedBundle : preparedBundles) {
        for (size_t i = 0; i < preparedBundle.cachedInfos.size(); ++i) {
            preparedBundle.cachedInfos[i]->SetUid(static_cast<uint32_t>(preparedBundle.migratedInfo.uidList[i]));
        }
    }
}

int32_t ExecutePreparedMigration(std::vector<PreparedMigrationBundle>& preparedBundles)
{
    int32_t ret = PersistMigratedBundles(preparedBundles);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    UpdateMigratedCache(preparedBundles);

#ifdef IS_SUPPORT_HAP_RUNNING
    // Verify bundles, build signing info, persist to DB and add kernel data
    // after main migration succeeds. This is best-effort and does not affect
    // migration success. Verification runs asynchronously on a worker thread.
    // Skip verification for newly created tokens — they have placeholder DB rows.
    for (auto& preparedBundle : preparedBundles) {
        std::vector<std::shared_ptr<HapTokenInfoInner>> verifyInfos;
        for (size_t i = 0; i < preparedBundle.cachedInfos.size(); ++i) {
            if (i < preparedBundle.newTokenFlags.size() && preparedBundle.newTokenFlags[i]) {
                continue;
            }
            verifyInfos.emplace_back(preparedBundle.cachedInfos[i]);
        }
        if (!verifyInfos.empty()) {
            MigrationVerifyWorker::GetInstance().Submit(
                preparedBundle.migratedInfo, verifyInfos);
        }
    }
#endif
    return RET_SUCCESS;
}

int32_t MigrateSingleBundle(const MigratedInfoIdl& migratedInfo, BundleMigrateResultIdl& result)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Migration begin for bundle %{public}s, hapCount=%{public}zu.",
        migratedInfo.bundleName.c_str(), migratedInfo.hapBaseInfoList.size());
    PreparedMigrationBundle preparedBundle;
    int32_t ret = PrepareMigrationBundle(migratedInfo, preparedBundle);

    // Fill result matching hapBaseInfoList size, even on failure. Uncollected entries get INVALID_TOKENID/NONE.
    const size_t hapCount = migratedInfo.hapBaseInfoList.size();
    result.tokenIdList.reserve(hapCount);
    result.reservedTypeList.reserve(hapCount);
    for (size_t i = 0; i < hapCount; ++i) {
        if (i < preparedBundle.cachedInfos.size()) {
            AccessTokenIDEx tidEx;
            tidEx.tokenIdExStruct.tokenID = preparedBundle.cachedInfos[i]->GetHapInfoBasic().tokenID;
            tidEx.tokenIdExStruct.tokenAttr = preparedBundle.cachedInfos[i]->GetHapInfoBasic().tokenAttr;
            result.tokenIdList.emplace_back(tidEx.tokenIDEx);
            result.reservedTypeList.emplace_back(preparedBundle.migratedInfo.reservedTypeList[i]);
        } else {
            result.tokenIdList.emplace_back(INVALID_TOKENID);
            result.reservedTypeList.emplace_back(ReservedTypeIdl::NONE);
        }
    }

    if (ret != RET_SUCCESS) {
        result.errcode = ret;
        return ret;
    }

    std::vector<PreparedMigrationBundle> preparedBundles;
    preparedBundles.emplace_back(std::move(preparedBundle));
    ret = ExecutePreparedMigration(preparedBundles);
    if (ret == RET_SUCCESS) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Migration finished for bundle %{public}s, hapCount=%{public}zu, "
            "tokenIdCount=%{public}zu.",
            migratedInfo.bundleName.c_str(), migratedInfo.hapBaseInfoList.size(),
            preparedBundles.front().cachedInfos.size());
    } else {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migration failed for bundle %{public}s, ret=%{public}d.",
            migratedInfo.bundleName.c_str(), ret);
    }
    result.errcode = ret;
    return ret;
}
} // namespace

int32_t AccessTokenMigrationManager::AppendHapTokenDbInfo(
    const PreparedMigrationBundle& preparedBundle, std::vector<GenericValues>& addValues)
{
    for (size_t i = 0; i < preparedBundle.cachedInfos.size(); ++i) {
        AccessTokenID tokenId = preparedBundle.cachedInfos[i]->GetHapInfoBasic().tokenID;
        bool isNew = (i < preparedBundle.newTokenFlags.size()) && preparedBundle.newTokenFlags[i];

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
        ReservedTypeIdl reserved = ReservedTypeIdl::NONE;
        if (i < preparedBundle.migratedInfo.reservedTypeList.size()) {
            reserved = preparedBundle.migratedInfo.reservedTypeList[i];
        }
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

    // Batch-query all hap info rows for the incoming bundle names in one IN-clause call,
    // and cache them in the manager for use by AppendHapTokenDbInfo.
    {
        std::vector<VariantValue> bundleNameValues;
        for (const auto& info : migratedInfoList) {
            bundleNameValues.emplace_back(info.bundleName);
        }
        std::vector<GenericValues> dbRows;
        int32_t queryRet = AccessTokenDbOperator::Find(
            AtmDataType::ACCESSTOKEN_HAP_INFO, TokenFiledConst::FIELD_BUNDLE_NAME, bundleNameValues, dbRows);
        if (queryRet != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Batch query hap info by bundleName failed, ret=%{public}d.", queryRet);
            return ERR_DATABASE_OPERATE_FAILED;
        }

        std::unordered_map<int32_t, GenericValues> newCache;
        for (auto& row : dbRows) {
            int32_t tid = row.GetInt(TokenFiledConst::FIELD_TOKEN_ID);
            newCache[tid] = std::move(row);
        }
        dbRowCache_.swap(newCache);
    }

    for (const auto& migratedInfo : migratedInfoList) {
        BundleMigrateResultIdl migrateResult;

        // Validate every UID in this bundle was registered via PreMigrateUIDList.
        bool uidMissing = false;
        {
            std::unique_lock<std::mutex> lock(preMigratedUidLock_);
            for (int32_t uid : migratedInfo.uidList) {
                if (preMigratedUidSet_.find(uid) == preMigratedUidSet_.end()) {
                    LOGE(ATM_DOMAIN, ATM_TAG,
                        "Migrate installed bundles failed, uid %{public}d not in pre-migrated set.", uid);
                    uidMissing = true;
                    break;
                }
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
            // Remove successfully migrated UIDs from the pre-migrated set.
            std::unique_lock<std::mutex> lock(preMigratedUidLock_);
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

    // Cache the incoming UIDs so MigrateInstalledBundles can validate against them.
    {
        std::unique_lock<std::mutex> lock(preMigratedUidLock_);
        preMigratedUidSet_.insert(uidList.begin(), uidList.end());
    }

    ret = AccessTokenIDManager::GetInstance().ImportInitialUids(uidList);
    if (ret == RET_SUCCESS) {
        LOGI(ATM_DOMAIN, ATM_TAG, "PreMigrateUIDList successful, count=%{public}zu.", uidList.size());
    }
    return ret;
}

int32_t AccessTokenMigrationManager::FinishMigration() const
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
    LOGI(ATM_DOMAIN, ATM_TAG, "BMS migration completed successfully.");
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
