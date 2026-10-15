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
#include "accesstoken_info_utils.h"
#include "bundle_sign_info.h"
#include "data_validator.h"
#include "hisysevent_adapter.h"
#include "idl_common.h"
#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
#include "install_session_manager.h"
#endif
#include "parameters.h"
#include "permission_kernel_utils.h"
#ifdef IS_SUPPORT_HAP_RUNNING
#include "interfaces/hap_verify.h"
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
const std::string SYSTEM_CONFIG_TRUE_VALUE = "2";
static constexpr int32_t INVALID_HAP_UID = -1;
static constexpr size_t MAX_MIGRATED_INFO_SIZE = 50;
static constexpr int32_t IS_MIGRATED = 1;

// mode is implicitly encoded in instIndex; returns 0 (main) or 1 (sub).
static int32_t GetBundleModeFromInstIndex(int32_t instIndex)
{
    return instIndex / MAIN_CLONE_INDEX_BASE;
}

static bool IsModeInstIndexValid(int32_t mode, int32_t instIndex)
{
    if (instIndex < 0) {
        return false;
    }
    return GetBundleModeFromInstIndex(instIndex) == mode;
}

static std::string GetPlaceholderModuleName(int32_t index)
{
    return "#" + std::to_string(index);
}

static std::string GetBundleModeKey(const std::string& bundleName, int32_t mode)
{
    return bundleName + std::to_string(mode);
}

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
    if (!DataValidator::IsListSizeValid(static_cast<uint32_t>(migratedInfo.hapBaseInfoList.size()))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, hapBaseInfoList size is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    size_t hapCount = migratedInfo.hapBaseInfoList.size();
    if (migratedInfo.uidList.size() != hapCount || migratedInfo.reservedTypeList.size() != hapCount) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, list sizes mismatch.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

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
        if (!IsModeInstIndexValid(static_cast<int32_t>(migratedInfo.pathList.mode), hap.instIndex)) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Migrate installed bundles failed, mode %{public}d with instIndex %{public}d is invalid.",
                static_cast<int32_t>(migratedInfo.pathList.mode), hap.instIndex);
            return AccessTokenError::ERR_PARAM_INVALID;
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
    int32_t cachedUid = infoPtr->GetUid();
    if ((cachedUid == INVALID_HAP_UID) || (cachedUid == uid)) {
        return RET_SUCCESS;
    }
    LOGC(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, cached uid %{public}d differs from migration uid "
        "%{public}d while migrating tokenId %{public}u.", cachedUid, uid, infoPtr->GetTokenID());
    return AccessTokenError::ERR_MIGRATION_UID_EXISTED;
}

int32_t AccessTokenMigrationManager::CreateNewTokenInfoForHap(
    PreparedMigrationBundle& preparedBundle, size_t index,
    std::shared_ptr<HapTokenInfoInner>& infoPtr)
{
    LOGC(ATM_DOMAIN, ATM_TAG, "Creating new token for hap %{public}s, index=%{public}zu.",
        preparedBundle.migratedInfo.hapBaseInfoList[index].bundleName.c_str(), index);
    const auto& hapBaseInfo = preparedBundle.migratedInfo.hapBaseInfoList[index];
    int32_t uid = preparedBundle.migratedInfo.uidList[index];
    int32_t dlpFlag = 0;
    int32_t cloneFlag = ((dlpFlag == 0) && (hapBaseInfo.instIndex % MAIN_CLONE_INDEX_BASE != 0)) ? 1 : 0;
    AccessTokenID newTokenId = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(
        TOKEN_HAP, dlpFlag, cloneFlag, 0);
    if (newTokenId == 0) {
        LOGC(ATM_DOMAIN, ATM_TAG, "CreateAndRegisterTokenId failed during PrepareIdentityInfos.");
        return AccessTokenError::ERR_TOKENID_CREATE_FAILED;
    }
    infoPtr = std::make_shared<HapTokenInfoInner>();
    HapTokenInfo hapTokenInfo;
    hapTokenInfo.tokenID = newTokenId;
    hapTokenInfo.userID = hapBaseInfo.userID;
    hapTokenInfo.bundleName = hapBaseInfo.bundleName;
    hapTokenInfo.instIndex = hapBaseInfo.instIndex;
    hapTokenInfo.uid = uid;
    infoPtr->SetTokenBaseInfo(hapTokenInfo);
    infoPtr->SetMigrated(true);
    return RET_SUCCESS;
}

void AccessTokenMigrationManager::FillFailedMigrationResult(
    const MigratedInfoIdl& migratedInfo, BundleMigrateResultIdl& migrateResult)
{
    migrateResult.tokenIdList.clear();
    for (const HapBaseInfoIdl& hapBaseInfo : migratedInfo.hapBaseInfoList) {
        migrateResult.tokenIdList.emplace_back(AccessTokenInfoManager::GetInstance().GetHapTokenID(
            hapBaseInfo.userID, hapBaseInfo.bundleName, hapBaseInfo.instIndex).tokenIDEx);
    }
    migrateResult.reservedTypeList = migratedInfo.reservedTypeList;
}

int32_t AccessTokenMigrationManager::CheckDuplicateHapBaseInfo(const HapBaseInfoIdl& hapBaseInfo,
    std::unordered_set<std::string>& seenHapBaseInfos)
{
    std::string hapUniqueStr = AccessTokenInfoUtils::GetHapUniqueStr(
        hapBaseInfo.userID, hapBaseInfo.bundleName, hapBaseInfo.instIndex);
    if (seenHapBaseInfos.insert(hapUniqueStr).second) {
        return RET_SUCCESS;
    }
    LOGC(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, duplicate hapBaseInfo in bundle %{public}s.",
        hapBaseInfo.bundleName.c_str());
    return AccessTokenError::ERR_MIGRATION_UID_DUPLICATED;
}

int32_t AccessTokenMigrationManager::CheckUidConflict(const MigratedInfoIdl& migratedInfo, int32_t uid,
    std::unordered_set<int32_t>& seenInBundle) const
{
    std::string ownerKey = GetBundleModeKey(migratedInfo.bundleName, static_cast<int32_t>(migratedInfo.pathList.mode));
    auto uidOwnerIter = uidOwnerBundles_.find(uid);
    if (uidOwnerIter != uidOwnerBundles_.end()) {
        if (uidOwnerIter->second == ownerKey) {
            return RET_SUCCESS;
        }
        LOGC(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, uid %{public}d already belongs to bundle "
            "%{public}s, current bundle=%{public}s.", uid, uidOwnerIter->second.c_str(),
            ownerKey.c_str());
        return AccessTokenError::ERR_MIGRATION_UID_DUPLICATED;
    }
    if (seenInBundle.insert(uid).second) {
        return RET_SUCCESS;
    }
    LOGC(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, duplicate uid %{public}d within bundle "
        "%{public}s.", uid, ownerKey.c_str());
    return AccessTokenError::ERR_MIGRATION_UID_DUPLICATED;
}

int32_t AccessTokenMigrationManager::CheckBundleIdConflict(const MigratedInfoIdl& migratedInfo,
    const HapBaseInfoIdl& hapBaseInfo, int32_t uid, std::unordered_map<int32_t, int32_t>& bundleIdByInstIndex) const
{
    int32_t bundleId = 0;
    if (!AccessTokenIDManager::GetInstance().ExtractBundleId(uid, bundleId)) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, invalid uid %{public}d in bundle "
            "%{public}s.", uid, migratedInfo.bundleName.c_str());
        return AccessTokenError::ERR_INVALID_UID;
    }

    std::string ownerKey = GetBundleModeKey(migratedInfo.bundleName, static_cast<int32_t>(migratedInfo.pathList.mode));
    auto ownerIter = bundleIdOwnerBundles_.find(bundleId);
    if (ownerIter != bundleIdOwnerBundles_.end() && ownerIter->second != ownerKey) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, duplicate bundleId %{public}d across "
            "bundles %{public}s and %{public}s.", bundleId, ownerIter->second.c_str(),
            ownerKey.c_str());
        return AccessTokenError::ERR_MIGRATION_UID_DUPLICATED;
    }

    auto bundleIdIter = bundleIdByInstIndex.find(hapBaseInfo.instIndex);
    if (bundleIdIter == bundleIdByInstIndex.end()) {
        bundleIdByInstIndex.emplace(hapBaseInfo.instIndex, bundleId);
        return RET_SUCCESS;
    }
    if (bundleIdIter->second == bundleId) {
        return RET_SUCCESS;
    }
    LOGC(ATM_DOMAIN, ATM_TAG, "Migrate installed bundles failed, inconsistent bundleId for same instIndex "
        "%{public}d in bundle %{public}s, userId=%{public}d, bundleId=%{public}d, expected=%{public}d.",
        hapBaseInfo.instIndex, migratedInfo.bundleName.c_str(), hapBaseInfo.userID, bundleId,
        bundleIdIter->second);
    return AccessTokenError::ERR_MIGRATION_UID_DUPLICATED;
}

int32_t AccessTokenMigrationManager::CheckMigrationConflicts(const MigratedInfoIdl& migratedInfo) const
{
    std::unordered_set<int32_t> seenInBundle;
    std::unordered_set<std::string> seenHapBaseInfos;
    std::unordered_map<int32_t, int32_t> bundleIdByInstIndex;

    for (size_t i = 0; i < migratedInfo.uidList.size(); ++i) {
        int32_t uid = migratedInfo.uidList[i];
        const auto& hapBaseInfo = migratedInfo.hapBaseInfoList[i];
        int32_t ret = CheckDuplicateHapBaseInfo(hapBaseInfo, seenHapBaseInfos);
        if (ret != RET_SUCCESS) {
            return ret;
        }
        ret = CheckUidConflict(migratedInfo, uid, seenInBundle);
        if (ret != RET_SUCCESS) {
            return ret;
        }
        ret = CheckBundleIdConflict(migratedInfo, hapBaseInfo, uid, bundleIdByInstIndex);
        if (ret != RET_SUCCESS) {
            return ret;
        }
    }
    return RET_SUCCESS;
}

int32_t AccessTokenMigrationManager::PrepareIdentityInfos(PreparedMigrationBundle& preparedBundle)
{
    const auto& migratedInfo = preparedBundle.migratedInfo;
    auto& cachedInfos = preparedBundle.cachedInfos;
    auto& newTokenFlags = preparedBundle.newTokenFlags;
    size_t hapCount = migratedInfo.hapBaseInfoList.size();
    cachedInfos.reserve(hapCount);
    newTokenFlags.reserve(hapCount);

    for (size_t i = 0; i < hapCount; ++i) {
        AccessTokenID tokenId = 0;
        std::shared_ptr<HapTokenInfoInner> infoPtr;
        bool isNewToken = false;
        int32_t ret = ResolveIdentityInfo(preparedBundle, i, tokenId, infoPtr, isNewToken);
        if (ret != RET_SUCCESS) {
            return ret;
        }
        int32_t uid = migratedInfo.uidList[i];
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

int32_t AccessTokenMigrationManager::ResolveIdentityInfo(PreparedMigrationBundle& preparedBundle, size_t index,
    AccessTokenID& tokenId, std::shared_ptr<HapTokenInfoInner>& infoPtr, bool& isNewToken)
{
    const auto& migratedInfo = preparedBundle.migratedInfo;
    const auto& hapBaseInfo = migratedInfo.hapBaseInfoList[index];
    AccessTokenIDEx tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(
        hapBaseInfo.userID, hapBaseInfo.bundleName, hapBaseInfo.instIndex);
    tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    if (tokenId != 0) {
        int32_t ret = GetCachedTokenInfo(tokenId, migratedInfo.bundleName, infoPtr);
        if (ret == RET_SUCCESS) {
            preparedBundle.needVerification = true;
            SetNeedPostVerify(true);
        }
        return ret;
    }

    std::string key = AccessTokenInfoUtils::GetHapUniqueStr(
        hapBaseInfo.userID, hapBaseInfo.bundleName, hapBaseInfo.instIndex);
    auto iter = hapIdentityMap_.find(key);
    if (iter != hapIdentityMap_.end() && iter->second.tokenId != 0) {
        tokenId = static_cast<AccessTokenID>(iter->second.tokenId);
        infoPtr = AccessTokenInfoManager::GetInstance().LoadHapTokenInfoFromDbAndNoCache(
            hapBaseInfo.userID, hapBaseInfo.bundleName, hapBaseInfo.instIndex);
        if (infoPtr == nullptr) {
            LOGC(ATM_DOMAIN, ATM_TAG,
                "Load hap token info from db failed, bundle=%{public}s, instIndex=%{public}d.",
                hapBaseInfo.bundleName.c_str(), hapBaseInfo.instIndex);
            return AccessTokenError::ERR_TOKENID_NOT_EXIST;
        }
        preparedBundle.needVerification = true;
        SetNeedPostVerify(true);
        return RET_SUCCESS;
    }

    isNewToken = true;
    int32_t ret = CreateNewTokenInfoForHap(preparedBundle, index, infoPtr);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    tokenId = infoPtr->GetTokenID();
    preparedBundle.migratedInfo.reservedTypeList[index] = ReservedTypeIdl::RESERVED_DATA;
    Identity identity;
    identity.tokenId = static_cast<uint64_t>(tokenId);
    identity.uid = migratedInfo.uidList[index];
    hapIdentityMap_[key] = identity;
    return RET_SUCCESS;
}

void AccessTokenMigrationManager::BuildHapTokenDeleteInfos(const PreparedMigrationBundle& preparedBundle,
    std::vector<DelInfo>& delInfoVec)
{
    for (const auto& info : preparedBundle.cachedInfos) {
        GenericValues delValue;
        delValue.Put(TokenFiledConst::FIELD_TOKEN_ID,
            static_cast<int32_t>(info->GetHapInfoBasic().tokenID));
        delInfoVec.emplace_back(DelInfo {AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, delValue});
    }
}

void AccessTokenMigrationManager::BuildPlaceholderSignInfo(const PreparedMigrationBundle& preparedBundle,
    std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec)
{
#ifdef IS_SUPPORT_HAP_RUNNING
    if (!preparedBundle.migratedInfo.pathList.hapPaths.empty() && preparedBundle.needVerification) {
        BundleSignInfo placeholderSign;
        placeholderSign.bundleName = preparedBundle.migratedInfo.bundleName;
        placeholderSign.mode = static_cast<MultipleMode>(preparedBundle.migratedInfo.pathList.mode);
        placeholderSign.isPreInstalled = preparedBundle.migratedInfo.pathList.isPreInstalled;
        Security::Verify::BootstrapInfo sentinelBootstrap = {};
        sentinelBootstrap.version = -1;
        for (size_t i = 0; i < preparedBundle.migratedInfo.pathList.hapPaths.size(); ++i) {
            const auto& hapPath = preparedBundle.migratedInfo.pathList.hapPaths[i];
            placeholderSign.moduleNameList.emplace_back(GetPlaceholderModuleName(i)); // Just a mark for "bad module"
            placeholderSign.pathList.emplace_back(hapPath);
            placeholderSign.bundleType.emplace_back(0);
            uint8_t* dumped = sentinelBootstrap.Dump();
            std::vector<uint8_t> blob;
            if (dumped != nullptr) {
                blob.assign(dumped, dumped + sentinelBootstrap.GetSize());
                delete[] dumped;
                dumped = nullptr;
            }
            placeholderSign.persistDataList.emplace_back(std::move(blob));
        }
        std::vector<GenericValues> signValues;
        if (placeholderSign.ToGenericValues(signValues) == RET_SUCCESS) {
            GenericValues delValues;
            delValues.Put(TokenFiledConst::FIELD_BUNDLE_NAME, preparedBundle.migratedInfo.bundleName);
            delValues.Put(TokenFiledConst::FIELD_MODE, static_cast<int32_t>(preparedBundle.migratedInfo.pathList.mode));
            delInfoVec.emplace_back(DelInfo {AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, delValues});
            addInfoVec.emplace_back(AddInfo {AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, signValues});
        }
    }
#else
    (void)preparedBundle;
    (void)delInfoVec;
    (void)addInfoVec;
#endif
}

int32_t AccessTokenMigrationManager::PersistMigratedBundles(const PreparedMigrationBundle& preparedBundle)
{
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    std::vector<GenericValues> hapInfoValues;
    BuildHapTokenDeleteInfos(preparedBundle, delInfoVec);

    int32_t ret = AppendHapTokenDbInfo(preparedBundle, hapInfoValues);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    if (!hapInfoValues.empty()) {
        addInfoVec.emplace_back(AddInfo {AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, hapInfoValues});
    }
    BuildPlaceholderSignInfo(preparedBundle, delInfoVec, addInfoVec);

    std::set<int32_t> reservedBundleIdsToRemove;
    for (int32_t uid : preparedBundle.migratedInfo.uidList) {
        int32_t bundleId = 0;
        if (AccessTokenIDManager::GetInstance().ExtractBundleId(uid, bundleId) &&
            AccessTokenIDManager::GetInstance().IsReservedBundleId(uid)) {
            reservedBundleIdsToRemove.insert(bundleId);
        }
    }
    ret = AccessTokenIDManager::GetInstance().BuildReservedBundleIdsPersistInfo(
        reservedBundleIdsToRemove, delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    if (ret == RET_SUCCESS && !reservedBundleIdsToRemove.empty()) {
        (void)AccessTokenIDManager::GetInstance().RemoveReservedBundleIds(reservedBundleIdsToRemove);
    }
    return ret;
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
                LOGC(ATM_DOMAIN, ATM_TAG,
                    "Migrate installed bundles failed, tokenId %{public}u.", tokenId);
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
        addValues[valueIndex].Put(TokenFiledConst::FIELD_MIGRATED, IS_MIGRATED);
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
        // todo: install_session_manager SetMigrationDone
#if defined(IS_SUPPORT_HAP_RUNNING) && defined(IS_SUPPORT_INSTALL_SESSION_MANAGER)
        InstallSessionManager::GetInstance().SetMigrationDone();
#endif
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
    return !results.empty() && results[0].GetString(TokenFiledConst::FIELD_VALUE) == SYSTEM_CONFIG_TRUE_VALUE;
}

int32_t AccessTokenMigrationManager::LoadDbCacheIfNeeded()
{
    if (cacheLoaded_) {
        return RET_SUCCESS;
    }
    std::vector<GenericValues> dbResults;
    int32_t ret = QueryAllHapTokenRows(dbResults);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    dbRowCache_ = BuildDbRowCache(dbResults);
    uidOwnerBundles_.clear();
    bundleIdOwnerBundles_.clear();
    ret = BuildUidBundleCaches();
    if (ret != RET_SUCCESS) {
        return ret;
    }
    BuildHapIdentityMap();
    cacheLoaded_ = true;
    return RET_SUCCESS;
}

int32_t AccessTokenMigrationManager::QueryAllHapTokenRows(std::vector<GenericValues>& dbResults)
{
    GenericValues emptyCondition;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, emptyCondition, dbResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "LoadDbCacheIfNeeded query all hap info failed, ret=%{public}d.", ret);
        return ERR_DATABASE_OPERATE_FAILED;
    }
    return RET_SUCCESS;
}

std::unordered_map<int32_t, GenericValues> AccessTokenMigrationManager::BuildDbRowCache(
    std::vector<GenericValues>& dbResults)
{
    std::unordered_map<int32_t, GenericValues> newCache;
    for (auto& row : dbResults) {
        int32_t tokenId = row.GetInt(TokenFiledConst::FIELD_TOKEN_ID);
        newCache[tokenId] = std::move(row);
    }
    return newCache;
}

int32_t AccessTokenMigrationManager::BuildUidBundleCaches()
{
    for (const auto& [tokenid, row] : dbRowCache_) {
        int32_t existingUid = row.GetInt(TokenFiledConst::FIELD_UID);
        std::string bundleName = row.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
        if (existingUid < 0) {
            continue;
        }
        int32_t bundleId = 0;
        if (!AccessTokenIDManager::GetInstance().ExtractBundleId(existingUid, bundleId)) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Failed to extract bundleId from uid %{public}d "
                "for bundle %{public}s.", existingUid, bundleName.c_str());
            ReportSysCommonEventError(
                static_cast<int32_t>(IAccessTokenManagerIpcCode::COMMAND_MIGRATE_INSTALLED_BUNDLES),
                ERR_INVALID_UID);
            continue;
        }
        int32_t mode = row.GetInt(TokenFiledConst::FIELD_INST_INDEX) / MAIN_CLONE_INDEX_BASE;
        std::string ownerKey = GetBundleModeKey(bundleName, mode);
        if (bundleIdOwnerBundles_.count(bundleId) == 0) {
            uidOwnerBundles_[existingUid] = ownerKey;
            bundleIdOwnerBundles_[bundleId] = ownerKey;
            continue;
        }
        LOGC(ATM_DOMAIN, ATM_TAG, "Found same bundleId bundle %{public}s and %{public}s for uid %{public}d.",
            bundleIdOwnerBundles_[bundleId].c_str(),
            ownerKey.c_str(), existingUid);
        ReportSysCommonEventError(
            static_cast<int32_t>(IAccessTokenManagerIpcCode::COMMAND_MIGRATE_INSTALLED_BUNDLES),
            ERR_INVALID_UID);
    }
    return RET_SUCCESS;
}

void AccessTokenMigrationManager::BuildHapIdentityMap()
{
    hapIdentityMap_.clear();
    for (const auto& [tokenId, row] : dbRowCache_) {
        int32_t userID = row.GetInt(TokenFiledConst::FIELD_USER_ID);
        std::string bundleName = row.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
        int32_t instIndex = row.GetInt(TokenFiledConst::FIELD_INST_INDEX);
        Identity identity;
        identity.tokenId = static_cast<uint64_t>(tokenId);
        identity.uid = row.GetInt(TokenFiledConst::FIELD_UID);
        hapIdentityMap_[AccessTokenInfoUtils::GetHapUniqueStr(userID, bundleName, instIndex)] = identity;
    }
}

BundleMigrateResultIdl AccessTokenMigrationManager::ProcessBundleMigration(
    const MigratedInfoIdl& migratedInfo)
{
    BundleMigrateResultIdl migrateResult;
    int32_t conflictRet = CheckMigrationConflicts(migratedInfo);
    if (conflictRet != RET_SUCCESS) {
        FillFailedMigrationResult(migratedInfo, migrateResult);
        migrateResult.errcode = conflictRet;
        return migrateResult;
    }

    int32_t singleRet = MigrateSingleBundle(migratedInfo, migrateResult);
    if (singleRet == RET_SUCCESS) {
        std::string ownerKey = GetBundleModeKey(migratedInfo.bundleName,
            static_cast<int32_t>(migratedInfo.pathList.mode));
        for (size_t i = 0; i < migratedInfo.hapBaseInfoList.size(); ++i) {
            const auto& hapBaseInfo = migratedInfo.hapBaseInfoList[i];
            std::string key = AccessTokenInfoUtils::GetHapUniqueStr(
                hapBaseInfo.userID, hapBaseInfo.bundleName, hapBaseInfo.instIndex);
            auto iter = hapIdentityMap_.find(key);
            if (iter != hapIdentityMap_.end()) {
                iter->second.uid = migratedInfo.uidList[i];
            }
        }
        for (int32_t uid : migratedInfo.uidList) {
            AccessTokenIDManager::GetInstance().InitSingleBundleIdCache(uid);
            uidOwnerBundles_[uid] = ownerKey;
            int32_t bundleId = 0;
            if (AccessTokenIDManager::GetInstance().ExtractBundleId(uid, bundleId)) {
                bundleIdOwnerBundles_[bundleId] = ownerKey;
            }
        }
    }
    return migrateResult;
}

int32_t AccessTokenMigrationManager::MigrateInstalledBundles(
    const std::vector<MigratedInfoIdl>& migratedInfoList, std::vector<BundleMigrateResultIdl>& results)
{
    std::lock_guard<std::mutex> lock(migrationMutex_);
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

    int32_t ret = LoadDbCacheIfNeeded();
    if (ret != RET_SUCCESS) {
        return ret;
    }
    for (const auto& migratedInfo : migratedInfoList) {
        BundleMigrateResultIdl migrateResult = ProcessBundleMigration(migratedInfo);
        int32_t errCode = migrateResult.errcode;
        if (errCode == RET_SUCCESS) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Bundle %{public}s migration succeeded, hapCount=%{public}zu.",
                migratedInfo.bundleName.c_str(), migratedInfo.hapBaseInfoList.size());
        } else {
            LOGC(ATM_DOMAIN, ATM_TAG, "Bundle %{public}s migration failed, ret=%{public}d.",
                migratedInfo.bundleName.c_str(), errCode);
        }
        ReportSysCommonEventError(
            static_cast<int32_t>(IAccessTokenManagerIpcCode::COMMAND_MIGRATE_INSTALLED_BUNDLES), errCode);
        results.emplace_back(std::move(migrateResult));
    }
    return RET_SUCCESS;
}

int32_t AccessTokenMigrationManager::FinishMigration()
{
    std::lock_guard<std::mutex> lock(migrationMutex_);
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
    // refresh next bundle id after migration, to avoid uid conflict with migrated hap
    (void)AccessTokenIDManager::GetInstance().InitBundleIdConfig();
#if defined(IS_SUPPORT_HAP_RUNNING) && defined(IS_SUPPORT_INSTALL_SESSION_MANAGER)
    InstallSessionManager::GetInstance().SetMigrationDone();
#endif
    ReportInvalidUidsIfNeeded();
    ResetMigrationCache();
    LOGI(ATM_DOMAIN, ATM_TAG, "BMS migration completed successfully.");
    return RET_SUCCESS;
}

int32_t AccessTokenMigrationManager::CheckMigratedUidSet(
    const std::set<int32_t>& totalUids, std::set<int32_t>& unreceivedUids)
{
    std::lock_guard<std::mutex> lock(migrationMutex_);
    unreceivedUids.clear();

    std::set<int32_t> serviceUids;
    for (const auto& entry : hapIdentityMap_) {
        serviceUids.insert(entry.second.uid);
    }
    for (int32_t uid : totalUids) {
        if (serviceUids.count(uid) == 0) {
            unreceivedUids.insert(uid);
        }
    }

    std::set<int32_t> reservedBundleIds;
    for (int32_t uid : unreceivedUids) {
        int32_t bundleId = 0;
        if (!AccessTokenIDManager::GetInstance().ExtractBundleId(uid, bundleId)) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Invalid uid=%{public}d in CheckMigratedUidSet.", uid);
            continue;
        }
        if (AccessTokenIDManager::GetInstance().IsBundleIdOccupied(bundleId)) {
            LOGW(ATM_DOMAIN, ATM_TAG, "bundleId=%{public}d is occupied, skip reserve.", bundleId);
            continue;
        }
        reservedBundleIds.insert(bundleId);
    }
    if (reservedBundleIds.empty()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Reserved bundleIds is empty.");
        return RET_SUCCESS;
    }
    return AccessTokenIDManager::GetInstance().RefreshReservedBundleIdSet(reservedBundleIds);
}

void AccessTokenMigrationManager::ReportInvalidUidsIfNeeded()
{
    GenericValues uidCondition;
    uidCondition.Put(TokenFiledConst::FIELD_UID, INVALID_HAP_UID);
    std::vector<GenericValues> invalidUidResults;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, uidCondition, invalidUidResults);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Query invalid uid hap info failed, ret=%{public}d.", ret);
        return;
    }
    for (const auto& row : invalidUidResults) {
        AccessTokenID tokenId = static_cast<AccessTokenID>(row.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
        std::string bundleName = row.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
        int32_t instIndex = row.GetInt(TokenFiledConst::FIELD_INST_INDEX);
        LOGC(ATM_DOMAIN, ATM_TAG,
            "FinishMigration cleaned invalid uid for tokenId=%{public}u, bundle=%{public}s, instIndex=%{public}d.",
            tokenId, bundleName.c_str(), instIndex);
        ReportSysCommonEventError(
            static_cast<int32_t>(IAccessTokenManagerIpcCode::COMMAND_FINISH_MIGRATION),
            ERR_INVALID_UID);
    }
}

void AccessTokenMigrationManager::ResetMigrationCache()
{
    dbRowCache_.clear();
    uidOwnerBundles_.clear();
    bundleIdOwnerBundles_.clear();
    hapIdentityMap_.clear();
    cacheLoaded_ = false;
}

void AccessTokenMigrationManager::SetNeedPostVerify(bool need)
{
    needPostVerify_.store(need);
}

bool AccessTokenMigrationManager::IsNeedPostVerify() const
{
    return needPostVerify_.load();
}

void AccessTokenMigrationManager::TryPostVerify()
{
#ifdef IS_SUPPORT_HAP_RUNNING
    if (!needPostVerify_.load()) {
        return;
    }
    needPostVerify_.store(false);
    MigrationVerifyHelper::GetInstance().PostVerifyMigratedBundlesTask();
#endif
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
