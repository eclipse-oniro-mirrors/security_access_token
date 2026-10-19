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

#include "boot_verify_scheduler.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <set>
#include <thread>
#include <unistd.h>
#include <utility>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_info_manager.h"
#ifdef SPM_DATA_ENABLE
#include "accesstoken_migration_manager.h"
#endif
#include "add_spm_data_task.h"
#include "data_translator.h"
#include "hisysevent_adapter.h"
#if defined(IS_SUPPORT_HAP_RUNNING)
#include "hap_sign_verify_helper.h"
#include "multiple_mode_utils.h"
#include "permission_map.h"
#include "permission_constraint_check.h"
#include "permission_manager.h"
#endif
#include "parameter.h"
#include "time_util.h"
#include "user_policy_manager.h"
#include "accesstoken_info_utils.h"
#include "add_spm_data_task.h"
#include "kernel_and_db_transaction.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
#if !defined(IS_SUPPORT_HAP_RUNNING)
BootVerifyScheduler& BootVerifyScheduler::GetInstance()
{
    static BootVerifyScheduler instance;
    return instance;
}

int32_t BootVerifyScheduler::VerifyBundleSignInfoWhenStart(
    uint32_t& hapSize, std::map<int32_t, TokenIdInfo>& tokenIdAplMap)
{
    (void)hapSize;
    (void)tokenIdAplMap;
    return RET_SUCCESS;
}

void BootVerifyScheduler::StartVerifyNormalBundleListAsync()
{}

int32_t BootVerifyScheduler::PreVerifyBundle(const std::string& bundleName)
{
    (void)bundleName;
    return RET_SUCCESS;
}

int32_t BootVerifyScheduler::PreVerifyBundle(const std::string& bundleName, int32_t instIndex)
{
    (void)bundleName;
    (void)instIndex;
    return RET_SUCCESS;
}

int32_t BootVerifyScheduler::PreVerifyBundle(uint32_t tokenID)
{
    (void)tokenID;
    return RET_SUCCESS;
}

int32_t BootVerifyScheduler::PreVerifyBundle(int32_t uid)
{
    (void)uid;
    return RET_SUCCESS;
}
#else
namespace {
constexpr uint32_t VERIFY_THREAD_COUNT = 4;
constexpr AccessTokenID INVALID_TOKEN_ID = 0;
constexpr uint32_t IS_KERNEL_EFFECT = (0x1 << 0);
constexpr uint32_t HAS_VALUE = (0x1 << 1);
constexpr uint32_t API_VERSION_SUFFIX_LEN = 3;
constexpr int32_t INVALID_UID = -1;
constexpr int32_t VERIFY_WAIT_TIMEOUT_SECONDS = 3;
constexpr uint32_t SYSTEM_APP_FLAG = 0x0001;
const std::string APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
const std::string APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL = "enterprise_normal";
const std::string APP_DISTRIBUTION_TYPE_NONE = "none";
#ifdef SPM_DATA_ENABLE
const std::string BMS_DB_DIR_PATH = "/data/service/el1/public/bms/bundle_manager_service/";
const std::string BMS_DB_FILE_NAME = "bmsdb.db";
const std::string BMS_SLAVE_DB_FILE_NAME = "bmsdb_slave.db";
#endif

#ifdef SPM_DATA_ENABLE
bool IsBmsDbExisted()
{
    for (const auto& dbPath : { BMS_DB_DIR_PATH + BMS_DB_FILE_NAME, BMS_DB_DIR_PATH + BMS_SLAVE_DB_FILE_NAME }) {
        if (access(dbPath.c_str(), F_OK) == 0) {
            return true;
        }
    }
    return false;
}
#endif

int32_t GetStoredApiVersion(int32_t apiVersion)
{
    std::string apiStr = std::to_string(apiVersion);
    if (apiStr.length() <= API_VERSION_SUFFIX_LEN) {
        return apiVersion;
    }
    return std::atoi(apiStr.substr(apiStr.length() - API_VERSION_SUFFIX_LEN).c_str());
}

void ReportNormalBundleVerifyFinish(uint32_t hapSize)
{
    InitDfxInfo dfxInfo = {};
    dfxInfo.hapSize = hapSize;
    ReportSysEventServiceStart(dfxInfo);
}

void ReportPreVerifyAddHapEvent(const std::string& key,
    const std::map<std::string, std::shared_ptr<BundleInfoInner>>& bundleInfoMap,
    const std::map<int, HapTokenInfoItem>& hapTokenInfoMap)
{
    AccessTokenID tokenId = INVALID_TOKEN_ID;
    const HapTokenInfoItem* hapInfo = nullptr;
    auto bundleIter = bundleInfoMap.find(key);
    if (bundleIter != bundleInfoMap.end() && bundleIter->second != nullptr &&
        !bundleIter->second->tokenIds.empty()) {
        tokenId = bundleIter->second->tokenIds[0];
        auto hapIter = hapTokenInfoMap.find(tokenId);
        if (hapIter != hapTokenInfoMap.end()) {
            hapInfo = &(hapIter->second);
        }
    }

    HapDfxInfo dfxInfo = {};
    dfxInfo.sceneCode = AddHapSceneCode::PRE_VERIFY;
    dfxInfo.bundleName = key;
    dfxInfo.tokenId = tokenId;
    dfxInfo.oriTokenId = tokenId;
    dfxInfo.tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    if (hapInfo != nullptr) {
        dfxInfo.userID = static_cast<int32_t>(hapInfo->uid);
        dfxInfo.instIndex = hapInfo->instIndex;
        dfxInfo.dlpType = static_cast<HapDlpType>(hapInfo->dlpType);
        dfxInfo.tokenIdEx.tokenIdExStruct.tokenAttr = hapInfo->tokenAttr;
    }
    ReportSysEventAddHap(RET_SUCCESS, dfxInfo, false);
}

void MergeBriefPermData(std::vector<BriefPermData>& permBriefDataList, const BriefPermData& data)
{
    for (auto& item : permBriefDataList) {
        if (item.permCode == data.permCode) {
            item.status = data.status;
            item.flag = data.flag;
            item.type = data.type;
            return;
        }
    }
    permBriefDataList.emplace_back(data);
}

void BuildExtendedPermListFromPolicy(const HapPolicy& policy, std::vector<PermissionWithValue>& extendPermList)
{
    extendPermList.clear();
    for (const auto& [permissionName, value] : policy.aclExtendedMap) {
        PermissionBriefDef permissionBriefDef;
        if (!GetPermissionBriefDef(permissionName, permissionBriefDef) || !permissionBriefDef.isEnable) {
            continue;
        }
        PermissionWithValue item;
        item.permissionName = permissionName;
        item.value = value;
        extendPermList.emplace_back(item);
    }
}

void ConvertBriefPermDataToGenericValues(AccessTokenID tokenId,
    const std::vector<BriefPermData>& briefPermDataList, std::vector<GenericValues>& genericValuesList)
{
    uint64_t currentTimestamp = static_cast<uint64_t>(TimeUtil::GetCurrentTimestamp());
    for (const auto& data : briefPermDataList) {
        std::string permissionName = TransferOpcodeToPermission(data.permCode);
        if (permissionName.empty()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TransferOpcodeToPermission failed code=%{public}d", data.permCode);
            continue;
        }
        GenericValues value;
        value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
        value.Put(TokenFiledConst::FIELD_DEVICE_ID, "PHONE-001");
        value.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
        value.Put(TokenFiledConst::FIELD_GRANT_STATE, static_cast<int32_t>(data.status));
        value.Put(TokenFiledConst::FIELD_GRANT_FLAG, static_cast<int32_t>(data.flag));
        value.Put(TokenFiledConst::FIELD_TIMESTAMP, static_cast<int64_t>(currentTimestamp));
        genericValuesList.emplace_back(value);
    }
}

bool IsExtendedPermListEqual(const std::vector<PermissionWithValue>& dbPerms,
    const std::vector<PermissionWithValue>& hapPerms)
{
    if (dbPerms.size() != hapPerms.size()) {
        return false;
    }
    std::map<std::string, std::string> dbPermMap;
    std::map<std::string, std::string> hapPermMap;
    for (const auto& perm : dbPerms) {
        dbPermMap[perm.permissionName] = perm.value;
    }
    for (const auto& perm : hapPerms) {
        hapPermMap[perm.permissionName] = perm.value;
    }
    return dbPermMap == hapPermMap;
}

void ConvertExtendPermToGenericValues(AccessTokenID tokenId,
    const std::vector<PermissionWithValue>& extendPermList, std::vector<GenericValues>& genericValuesList)
{
    for (const auto& extendPerm : extendPermList) {
        GenericValues value;
        value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, extendPerm.permissionName);
        value.Put(TokenFiledConst::FIELD_VALUE, extendPerm.value);
        genericValuesList.emplace_back(value);
    }
}

HapTokenInfo ConvertToHapTokenInfo(const HapTokenInfoItem& item)
{
    HapTokenInfo hapInfo;
    hapInfo.tokenID = item.tokenId;
    hapInfo.userID = static_cast<int32_t>(item.userId);
    hapInfo.bundleName = item.bundleName;
    hapInfo.instIndex = static_cast<int32_t>(item.instIndex);
    hapInfo.dlpType = item.dlpType;
    hapInfo.apiVersion = GetStoredApiVersion(item.apiVersion);
    hapInfo.uid = static_cast<int32_t>(item.uid);
    hapInfo.ver = static_cast<char>(item.version);
    hapInfo.tokenAttr = item.tokenAttr;
    return hapInfo;
}
}

BootVerifyScheduler& BootVerifyScheduler::GetInstance()
{
    static BootVerifyScheduler instance;
    return instance;
}

int32_t BootVerifyScheduler::LoadVerifyDataFromDb(std::map<int32_t, TokenIdInfo>& tokenIdAplMap)
{
    GenericValues conditionValue;
    std::vector<GenericValues> hapTokenRes;
    std::vector<GenericValues> permStateRes;
    std::vector<GenericValues> extendedPermRes;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, hapTokenRes);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Load hap token info failed, ret=%{public}d.", ret);
        return ret;
    }
#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
    bool migrationCompleted = AccessTokenMigrationManager::GetInstance().IsMigrationCompleted();
    if (!migrationCompleted && hapTokenRes.empty() && !IsBmsDbExisted()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Access token database is empty and BMS database does not exist, "
            "mark migration completed.");
        int32_t markRet = AccessTokenMigrationManager::MarkMigrationCompleted();
        if (markRet != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Mark migration completed failed, ret=%{public}d.", markRet);
        } else {
            migrationCompleted = true;
        }
    }
    migrationCompleted_.store(
        migrationCompleted ? migrationCompleted : AccessTokenMigrationManager::GetInstance().IsMigrationCompleted());
#endif
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateRes);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Load permission state failed, ret=%{public}d.", ret);
        return ret;
    }
    ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, conditionValue, extendedPermRes);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Load extended permission failed, ret=%{public}d.", ret);
        extendedPermRes.clear();
    }
    tokenIdAplMap.clear();
    for (const auto& tokenValue : hapTokenRes) {
        int32_t tokenId = tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID);
        TokenIdInfo tokenIdInfo;
        tokenIdInfo.apl = tokenValue.GetInt(TokenFiledConst::FIELD_APL);
        tokenIdInfo.isSystemApp = AccessTokenInfoUtils::CheckSpecifiedFlag(
            tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ATTR), SYSTEM_APP_FLAG);
        tokenIdAplMap[tokenId] = tokenIdInfo;
    }
    InitBundleVerifyContext(hapTokenRes, permStateRes, extendedPermRes);
    return RefreshBundleSignInfoMap();
}

std::vector<DelInfo> BootVerifyScheduler::BuildDeleteInfos(const std::vector<BundleSignInfo>& infos)
{
    std::vector<DelInfo> delInfoVec;
    for (const auto& info : infos) {
        GenericValues conditionValue;
        conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, info.bundleName);
        conditionValue.Put(TokenFiledConst::FIELD_MODE, static_cast<int32_t>(info.mode));
        delInfoVec.emplace_back(DelInfo { AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue });
    }
    return delInfoVec;
}

void BootVerifyScheduler::InitBundleVerifyContext(const std::vector<GenericValues>& hapTokenRes,
    const std::vector<GenericValues>& permStateRes, const std::vector<GenericValues>& extendedPermRes)
{
    std::map<AccessTokenID, std::vector<GenericValues>> permStateMap;
    std::map<AccessTokenID, std::vector<GenericValues>> extendedPermMap;
    InitPermStateContext(permStateRes, permStateMap);
    InitExtendedPermContext(extendedPermRes, extendedPermMap);
    InitHapTokenContext(hapTokenRes, permStateMap, extendedPermMap);
}

void BootVerifyScheduler::ClearBundleVerifyContext()
{
    std::lock_guard<std::mutex> lock(verifyMutex_);
    bundleInfoMap_.clear();
    bundleNoCachedInfoMap_.clear();
    hapTokenInfoMap_.clear();
    requestedPermData_.clear();
    extendedPermMap_.clear();
    isVerifiedMap_.clear();
    isVerifyingMap_.clear();
    highPrivilegeBundleList_.clear();
    normalBundleList_.clear();
    bundleSignInfoMap_.clear();
    uidSet_.clear();
}

void BootVerifyScheduler::InitPermStateContext(const std::vector<GenericValues>& permStateRes,
    std::map<AccessTokenID, std::vector<GenericValues>>& permStateMap)
{
    for (const auto& permStateValue : permStateRes) {
        AccessTokenID tokenId = static_cast<AccessTokenID>(permStateValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
        permStateMap[tokenId].emplace_back(permStateValue);
    }
}

void BootVerifyScheduler::InitExtendedPermContext(const std::vector<GenericValues>& extendedPermRes,
    std::map<AccessTokenID, std::vector<GenericValues>>& extendedPermMap)
{
    for (const auto& permValue : extendedPermRes) {
        AccessTokenID tokenId = static_cast<AccessTokenID>(permValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
        extendedPermMap[tokenId].emplace_back(permValue);
        PermissionWithValue perm;
        if (DataTranslator::TranslationIntoExtendedPermission(permValue, perm) != RET_SUCCESS) {
            LOGD(ATM_DOMAIN, ATM_TAG, "Translate extended permission failed, tokenId=%{public}u.", tokenId);
            continue;
        }
        if (!IsDefinedPermissionInner(perm.permissionName)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Permission %{public}s is not defined, tokenId=%{public}u.",
                perm.permissionName.c_str(), tokenId);
            continue;
        }
        extendedPermMap_[tokenId].emplace_back(perm);
    }
}

void BootVerifyScheduler::InitHapTokenContext(const std::vector<GenericValues>& hapTokenRes,
    const std::map<AccessTokenID, std::vector<GenericValues>>& permStateMap,
    const std::map<AccessTokenID, std::vector<GenericValues>>& extendedPermMap)
{
    for (const auto& tokenValue : hapTokenRes) {
        if (!InitSingleHapTokenContext(tokenValue, permStateMap, extendedPermMap)) {
            continue;
        }
    }
}

bool BootVerifyScheduler::InitHapInfoUid(const std::string& bundleName, AccessTokenID tokenId, int32_t uid)
{
    if (uid <= 0) {
        return true;
    }

    if (uidSet_.count(uid) == 0) {
        uidSet_.insert(uid);
        AccessTokenIDManager::GetInstance().InitSingleBundleIdCache(uid);
        return true;
    }
    LOGC(ATM_DOMAIN, ATM_TAG, "Duplicate uid found for tokenId=%{public}u, uid=%{public}d.", tokenId, uid);
    ReportSysCommonEventError(AccessTokenServiceStartSceneCode::REGISTER_UID,
        AccessTokenServiceStartErrorCode::UID_CONFLICT);
    return false;
}

bool BootVerifyScheduler::InitSingleHapTokenContext(const GenericValues& tokenValue,
    const std::map<AccessTokenID, std::vector<GenericValues>>& permStateMap,
    const std::map<AccessTokenID, std::vector<GenericValues>>& extendedPermMap)
{
    const std::string bundleName = tokenValue.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
    AccessTokenID tokenId = static_cast<AccessTokenID>(tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
    if (bundleName.empty() || tokenId == INVALID_TOKEN_ID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Init token context failed, bundleName=%{public}s, tokenId=%{public}u.",
            bundleName.c_str(), tokenId);
        return false;
    }
    bool isReservedToken = false;
    AccessTokenInfoManager::GetInstance().AddReservedHapInfoFromDbValues(tokenValue, isReservedToken);
    if (isReservedToken) {
#ifdef SPM_DATA_ENABLE
        int32_t uid = tokenValue.GetInt(TokenFiledConst::FIELD_UID);
        (void)InitHapInfoUid(bundleName, tokenId, uid);
#endif
        return false;
    }

    HapTokenInfoItem hapTokenInfoItem;
    if (!BuildHapTokenInfoItemFromDb(tokenId, tokenValue, hapTokenInfoItem)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build hap token info failed, tokenId=%{public}u.", tokenId);
        return false;
    }
    const std::vector<GenericValues> emptyPermState;
    auto permStateIter = permStateMap.find(tokenId);
    std::vector<BriefPermData> briefPermData;
    const auto& permStateValues = (permStateIter == permStateMap.end()) ? emptyPermState : permStateIter->second;
    BuildBriefPermDataFromDb(permStateValues, briefPermData);

    int32_t ret = AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "RegisterTokenId failed, tokenId=%{public}u, ret=%{public}d.", tokenId, ret);
        ReportSysCommonEventError(AccessTokenServiceStartSceneCode::REGISTER_TOKEN_ID,
            AccessTokenServiceStartErrorCode::REGISTER_TOKEN_ID_FAILED);
        return false;
    }
#if SPM_DATA_ENABLE
    if (!InitHapInfoUid(bundleName, tokenId, static_cast<int32_t>(hapTokenInfoItem.uid))) {
        return false;
    }
#endif
    hapTokenInfoMap_[tokenId] = hapTokenInfoItem;
    requestedPermData_[tokenId] = briefPermData;

    UpdateBundleVerifyContext(bundleName, tokenId, tokenValue, briefPermData);
    return true;
}

bool BootVerifyScheduler::BuildHapTokenInfoItemFromDb(AccessTokenID tokenId, const GenericValues& tokenValue,
    HapTokenInfoItem& hapTokenInfoItem)
{
    hapTokenInfoItem.tokenId = tokenId;
    hapTokenInfoItem.userId = static_cast<uint32_t>(tokenValue.GetInt(TokenFiledConst::FIELD_USER_ID));
    hapTokenInfoItem.bundleName = tokenValue.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
    if (hapTokenInfoItem.bundleName.empty()) {
        return false;
    }
    hapTokenInfoItem.apiVersion = tokenValue.GetInt(TokenFiledConst::FIELD_API_VERSION);
    hapTokenInfoItem.instIndex = static_cast<uint32_t>(tokenValue.GetInt(TokenFiledConst::FIELD_INST_INDEX));
    hapTokenInfoItem.dlpType = static_cast<HapDlpType>(tokenValue.GetInt(TokenFiledConst::FIELD_DLP_TYPE));
    hapTokenInfoItem.appId = tokenValue.GetString(TokenFiledConst::FIELD_APP_ID);
    hapTokenInfoItem.version = static_cast<uint32_t>(tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_VERSION));
    hapTokenInfoItem.tokenAttr = static_cast<uint32_t>(tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ATTR));
    hapTokenInfoItem.apl = static_cast<ATokenAplEnum>(tokenValue.GetInt(TokenFiledConst::FIELD_APL));
    hapTokenInfoItem.deviceId = tokenValue.GetString(TokenFiledConst::FIELD_DEVICE_ID);
    hapTokenInfoItem.permDialogCapState = tokenValue.GetInt(TokenFiledConst::FIELD_FORBID_PERM_DIALOG) != 0;
    hapTokenInfoItem.isSideload = tokenValue.GetInt(TokenFiledConst::FIELD_IS_SIDELOAD) != 0;
#ifdef SPM_DATA_ENABLE
    hapTokenInfoItem.reserved = static_cast<ReservedType>(tokenValue.GetInt(TokenFiledConst::FIELD_RESERVED));
    hapTokenInfoItem.migrated = tokenValue.GetInt(TokenFiledConst::FIELD_MIGRATED) != 0;
    hapTokenInfoItem.uid = tokenValue.GetInt(TokenFiledConst::FIELD_UID);
#endif

    return true;
}

void BootVerifyScheduler::BuildBriefPermDataFromDb(const std::vector<GenericValues>& permStateValues,
    std::vector<BriefPermData>& briefPermData)
{
    briefPermData.clear();
    for (const auto& stateValue : permStateValues) {
        PermissionStatus state;
        if (DataTranslator::TranslationIntoPermissionStatus(stateValue, state) != RET_SUCCESS) {
            continue;
        }
        uint32_t permCode = 0;
        PermissionBriefDef briefDef;
        if (!GetPermissionBriefDef(state.permissionName, briefDef, permCode) || !briefDef.isEnable) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Permission %{public}s is invalid or disabled, skip.",
                state.permissionName.c_str());
            continue;
        }

        BriefPermData data {};
        data.status = static_cast<int8_t>(state.grantStatus);
        data.permCode = static_cast<uint16_t>(permCode);
        data.flag = state.grantFlag;
        if (briefDef.isKernelEffect) {
            data.type |= IS_KERNEL_EFFECT;
        }
        if (briefDef.hasValue) {
            data.type |= HAS_VALUE;
        }
        MergeBriefPermData(briefPermData, data);
    }
}

void BootVerifyScheduler::UpdateBundleVerifyContext(const std::string& bundleName, AccessTokenID tokenId,
    const GenericValues& tokenValue, const std::vector<BriefPermData>& briefPermData)
{
    int32_t mode = static_cast<int32_t>(
        MultipleModeUtils::GetTokenMode(tokenValue.GetInt(TokenFiledConst::FIELD_INST_INDEX)));
    std::string key = MultipleModeUtils::GetBundleModeKey(bundleName, mode);
    auto& bundleInfo = bundleInfoMap_[key];
    if (bundleInfo == nullptr) {
        bundleInfo = std::make_shared<BundleInfoInner>();
    }
    bundleInfo->tokenIds.emplace_back(tokenId);
    bundleNoCachedInfoMap_[key].apl =
        static_cast<ATokenAplEnum>(tokenValue.GetInt(TokenFiledConst::FIELD_APL));
    for (const auto& permData : briefPermData) {
        if (std::find(bundleInfo->permCodeList.begin(), bundleInfo->permCodeList.end(), permData.permCode) ==
            bundleInfo->permCodeList.end()) {
            bundleInfo->permCodeList.emplace_back(static_cast<uint16_t>(permData.permCode));
        }
    }
}

void BootVerifyScheduler::BuildPriorityBundleList()
{
    std::set<std::string> bundleKeySet;
    CollectBundleKeySet(bundleKeySet);
    for (const auto& key : bundleKeySet) {
        ClassifyBundle(key);
    }
    SortPriorityBundleList();
}

void BootVerifyScheduler::CollectBundleKeySet(std::set<std::string>& bundleKeySet)
{
    for (const auto& item : bundleSignInfoMap_) {
        bundleKeySet.insert(item.first);
    }
    for (const auto& item : hapTokenInfoMap_) {
        if (item.second.bundleName.empty()) {
            continue;
        }
        int32_t mode = static_cast<int32_t>(
            MultipleModeUtils::GetTokenMode(static_cast<int32_t>(item.second.instIndex)));
        bundleKeySet.insert(MultipleModeUtils::GetBundleModeKey(item.second.bundleName, mode));
    }
}

void BootVerifyScheduler::ClassifyBundle(const std::string& key)
{
    if (bundleInfoMap_[key] == nullptr) {
        bundleInfoMap_[key] = std::make_shared<BundleInfoInner>();
    }
    isVerifiedMap_[key] = false;
    isVerifyingMap_[key] = false;
#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
    if (!migrationCompleted_.load()) {
        // Migration not completed, verify all bundles with high priority.
        highPrivilegeBundleList_.emplace_back(key);
        return;
    }
#endif

    auto signInfoIter = bundleSignInfoMap_.find(key);
    if (signInfoIter == bundleSignInfoMap_.end()) {
        // only has hap token info, no sign info, treat as high privilege bundle
        highPrivilegeBundleList_.emplace_back(key);
        return;
    }
    if (signInfoIter->second.isPreInstalled) {
        highPrivilegeBundleList_.emplace_back(key);
    } else {
        normalBundleList_.emplace_back(key);
    }
}

void BootVerifyScheduler::SortPriorityBundleList()
{
    // sort the bundle list by the number of paths in descending order, and then by bundle key in ascending order
    auto bundleComparator = [this](const std::string& left, const std::string& right) {
        size_t leftCount = 0;
        auto leftIter = bundleSignInfoMap_.find(left);
        if (leftIter != bundleSignInfoMap_.end()) {
            leftCount = leftIter->second.pathList.size();
        }
        size_t rightCount = 0;
        auto rightIter = bundleSignInfoMap_.find(right);
        if (rightIter != bundleSignInfoMap_.end()) {
            rightCount = rightIter->second.pathList.size();
        }
        if (leftCount != rightCount) {
            return leftCount > rightCount;
        }
        return left < right;
    };
    std::sort(highPrivilegeBundleList_.begin(), highPrivilegeBundleList_.end(), bundleComparator);
    std::sort(normalBundleList_.begin(), normalBundleList_.end(), bundleComparator);
}

int32_t BootVerifyScheduler::RefreshBundleSignInfoMap()
{
#ifdef SPM_DATA_ENABLE
    std::vector<GenericValues> results;
    GenericValues conditionValue;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, results);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get bundle sign info failed, ret=%{public}d.", ret);
        return ret;
    }

    for (const auto& result : results) {
        std::string bundleName = result.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
        int32_t mode = result.GetInt(TokenFiledConst::FIELD_MODE);
        if (mode < 0) {
            mode = 0;
        }
        std::string key = MultipleModeUtils::GetBundleModeKey(bundleName, mode);
        auto& info = bundleSignInfoMap_[key];
        int32_t bundleType = result.GetInt(TokenFiledConst::FIELD_BUNDLE_TYPE);
        if (bundleType != static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP) &&
            bundleType != static_cast<int32_t>(AppExecFwk::Spm::BundleType::ATOMIC_SERVICE) &&
            bundleType != static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP_SERVICE_FWK)) {
            LOGI(ATM_DOMAIN, ATM_TAG,
                "bundleName=%{public}s, bundleType=%{public}d is not necessary to load into cache.",
                bundleName.c_str(), bundleType);
            continue;
        }
        info.bundleType.emplace_back(static_cast<uint32_t>(bundleType));
        info.bundleName = bundleName;
        info.mode = static_cast<MultipleMode>(mode);
        info.isPreInstalled = (result.GetInt(TokenFiledConst::FIELD_IS_PREINSTALLED) != 0);
        info.moduleNameList.emplace_back(result.GetString(TokenFiledConst::FIELD_MODULE_NAME));
        info.pathList.emplace_back(result.GetString(TokenFiledConst::FIELD_PATH));
        info.persistDataList.emplace_back(result.GetBlob(TokenFiledConst::FIELD_PERSIST_DATA));
    }
#endif
    return RET_SUCCESS;
}

void BootVerifyScheduler::CommitBundleCacheLocked(const std::string& key)
{
    auto bundleIter = bundleInfoMap_.find(key);
    if (bundleIter == bundleInfoMap_.end() || bundleIter->second == nullptr) {
        return;
    }

    std::vector<AccessTokenInfoManager::HapTokenRestoreData> tokenRestoreDataList;
    for (const auto tokenId : bundleIter->second->tokenIds) {
        auto hapIter = hapTokenInfoMap_.find(tokenId);
        if (hapIter == hapTokenInfoMap_.end()) {
            continue;
        }

        (void)PermissionKernelUtils::AddHapPermToKernel(tokenId, requestedPermData_[tokenId]);

        AccessTokenInfoManager::HapTokenRestoreData restoreData;
        restoreData.hapTokenInfoItem = hapIter->second;
        restoreData.requestedPermData = requestedPermData_[tokenId];
        auto extendedPermIter = extendedPermMap_.find(tokenId);
        if (extendedPermIter != extendedPermMap_.end()) {
            restoreData.extendedPermList = extendedPermIter->second;
        }
        tokenRestoreDataList.emplace_back(restoreData);
    }

    AccessTokenInfoManager::GetInstance().RestoreHapCache(tokenRestoreDataList);
}

bool BootVerifyScheduler::IsAllBundlesVerified() const
{
    return isAllHapBundlesVerified_.load();
}

void BootVerifyScheduler::UpdateBundleSignInfoByTrustedInfos(BundleSignInfo& signInfo,
    const std::vector<uint32_t>& changedIndexList, const std::vector<TrustedBundleInfoInner>& trustedInfos)
{
    const size_t infoSize = trustedInfos.size();
    if (infoSize != signInfo.persistDataList.size() || infoSize != signInfo.moduleNameList.size() ||
        infoSize != signInfo.bundleType.size()) {
        return;
    }

    for (const auto& index : changedIndexList) {
        if (index >= infoSize || trustedInfos[index].bootstrapInfo == nullptr) {
            continue;
        }
        std::unique_ptr<uint8_t[]> dumpData(trustedInfos[index].bootstrapInfo->Dump());
        uint64_t dumpSize = trustedInfos[index].bootstrapInfo->GetSize();
        if (dumpData == nullptr || dumpSize == 0) {
            continue;
        }
        signInfo.persistDataList[index] = std::vector<uint8_t>(dumpData.get(), dumpData.get() + dumpSize);
        signInfo.moduleNameList[index] = trustedInfos[index].GetModuleName();
        signInfo.bundleType[index] = static_cast<uint32_t>(trustedInfos[index].GetBundleType());
    }
}

int32_t BootVerifyScheduler::VerifySingleBundle(const std::string& key, BundleSignInfo& updatedInfo,
    VerifiedBundleState& state)
{
    state.bundleName = updatedInfo.bundleName;
    HapSignVerifyManager& verifyManager = HapSignVerifyManager::GetInstance();
    std::vector<TrustedBundleInfoInner> trustedInfos;
    std::vector<uint32_t> changedIndexList;
    trustedInfos.reserve(updatedInfo.pathList.size());
    int32_t ret = RET_SUCCESS;
    for (uint32_t i = 0; i < updatedInfo.pathList.size(); ++i) {
        TrustedBundleInfoInner trustedInfo;
        bool isChanged = false;
        trustedInfo.bootstrapInfo = std::make_shared<Security::Verify::BootstrapInfo>();
        trustedInfo.bootstrapInfo->Load(
            updatedInfo.persistDataList[i].data(), updatedInfo.persistDataList[i].size());
        ret = verifyManager.CheckHapsSignInfo(
            HapSignVerifyManager::MakeVerifyParams(updatedInfo.pathList[i], Verify::VerifyType::Fast, -1),
            true, trustedInfo, isChanged);
        if (ret != RET_SUCCESS) {
            LOGC(ATM_DOMAIN, ATM_TAG,
                "Check hap sign info failed, bundleName=%{public}s, path=%{public}s, ret=%{public}d.",
                key.c_str(), updatedInfo.pathList[i].c_str(), ret);
            return ERR_HAP_SIGN_VERIFY_FAILED;
        }
        trustedInfos.emplace_back(trustedInfo);
        if (isChanged) {
            changedIndexList.emplace_back(i);
        }
    }

    ret = verifyManager.CheckMultipleHaps(trustedInfos);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, bundleName=%{public}s, ret=%{public}d.",
            key.c_str(), ret);
        return ret;
    }
    if (!trustedInfos.empty() && updatedInfo.bundleName != trustedInfos[0].GetBundleName()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Bundle name mismatch, bundleName=%{public}s, trustedBundleName=%{public}s.",
            key.c_str(), trustedInfos[0].GetBundleName().c_str());
        return ERR_HAP_SIGN_VERIFY_FAILED;
    }

    UpdateVerifiedSignInfo(key, updatedInfo, changedIndexList, trustedInfos, state);

    HapPolicy policy;
    BundleParam param;
    ret = verifyManager.BuildHapPolicy(trustedInfos, policy, param);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "BuildHapPolicy failed, bundleName=%{public}s, ret=%{public}d.",
            key.c_str(), ret);
        return ret;
    }

    return ReconcileVerifiedBundleCache(key, policy, param, state);
}

void BootVerifyScheduler::UpdateVerifiedSignInfo(const std::string& key, BundleSignInfo& updatedInfo,
    const std::vector<uint32_t>& changedIndexList, const std::vector<TrustedBundleInfoInner>& trustedInfos,
    VerifiedBundleState& state)
{
    if (changedIndexList.empty()) {
        return;
    }
    UpdateBundleSignInfoByTrustedInfos(updatedInfo, changedIndexList, trustedInfos);
    state.needUpdateSignInfo = true;
    std::lock_guard<std::mutex> lock(verifyMutex_);
    bundleSignInfoMap_[key] = updatedInfo;
}

int32_t BootVerifyScheduler::ReconcileVerifiedBundleCache(
    const std::string& key, const HapPolicy& policy, const BundleParam& param, VerifiedBundleState& state)
{
    std::shared_ptr<BundleInfoInner> bundleInfo = nullptr;
    BundleNoCachedInfo noCachedInfo;
    AccessTokenInfoUtils::BuildBundleFullInfo(param, policy, bundleInfo, noCachedInfo);
    std::vector<PermissionWithValue> fixedExtendPerms;
    BuildExtendedPermListFromPolicy(policy, fixedExtendPerms);

    std::lock_guard<std::mutex> lock(verifyMutex_);
    auto bundleIter = bundleInfoMap_.find(key);
    if (bundleIter == bundleInfoMap_.end() || bundleIter->second == nullptr) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Bundle info not exist, bundleName=%{public}s.", key.c_str());
        return ERR_BUNDLE_NOT_EXIST;
    }
    const auto tokenIds = bundleIter->second->tokenIds;
    for (const auto tokenId : tokenIds) {
        auto hapIter = hapTokenInfoMap_.find(tokenId);
        if (hapIter == hapTokenInfoMap_.end()) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Hap token info not exist, tokenId=%{public}u.", tokenId);
            return ERR_TOKENID_NOT_EXIST;
        }
        HapTokenInfoItem fixedItem = hapIter->second;
        bool hapInfoFixed = false;
        PermissionConstraintCheck::FixPersistentHapInfo(param, policy, fixedItem, hapInfoFixed);
        if (hapInfoFixed) {
            state.needPersistHapInfo = true;
            hapTokenInfoMap_[tokenId] = fixedItem;
        }
        std::vector<BriefPermData> fixedPermBriefData = requestedPermData_[tokenId];
        bool briefDataFixed = false;
        PermissionConstraintCheck::FixBriefPermData(*bundleInfo, fixedItem.dlpType, fixedPermBriefData, briefDataFixed);
        if (briefDataFixed) {
            state.needPersistPermState = true;
            requestedPermData_[tokenId] = fixedPermBriefData;
        }
        bool needUpdateExtendPerm = false;
        auto extendIter = extendedPermMap_.find(tokenId);
        if (extendIter == extendedPermMap_.end()) {
            needUpdateExtendPerm = !fixedExtendPerms.empty();
        } else {
            needUpdateExtendPerm = !IsExtendedPermListEqual(extendIter->second, fixedExtendPerms);
        }
        if (needUpdateExtendPerm) {
            extendedPermMap_[tokenId] = fixedExtendPerms;
            state.needUpdateExtendPerm = true;
        }
    }
    bundleNoCachedInfoMap_[key] = noCachedInfo;
    bundleInfo->tokenIds = tokenIds;
    bundleInfoMap_[key] = bundleInfo;
    return RET_SUCCESS;
}

int32_t BootVerifyScheduler::BuildVerifyBundleData(const std::string& key, BundleSignInfo& signInfo, bool isPreVerify)
{
    std::unique_lock<std::mutex> lock(verifyMutex_);
    auto verifiedIter = isVerifiedMap_.find(key);
    if (verifiedIter == isVerifiedMap_.end()) {
        return ERR_BUNDLE_NOT_EXIST;
    }
    if (IsAllBundlesVerified() || verifiedIter->second) {
        return RET_SUCCESS;
    }

    if (isPreVerify && isVerifyingMap_[key]) {
        bool finished = verifyCondition_.wait_for(lock, std::chrono::seconds(VERIFY_WAIT_TIMEOUT_SECONDS),
            [this, &key]() {
                return !isVerifyingMap_[key];
            });
        if (isVerifiedMap_[key]) {
            return RET_SUCCESS;
        }
        if (!finished) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Wait for verify timeout, bundleName=%{public}s.", key.c_str());
            return ERR_SERVICE_ABNORMAL;
        }
    }

    auto signInfoIter = bundleSignInfoMap_.find(key);
    if (signInfoIter == bundleSignInfoMap_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build verify bundle data failed, sign info not exist, bundleName=%{public}s.",
            key.c_str());
        return ERR_BUNDLE_NOT_EXIST;
    }
    signInfo = signInfoIter->second;
    isVerifyingMap_[key] = true;

    return RET_SUCCESS;
}

int32_t BootVerifyScheduler::VerifyBundleWithState(const std::string& key, bool isPreVerify)
{
    if (IsAllBundlesVerified()) {
        return RET_SUCCESS;
    }
    BundleSignInfo updatedInfo;
    VerifiedBundleState state;
    int32_t ret = BuildVerifyBundleData(key, updatedInfo, isPreVerify);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build verify bundle data failed, bundleName=%{public}s, ret=%{public}d.",
            key.c_str(), ret);
        return ret;
    }

    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        if (isVerifiedMap_[key]) {
            LOGD(ATM_DOMAIN, ATM_TAG, "Bundle already verified, bundleName=%{public}s.", key.c_str());
            return RET_SUCCESS;
        }
        if (ShouldSkipVerifyLocked(key)) {
            FinishSkippedBundleVerifyLocked(key);
            verifyCondition_.notify_all();
            return RET_SUCCESS;
        }
    }

    ret = VerifySingleBundle(key, updatedInfo, state);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Verify single bundle failed, bundleName=%{public}s, ret=%{public}d.",
            key.c_str(), ret);
        ChangeTokenIdToUntrustedStatus(key);
        if (!AccessTokenInfoUtils::IsSystemSpmEnforcing()) {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            FinishCommitBundleVerifyLocked(key);
            verifyCondition_.notify_all();
        } else {
            HandleVerifyBundleFailure(key, ret);
        }
        ReportSysCommonEventError(AccessTokenServiceStartSceneCode::VERIFY_HAP, ret);
    }

    if (ret == RET_SUCCESS) {
        ret = AddSpmDataAndCommitCache(key, { state });
        if (ret == RET_SUCCESS && isPreVerify) {
            ReportPreVerifyAddHapEvent(key, bundleInfoMap_, hapTokenInfoMap_);
        }
    }
    verifyCondition_.notify_all();
    return ret;
}

void BootVerifyScheduler::ChangeTokenIdToUntrustedStatus(const std::string& key)
{
    if (!AccessTokenInfoUtils::IsSystemSpmEnforcing()) {
        return;
    }
    auto bundleIter = bundleInfoMap_.find(key);
    if (bundleIter == bundleInfoMap_.end() || bundleIter->second == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Change tokenId status failed, bundle info not exist, bundleName=%{public}s.",
            key.c_str());
        return;
    }
    const auto tokenIds = bundleIter->second->tokenIds;
    for (const auto tokenId : tokenIds) {
        int32_t ret = AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(tokenId, TokenIdStatus::UNTRUSTED);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "ChangeTokenIdStatus failed, tokenId=%{public}u, ret=%{public}d.", tokenId, ret);
        }
    }
}

void BootVerifyScheduler::StartVerifyNormalBundleListAsync()
{
    const uint32_t hapSize = static_cast<uint32_t>(normalBundleList_.size());
    if (normalBundleList_.empty()) {
        isAllHapBundlesVerified_.store(true);
        ClearBundleVerifyContext();
        AccessTokenInfoUtils::AccessTokenServiceAppVerifyParamSet();
        ReportNormalBundleVerifyFinish(hapSize);
        return;
    }
    std::thread([this, hapSize]() {
        VerifyNormalBundleListAsync();
        ReportNormalBundleVerifyFinish(hapSize);
    }).detach();
}

void BootVerifyScheduler::VerifyNormalBundleListAsync()
{
    for (const auto& key : normalBundleList_) {
        {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            if (IsAllBundlesVerified()) {
                break;
            }
            auto iter = isVerifiedMap_.find(key);
            if (iter == isVerifiedMap_.end() || iter->second) {
                continue;
            }
        }

        int32_t ret = VerifyBundleWithState(key);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Verify normal bundle failed, bundleName=%{public}s, ret=%{public}d.",
                key.c_str(), ret);
        }
    }
    isAllHapBundlesVerified_.store(true);
    ClearBundleVerifyContext();
    verifyCondition_.notify_all();
    AccessTokenInfoUtils::AccessTokenServiceAppVerifyParamSet();
}

int32_t BootVerifyScheduler::VerifyBundleSignInfoWhenStart(
    uint32_t& hapSize, std::map<int32_t, TokenIdInfo>& tokenIdAplMap)
{
    ClearBundleVerifyContext();
    isAllHapBundlesVerified_.store(false);
    int32_t ret = LoadVerifyDataFromDb(tokenIdAplMap);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Load verify data failed, ret=%{public}d.", ret);
        return ret;
    }

    ret = AccessTokenIDManager::GetInstance().InitBundleIdConfig();
    if (ret != RET_SUCCESS) {
        return ret;
    }

    BuildPriorityBundleList();
    hapSize = static_cast<uint32_t>(highPrivilegeBundleList_.size());
    std::map<std::string, VerifiedBundleState> stateList;
    VerifyHighPrivilegeBundleList(stateList);
    HandleHighPrivilegeBundleSpmData(stateList);
    return RET_SUCCESS;
}

void BootVerifyScheduler::VerifyHighPrivilegeBundleList(std::map<std::string, VerifiedBundleState>& stateList)
{
    std::vector<std::map<std::string, VerifiedBundleState>> stateGroups;
    RunHighPrivilegeBundleVerifyTasks(stateGroups);
    stateList.clear();
    for (const auto& infoGroup : stateGroups) {
        stateList.insert(infoGroup.begin(), infoGroup.end());
    }
}

void BootVerifyScheduler::VerifyBundleList(std::atomic_size_t& nextBundleIndex,
    std::map<std::string, VerifiedBundleState>& stateList)
{
    while (true) {
        const size_t bundleIndex = nextBundleIndex.fetch_add(1);
        if (bundleIndex >= highPrivilegeBundleList_.size()) {
            break;
        }

        const std::string& key = highPrivilegeBundleList_[bundleIndex];
        BundleSignInfo updatedInfo;
        VerifiedBundleState state;
        {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            if (!PrepareBundleForBatchVerifyLocked(key, updatedInfo)) {
                continue;
            }
        }
        int32_t ret = VerifySingleBundle(key, updatedInfo, state);
        if (ret != RET_SUCCESS) {
            ChangeTokenIdToUntrustedStatus(key);
            HandleVerifyBundleFailure(key, ret);
            ReportSysCommonEventError(AccessTokenServiceStartSceneCode::VERIFY_HAP, ret);
            continue;
        }
        stateList.emplace(key, state);
    }
}

void BootVerifyScheduler::RunHighPrivilegeBundleVerifyTasks(
    std::vector<std::map<std::string, VerifiedBundleState>>& stateGroups)
{
    std::vector<std::thread> threads;
    const size_t threadCount = std::min(highPrivilegeBundleList_.size(), static_cast<size_t>(VERIFY_THREAD_COUNT));
    stateGroups.assign(threadCount, {});
    threads.reserve(threadCount);
    std::atomic_size_t nextBundleIndex = 0;
    for (size_t i = 0; i < threadCount; ++i) {
        threads.emplace_back([this, &stateGroups, &nextBundleIndex, i]() {
            VerifyBundleList(nextBundleIndex, stateGroups[i]);
        });
    }
    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

void BootVerifyScheduler::HandleHighPrivilegeBundleSpmData(const std::map<std::string, VerifiedBundleState>& stateMap)
{
    std::vector<std::pair<std::string, VerifiedBundleState>> bundleStatesToPersist;
    for (const auto& key : highPrivilegeBundleList_) {
        auto stateIter = stateMap.find(key);
        if (stateIter == stateMap.end()) {
            // verify failed, skip persist and commit, but still need to notify the waiting threads
            std::lock_guard<std::mutex> lock(verifyMutex_);
            if (!AccessTokenInfoUtils::IsSystemSpmEnforcing()) {
                FinishCommitBundleVerifyLocked(key);
            }
            continue;
        }
        bundleStatesToPersist.emplace_back(key, stateIter->second);
        int32_t ret = AddSpmDataForBundle(key);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Add spm data failed, bundleName=%{public}s, ret=%{public}d.",
                key.c_str(), ret);
        }
    }

    // Boot-time database correction: a failed DB write is not rolled back.
    // The kernel SPM data and in-memory cache are already committed; on failure
    // only the event is reported and the affected bundles are marked as failed.
    int32_t ret = PersistVerifiedBundleStates(bundleStatesToPersist);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Persist verified bundle states failed, ret=%{public}d.", ret);
        ReportSysCommonEventError(AccessTokenServiceStartSceneCode::PERSIST_BUNDLE_DATA, ret);
    }

    for (const auto& [key, state] : bundleStatesToPersist) {
        (void)state;
        {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            FinishCommitBundleVerifyLocked(key);
            LOGI(ATM_DOMAIN, ATM_TAG, "Fast verify finished, bundleName=%{public}s.", key.c_str());
        }
    }
}

bool BootVerifyScheduler::ShouldSkipVerifyLocked(const std::string& key) const
{
#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
    // skip verify only when migration is not completed.
    if (!migrationCompleted_.load()) {
        return true;
    }
#endif
    auto bundleIter = bundleInfoMap_.find(key);
    if (bundleIter == bundleInfoMap_.end() || bundleIter->second == nullptr || bundleIter->second->tokenIds.empty()) {
        return true;
    }
    // Skip verification only when all tokens in the bundle are present in the cache and
    // carry the unassigned uid (-1); otherwise the bundle still requires normal verification.
    bool allUidInvalid = true;
    for (const auto tokenId : bundleIter->second->tokenIds) {
        auto hapIter = hapTokenInfoMap_.find(tokenId);
        if (hapIter == hapTokenInfoMap_.end()) {
            continue;
        }
        if (hapIter->second.uid != INVALID_UID) {
            allUidInvalid = false;
            break;
        }
    }
    if (allUidInvalid) {
        return true;
    }
    return bundleSignInfoMap_.find(key) == bundleSignInfoMap_.end();
}

void BootVerifyScheduler::FinishSkippedBundleVerifyLocked(const std::string& key)
{
    FinishCommitBundleVerifyLocked(key);
    LOGI(ATM_DOMAIN, ATM_TAG, "Skip fast verify finished, bundleName=%{public}s.", key.c_str());
}

int32_t BootVerifyScheduler::BuildSpmParams(const std::string& key, BundleNoCachedInfo& noCachedInfo,
    std::vector<HapTokenInfo>& hapInfoCache, std::vector<std::vector<BriefPermData>>& permBriefDataListCache,
    std::vector<std::vector<PermissionWithValue>>& extendPermListCache, std::vector<SpmDataParam>& params)
{
    params.clear();
    hapInfoCache.clear();
    permBriefDataListCache.clear();
    extendPermListCache.clear();
    std::lock_guard<std::mutex> lock(verifyMutex_);
    auto bundleIter = bundleInfoMap_.find(key);
    auto noCachedIter = bundleNoCachedInfoMap_.find(key);
    if (bundleIter == bundleInfoMap_.end() || bundleIter->second == nullptr ||
        noCachedIter == bundleNoCachedInfoMap_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build spm params failed, bundleName=%{public}s.", key.c_str());
        return ERR_BUNDLE_NOT_EXIST;
    }
    noCachedInfo = noCachedIter->second;
    const auto tokenIds = bundleIter->second->tokenIds;
    hapInfoCache.reserve(tokenIds.size());
    permBriefDataListCache.reserve(tokenIds.size());
    extendPermListCache.reserve(tokenIds.size());
    params.reserve(tokenIds.size());
    for (const auto tokenId : tokenIds) {
        auto hapIter = hapTokenInfoMap_.find(tokenId);
        auto permIter = requestedPermData_.find(tokenId);
        if (hapIter == hapTokenInfoMap_.end() || permIter == requestedPermData_.end()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Build spm params failed, tokenId=%{public}u.", tokenId);
            return ERR_TOKENID_NOT_EXIST;
        }
        if (hapIter->second.uid == INVALID_UID) {
            LOGC(ATM_DOMAIN, ATM_TAG,
                "bundleName=%{public}s, tokenId=%{public}u skip load to kernel.", key.c_str(), tokenId);
            ReportSysCommonEventError(AccessTokenServiceStartSceneCode::LOAD_SPM_DATA_TO_KERNEL,
                AccessTokenServiceStartErrorCode::UID_INVALID);
            continue;
        }
        hapInfoCache.emplace_back(ConvertToHapTokenInfo(hapIter->second));
        permBriefDataListCache.emplace_back(permIter->second);
        extendPermListCache.emplace_back(extendedPermMap_[tokenId]);
        params.emplace_back(SpmDataParam { hapInfoCache.back(), noCachedInfo, permBriefDataListCache.back(),
            extendPermListCache.back() });
    }
    return RET_SUCCESS;
}

int32_t BootVerifyScheduler::GetBundleTokenIds(const std::string& key, std::vector<AccessTokenID>& tokenIds)
{
    std::lock_guard<std::mutex> lock(verifyMutex_);
    auto bundleIter = bundleInfoMap_.find(key);
    if (bundleIter == bundleInfoMap_.end() || bundleIter->second == nullptr) {
        return ERR_BUNDLE_NOT_EXIST;
    }
    tokenIds = bundleIter->second->tokenIds;
    return RET_SUCCESS;
}

void BootVerifyScheduler::BuildBundlePersistInfos(AccessTokenID tokenId, const VerifiedBundleState& state,
    std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    if (state.needPersistHapInfo) {
        delInfoVec.emplace_back(DelInfo { AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition });
        std::vector<GenericValues> hapInfoValues;
        {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            hapTokenInfoMap_[tokenId].BuildAddValue(hapInfoValues);
        }
        if (!hapInfoValues.empty()) {
            addInfoVec.emplace_back(AddInfo { AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, hapInfoValues });
        }
    }
    if (state.needPersistPermState) {
        delInfoVec.emplace_back(DelInfo { AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition });
        std::vector<BriefPermData> permData;
        std::vector<GenericValues> permStateValues;
        {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            permData = requestedPermData_[tokenId];
        }
        ConvertBriefPermDataToGenericValues(tokenId, permData, permStateValues);
        addInfoVec.emplace_back(AddInfo { AtmDataType::ACCESSTOKEN_PERMISSION_STATE, permStateValues });
    }
    if (state.needUpdateExtendPerm) {
        delInfoVec.emplace_back(DelInfo { AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, condition });
        std::vector<PermissionWithValue> extendPermList;
        std::vector<GenericValues> extendPermValues;
        {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            extendPermList = extendedPermMap_[tokenId];
        }
        ConvertExtendPermToGenericValues(tokenId, extendPermList, extendPermValues);
        if (!extendPermValues.empty()) {
            addInfoVec.emplace_back(AddInfo { AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, extendPermValues });
        }
    }
}

void BootVerifyScheduler::BuildSignInfoPersistInfo(
    const std::string& key, std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec)
{
    BundleSignInfo bundleSignInfo;
    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        bundleSignInfo = bundleSignInfoMap_[key];
    }
    auto signInfoDelInfos = BuildDeleteInfos({ bundleSignInfo });
    delInfoVec.insert(delInfoVec.end(), signInfoDelInfos.begin(), signInfoDelInfos.end());
    std::vector<GenericValues> values;
    bundleSignInfo.ToGenericValues(values);
    if (!values.empty()) {
        addInfoVec.emplace_back(AddInfo { AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, values });
    }
}

int32_t BootVerifyScheduler::PersistVerifiedBundleState(
    const std::string& key, const VerifiedBundleState& state)
{
    if (!state.needUpdateSignInfo && !state.needPersistHapInfo &&
        !state.needPersistPermState && !state.needUpdateExtendPerm) {
        return RET_SUCCESS;
    }
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    int32_t ret = BuildVerifiedBundlePersistInfo(key, state, delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        HandleVerifyBundleFailure(key, ret);
        return ret;
    }

    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        HandleVerifyBundleFailure(key, ret);
        return ret;
    }
    return ret;
}

int32_t BootVerifyScheduler::BuildVerifiedBundlePersistInfo(const std::string& key,
    const VerifiedBundleState& state, std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec)
{
    delInfoVec.clear();
    addInfoVec.clear();
    std::vector<AccessTokenID> tokenIds;
    int32_t ret = GetBundleTokenIds(key, tokenIds);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    for (const auto tokenId : tokenIds) {
        BuildBundlePersistInfos(tokenId, state, delInfoVec, addInfoVec);
    }
    if (state.needUpdateSignInfo) {
        BuildSignInfoPersistInfo(key, delInfoVec, addInfoVec);
    }
    return RET_SUCCESS;
}

int32_t BootVerifyScheduler::PersistVerifiedBundleStates(
    const std::vector<std::pair<std::string, VerifiedBundleState>>& bundleStates)
{
    if (bundleStates.empty()) {
        return RET_SUCCESS;
    }
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    for (const auto& [key, state] : bundleStates) {
        std::vector<DelInfo> currentDelInfoVec;
        std::vector<AddInfo> currentAddInfoVec;
        int32_t ret = BuildVerifiedBundlePersistInfo(key, state, currentDelInfoVec, currentAddInfoVec);
        if (ret != RET_SUCCESS) {
            HandleVerifyBundleFailure(key, ret);
            LOGC(ATM_DOMAIN, ATM_TAG, "Failed to build persist info %{public}s", key.c_str());
            continue;
        }
        delInfoVec.insert(delInfoVec.end(), currentDelInfoVec.begin(), currentDelInfoVec.end());
        addInfoVec.insert(addInfoVec.end(), currentAddInfoVec.begin(), currentAddInfoVec.end());
    }
    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to persist verified bundle states, ret=%{public}d.", ret);
        for (const auto& [key, state] : bundleStates) {
            (void)state;
            HandleVerifyBundleFailure(key, ret);
        }
    }
    return ret;
}

void BootVerifyScheduler::FinishCommitBundleVerifyLocked(const std::string& key)
{
    if (isVerifiedMap_[key]) {
        return;
    }
    CommitBundleCacheLocked(key);
    isVerifiedMap_[key] = true;
    isVerifyingMap_[key] = false;
}

int32_t BootVerifyScheduler::AddSpmDataAndCommitCache(
    const std::string& key, const VerifiedBundleState& state)
{
    int32_t ret = AddSpmDataForBundle(key);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    int32_t result = PersistVerifiedBundleState(key, state);
    if (result != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to modify database, bundleName=%{public}s.", key.c_str());
        ReportSysCommonEventError(AccessTokenServiceStartSceneCode::PERSIST_BUNDLE_DATA, ret);
        return result;
    }

    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        FinishCommitBundleVerifyLocked(key);
    }
    verifyCondition_.notify_all();

    LOGI(ATM_DOMAIN, ATM_TAG, "Fast verify finished, bundleName=%{public}s.", key.c_str());
    return RET_SUCCESS;
}

int32_t BootVerifyScheduler::AddSpmDataForBundle(const std::string& key)
{
    if (!PermissionKernelUtils::IsKernelSupportSpm() || AccessTokenInfoUtils::IsSystemAppVerified()) {
        return RET_SUCCESS;
    }

    BundleNoCachedInfo noCachedInfo;
    std::vector<HapTokenInfo> hapInfoCache;
    std::vector<std::vector<BriefPermData>> permBriefDataListCache;
    std::vector<std::vector<PermissionWithValue>> extendPermListCache;
    std::vector<SpmDataParam> params;
    int32_t ret = BuildSpmParams(
        key, noCachedInfo, hapInfoCache, permBriefDataListCache, extendPermListCache, params);
    if (ret != RET_SUCCESS) {
        HandleVerifyBundleFailure(key, ret);
        return ret;
    }
    if (hapInfoCache.empty()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "No valid hap info found, bundleName=%{public}s.", key.c_str());
        return RET_SUCCESS;
    }

#ifdef SPM_DATA_ENABLE
    KernelAndDBWriteTransaction txn;
    ret = txn.StageKernelAdd(params);
    if (ret != RET_SUCCESS && ret != ERR_DATA_CONFLICT_WITH_KERNEL) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Add spm data failed, bundleName=%{public}s, ret=%{public}d.",
            key.c_str(), ret);
        HandleVerifyBundleFailure(key, ret);
        return ret;
    }
    txn.Commit();
#endif
    return RET_SUCCESS;
}

bool BootVerifyScheduler::PrepareBundleForBatchVerifyLocked(
    const std::string& key, BundleSignInfo& updatedInfo)
{
    if (ShouldSkipVerifyLocked(key)) {
        FinishSkippedBundleVerifyLocked(key);
        return false;
    }
    if (isVerifyingMap_[key] || isVerifiedMap_[key]) {
        LOGD(ATM_DOMAIN, ATM_TAG, "Bundle is already being verified, bundleName=%{public}s.", key.c_str());
        return false;
    }

    auto signInfoIter = bundleSignInfoMap_.find(key);
    if (signInfoIter == bundleSignInfoMap_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Prepare batch verify failed, bundleName=%{public}s.", key.c_str());
        return false;
    }
    updatedInfo = signInfoIter->second;
    isVerifyingMap_[key] = true;
    return true;
}

void BootVerifyScheduler::HandleVerifyBundleFailure(const std::string& key, int32_t ret)
{
    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        isVerifyingMap_[key] = false;
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "Verify bundle failed, bundleName=%{public}s, ret=%{public}d.",
        key.c_str(), ret);
    verifyCondition_.notify_all();
}

int32_t BootVerifyScheduler::PreVerifyBundle(const std::string& bundleName)
{
    if (IsAllBundlesVerified() || bundleInfoMap_.empty()) {
        return RET_SUCCESS;
    }

    bool found = false;
    int32_t result = RET_SUCCESS;
    for (int32_t mode = 0; mode <= 1; ++mode) {
        std::string key = MultipleModeUtils::GetBundleModeKey(bundleName, mode);
        {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            if (bundleInfoMap_.find(key) == bundleInfoMap_.end()) {
                continue;
            }
            found = true;
        }
        int32_t ret = PreVerifyBundleInner(key);
        if (ret != RET_SUCCESS) {
            result = ret;
        }
    }
    if (!found) {
        LOGW(ATM_DOMAIN, ATM_TAG,
            "Pre verify skipped, bundle not exist, bundleName=%{public}s.", bundleName.c_str());
        return RET_SUCCESS;
    }
    return result;
}

int32_t BootVerifyScheduler::PreVerifyBundle(const std::string& bundleName, int32_t instIndex)
{
    if (IsAllBundlesVerified() || bundleInfoMap_.empty()) {
        return RET_SUCCESS;
    }

    std::string key = MultipleModeUtils::GetBundleModeKey(bundleName,
        static_cast<int32_t>(MultipleModeUtils::GetTokenMode(instIndex)));
    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        if (bundleInfoMap_.find(key) == bundleInfoMap_.end()) {
            LOGW(ATM_DOMAIN, ATM_TAG,
                "Pre verify skipped, bundle not exist, bundleName=%{public}s, mode=%{public}d.",
                bundleName.c_str(), static_cast<int32_t>(MultipleModeUtils::GetTokenMode(instIndex)));
            return RET_SUCCESS;
        }
    }
    return PreVerifyBundleInner(key);
}

int32_t BootVerifyScheduler::PreVerifyBundleInner(const std::string& key)
{
    return VerifyBundleWithState(key, true);
}

int32_t BootVerifyScheduler::PreVerifyBundle(uint32_t tokenID)
{
    if (IsAllBundlesVerified() || hapTokenInfoMap_.empty()) {
        return RET_SUCCESS;
    }

    std::string bundleName;
    int32_t mode = 0;
    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        auto tokenIter = hapTokenInfoMap_.find(tokenID);
        if (tokenIter == hapTokenInfoMap_.end()) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Pre verify skipped, token not exist, tokenId=%{public}u.", tokenID);
            return RET_SUCCESS;
        }
        bundleName = tokenIter->second.bundleName;
        mode = static_cast<int32_t>(MultipleModeUtils::GetTokenMode(static_cast<int32_t>(tokenIter->second.instIndex)));
    }
    if (bundleName.empty()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Pre verify skipped, bundle name empty, tokenId=%{public}u.", tokenID);
        return RET_SUCCESS;
    }
    return PreVerifyBundleInner(MultipleModeUtils::GetBundleModeKey(bundleName, mode));
}

int32_t BootVerifyScheduler::PreVerifyBundle(int32_t uid)
{
    if (uid <= 0 || IsAllBundlesVerified() || hapTokenInfoMap_.empty()) {
        return RET_SUCCESS;
    }

    std::string bundleName;
    int32_t mode = 0;
    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        for (const auto& entry : hapTokenInfoMap_) {
            if (entry.second.uid != uid) {
                continue;
            }
            bundleName = entry.second.bundleName;
            mode = static_cast<int32_t>(MultipleModeUtils::GetTokenMode(static_cast<int32_t>(entry.second.instIndex)));
            break;
        }
    }
    if (bundleName.empty()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Pre verify skipped, uid not exist, uid=%{public}d.", uid);
        return RET_SUCCESS;
    }
    return PreVerifyBundleInner(MultipleModeUtils::GetBundleModeKey(bundleName, mode));
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
