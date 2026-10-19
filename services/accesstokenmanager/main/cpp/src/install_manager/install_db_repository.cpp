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

#include "install_db_repository.h"

#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_utils.h"
#include "data_translator.h"
#include "multiple_mode_utils.h"
#include "permission_map.h"
#include "permission_status.h"
#include "table_item.h"
#include "time_util.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
// Build the ACL extended permission values and the token-id-stamped undefined
// permission values for persistence (same tables as master AddHapTokenInfoToDb).
void BuildPermExtendAndUndefValues(AccessTokenID tokenId,
    const std::vector<PermissionWithValue>& extendPermList,
    const std::vector<GenericValues>& undefValues,
    std::vector<GenericValues>& permExtendValues,
    std::vector<GenericValues>& undefValuesWithTokenId)
{
    for (const auto& extendValue : extendPermList) {
        GenericValues genericValues;
        genericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        genericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, extendValue.permissionName);
        genericValues.Put(TokenFiledConst::FIELD_VALUE, extendValue.value);
        permExtendValues.emplace_back(genericValues);
    }
    for (const auto& undefValue : undefValues) {
        GenericValues stamped = undefValue;
        stamped.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        undefValuesWithTokenId.emplace_back(stamped);
    }
}
constexpr int32_t HAP_TOKEN_CURRENT_VERSION = 1;
constexpr const char* HAP_TOKEN_DEFAULT_DEVICE_ID = "0";
constexpr const char* PERM_STATE_LOCAL_DEVICE_ID = "PHONE-001";
constexpr int32_t INVALID_UID = -1;
}

int32_t InstallDbRepository::GetInstalledBundleInfo(std::string bundleName, MultipleMode mode,
    std::vector<std::string>& paths, std::vector<std::vector<uint8_t>>& persistDatas)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    condition.Put(TokenFiledConst::FIELD_MODE, static_cast<int32_t>(mode));
    std::vector<GenericValues> hapTokenResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, condition, hapTokenResults);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Db find failed, ret=%{public}d", ret);
        return ERR_DATABASE_OPERATE_FAILED;
    }

    for (const auto& tokenValue : hapTokenResults) {
        paths.emplace_back(tokenValue.GetString(TokenFiledConst::FIELD_PATH));
        persistDatas.emplace_back(tokenValue.GetBlob(TokenFiledConst::FIELD_PERSIST_DATA));
    }

    return RET_SUCCESS;
}

int32_t InstallDbRepository::QueryBundleTokenbyIndex(const std::string& bundleName, int32_t instIndex,
    std::vector<GenericValues>& hapTokenResults)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    condition.Put(TokenFiledConst::FIELD_INST_INDEX, instIndex);
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, hapTokenResults);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Query failed, ret: %{public}d", ret);
        return ERR_DATABASE_OPERATE_FAILED;
    }
    return RET_SUCCESS;
}

int32_t InstallDbRepository::QueryBundleTokens(const std::string& bundleName, InstallCache& cache,
    std::vector<GenericValues>& hapTokenResults)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, hapTokenResults);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Query failed, ret: %{public}d", ret);
        return ERR_DATABASE_OPERATE_FAILED;
    }

    // single pass: mode-mismatched rows are dropped from the output; mode-matched
    // rows stay in hapTokenResults (any status, the reuse path needs reserved
    // rows); only ACTIVE rows enter the supplement candidate list
    std::vector<GenericValues> modeMatched;
    modeMatched.reserve(hapTokenResults.size());
    cache.bundleTokenIdList.clear();
    for (const auto& tokenValue : hapTokenResults) {
        int32_t instIndex = tokenValue.GetInt(TokenFiledConst::FIELD_INST_INDEX);
        if (!MultipleModeUtils::IsModeInstIndexMatch(static_cast<int32_t>(cache.mode), instIndex)) {
            continue;
        }
        modeMatched.emplace_back(tokenValue);
        AccessTokenID tokenId = static_cast<AccessTokenID>(tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
        TokenIdStatus status;
        if ((AccessTokenIDManager::GetInstance().GetTokenIdStatus(tokenId, status) != RET_SUCCESS) ||
            (status != TokenIdStatus::ACTIVE)) {
            continue;
        }
        cache.bundleTokenIdList.emplace_back(tokenId);
    }
    hapTokenResults = std::move(modeMatched);
    cache.bundleTokenIdsLoaded = true;
    return RET_SUCCESS;
}

void InstallDbRepository::TranslateGenericValuesToPermState(
    const std::vector<GenericValues>& permStateResults, std::vector<PermissionStatus>& existingPermList)
{
    for (const auto& value : permStateResults) {
        PermissionStatus permStatus;
        int32_t ret = DataTranslator::TranslationIntoPermissionStatus(value, permStatus);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TranslationIntoPermissionStatus failed");
            continue;
        }
        existingPermList.emplace_back(permStatus);
    }
}

int32_t InstallDbRepository::BuildPermStateByTokenId(
    AccessTokenID tokenId, std::vector<BriefPermData>& oldPermBriefDataList)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> permStateResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition, permStateResults);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Find permission state failed, ret=%{public}d", ret);
        return ERR_DATABASE_OPERATE_FAILED;
    }

    std::vector<PermissionStatus> permList;
    TranslateGenericValuesToPermState(permStateResults, permList);
    PermissionDataBrief::BuildPermissionBriefDataList(permList, oldPermBriefDataList);
    return RET_SUCCESS;
}

int32_t InstallDbRepository::DeleteFromDbByTokenId(AccessTokenID tokenID)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Find in db but not exist in IDManager, delete token %{public}u", tokenID);
    GenericValues cond;
    cond.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));

    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, cond, delInfoVec);
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, cond, delInfoVec);
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, cond, delInfoVec);
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, cond, delInfoVec);

    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, {});
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to delete token %{public}u from db, ret=%{public}d.", tokenID, ret);
        return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
    }
    return RET_SUCCESS;
}

void InstallDbRepository::GenerateHapTokenInfoItem(const InstallCache& cache, const InstallHapInfo& installInfo,
    std::vector<GenericValues>& genericValues)
{
    // the sideload bit and the sticky flags (migrated / perm-dialog-cap) were
    // resolved once at FillFinishContext; the db write and the cache refresh
    // share them
    HapTokenInfoItem item;
    item.migrated = installInfo.migrated;
    item.permDialogCapState = installInfo.permDialogCapState;
    item.tokenId = installInfo.baseInfo.tokenID;
    item.userId = static_cast<uint32_t>(installInfo.baseInfo.userID);
    item.bundleName = installInfo.baseInfo.bundleName;
    item.instIndex = static_cast<uint32_t>(installInfo.baseInfo.instIndex);
    item.dlpType = static_cast<HapDlpType>(installInfo.baseInfo.dlpType);
    item.apiVersion = installInfo.baseInfo.apiVersion;
    item.uid = installInfo.baseInfo.uid;
    item.tokenAttr = static_cast<uint32_t>(installInfo.baseInfo.tokenAttr);

    item.appId = cache.bundleParam.appId;
    item.deviceId = HAP_TOKEN_DEFAULT_DEVICE_ID;
    item.apl = cache.policy.apl;
    item.version = HAP_TOKEN_CURRENT_VERSION;
    item.reserved = ReservedType::NONE;
    item.isSideload = installInfo.isSideload;

    item.BuildAddValue(genericValues);
}

int32_t InstallDbRepository::GetLocalPermStateListFromDb(AccessTokenID tokenId,
    std::vector<PermissionStatus>& permList)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> oldPermStateValues;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE,
        condition, oldPermStateValues);
    if (ret != RET_SUCCESS) {
        // a failed find may leave partial rows; drop them and fail fast so the
        // caller aborts instead of silently resetting every grant timestamp
        oldPermStateValues.clear();
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to find old permission states for token %{public}u, ret %{public}d.",
            tokenId, ret);
        return ret;
    }
    // local-device rows only: remote-device rows (distributed sync) carry
    // their own grant timestamps and must not leak into the local row,
    // same as the master update flow (BuildPermissionStateValues)
    std::vector<GenericValues> localValues;
    for (const auto& value : oldPermStateValues) {
        if (value.GetString(TokenFiledConst::FIELD_DEVICE_ID) == PERM_STATE_LOCAL_DEVICE_ID) {
            localValues.emplace_back(value);
        }
    }
    TranslateGenericValuesToPermState(localValues, permList);
    return RET_SUCCESS;
}

int32_t InstallDbRepository::ConvertBriefPermDataToGenericValues(AccessTokenID tokenId,
    const std::vector<BriefPermData>& briefPermDataList, std::vector<GenericValues>& genericValuesList)
{
    std::vector<PermissionStatus> existingPermList;
    int32_t ret = GetLocalPermStateListFromDb(tokenId, existingPermList);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    uint64_t currentTimestamp = static_cast<uint64_t>(TimeUtil::GetCurrentTimestamp());
    for (const auto& data : briefPermDataList) {
        std::string permissionName = TransferOpcodeToPermission(data.permCode);
        if (permissionName.empty()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TransferOpcodeToPermission failed code=%{public}d", data.permCode);
            continue;
        }

        GenericValues genericValues;
        genericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        genericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
        genericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, PERM_STATE_LOCAL_DEVICE_ID);
        genericValues.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
        genericValues.Put(TokenFiledConst::FIELD_GRANT_STATE, static_cast<int32_t>(data.status));
        genericValues.Put(TokenFiledConst::FIELD_GRANT_FLAG, static_cast<int32_t>(data.flag));

        // timestamp arbitration aligned with the master update flow
        // (BuildPermissionStateValues): keep the old grant time only when the
        // local row matches on name + status + flag; any change, including a
        // flag flip (grant nature change), is a new grant event
        auto iter = std::find_if(existingPermList.begin(), existingPermList.end(),
            [permissionName, data](const PermissionStatus& oldPerm) {
                return permissionName == oldPerm.permissionName && data.status == oldPerm.grantStatus &&
                    data.flag == oldPerm.grantFlag;
            });
        if (iter != existingPermList.end()) {
            genericValues.Put(TokenFiledConst::FIELD_TIMESTAMP, static_cast<int64_t>(iter->timestamp));
        } else {
            genericValues.Put(TokenFiledConst::FIELD_TIMESTAMP, static_cast<int64_t>(currentTimestamp));
        }

        genericValuesList.emplace_back(genericValues);
    }
    return RET_SUCCESS;
}

void InstallDbRepository::GeneratePermDefFromHapPolicy(AccessTokenID tokenId, const HapPolicy& hapPolicy,
    const std::string& bundleName, std::vector<GenericValues>& genericValuesList)
{
    if (!AccessTokenInfoUtils::IsSystemResource(bundleName)) {
        return;
    }
    genericValuesList.clear();
    for (const auto& permDef : hapPolicy.permList) {
        GenericValues genericValues;
        genericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        DataTranslator::TranslationIntoGenericValues(permDef, genericValues);
        genericValuesList.emplace_back(genericValues);
    }
}

int32_t InstallDbRepository::ResolveModulePaths(const InstallCache& cache,
    const std::map<std::string, std::string>& modulePathMap, std::vector<std::string>& modulePaths)
{
    modulePaths.clear();
    modulePaths.reserve(cache.bundleInfos.size());
    size_t newCount = cache.list.hapPaths.size();
    for (size_t i = 0; i < cache.bundleInfos.size(); ++i) {
        if (i < newCount) {
            auto it = modulePathMap.find(cache.list.hapPaths[i]);
            if (it == modulePathMap.end()) {
                LOGC(ATM_DOMAIN, ATM_TAG, "HAP path not found in map, index=%{public}zu.", i);
                return AccessTokenError::ERR_PARAM_INVALID;
            }
            modulePaths.emplace_back(it->second);
        } else {
            modulePaths.emplace_back(cache.oldModulePaths[i - newCount]);
        }
    }
    return RET_SUCCESS;
}

int32_t InstallDbRepository::ConvertInstallCacheToBundleInfoItems(const InstallCache& cache,
    const std::map<std::string, std::string>& modulePathMap, std::vector<GenericValues>& genericValuesList,
    GenericValues& delCondition)
{
    std::vector<std::string> modulePaths;
    int32_t ret = ResolveModulePaths(cache, modulePathMap, modulePaths);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    BundleInfoItems items;
    items.bundleName = cache.bundleInfos[0].GetBundleName();
    items.isPreInstalled = cache.list.isPreInstalled;
    items.mode = cache.mode;
    for (size_t i = 0; i < cache.bundleInfos.size(); ++i) {
        const auto& bundleInfo = cache.bundleInfos[i];
        ModuleInfoItem moduleItem;
        moduleItem.moduleName = bundleInfo.GetModuleName();
        moduleItem.path = modulePaths[i];
        moduleItem.bundleType = bundleInfo.GetBundleType();
        if (bundleInfo.bootstrapInfo != nullptr) {
            uint64_t persistSize = bundleInfo.bootstrapInfo->GetSize();
            if (persistSize > 0) {
                uint8_t* data = bundleInfo.bootstrapInfo->Dump();
                moduleItem.persistData.assign(data, data + static_cast<size_t>(persistSize));
                delete[] data;
            }
        }
        items.moduleInfoItems.emplace_back(moduleItem);
    }

    items.BuildAddValue(genericValuesList);
    // delete is mode-scoped: a sub-mode reinstall must not remove the main
    // mode rows of the same bundleName (hap_info_table PK is name+module+mode)
    delCondition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, items.bundleName);
    delCondition.Put(TokenFiledConst::FIELD_MODE, static_cast<int32_t>(items.mode));
    return RET_SUCCESS;
}

int32_t InstallDbRepository::GenerateTokenDbOpsVec(const InstallCache& cache, const FinishContext& context,
    size_t index, std::vector<AddInfo>& addInfoVec, std::vector<DelInfo>& delInfoVec)
{
    const InstallHapInfo& installInfo = context.hapInfos[index];
    AccessTokenID tokenId = installInfo.baseInfo.tokenID;
    std::vector<GenericValues> hapTokenInfoValues;
    GenerateHapTokenInfoItem(cache, installInfo, hapTokenInfoValues);
    std::vector<GenericValues> permStateValues;
    int32_t ret = ConvertBriefPermDataToGenericValues(tokenId, context.permBriefDataLists[index], permStateValues);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    std::vector<GenericValues> permDefValues;
    GeneratePermDefFromHapPolicy(tokenId, cache.policy, installInfo.baseInfo.bundleName, permDefValues);

    std::vector<GenericValues> permExtendValues;
    std::vector<GenericValues> undefValuesWithTokenId;
    BuildPermExtendAndUndefValues(tokenId, context.extendPermLists[index], context.undefValues,
        permExtendValues, undefValuesWithTokenId);

    AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, hapTokenInfoValues, addInfoVec);
    AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, permStateValues, addInfoVec);
    // optional tables emit add entries only when they carry data; the del
    // entries below still guarantee the rewrite cleanup
    if (!permExtendValues.empty()) {
        AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE,
            permExtendValues, addInfoVec);
    }
    if (!undefValuesWithTokenId.empty()) {
        AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO,
            undefValuesWithTokenId, addInfoVec);
    }

    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, delInfoVec);
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition, delInfoVec);
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, condition,
        delInfoVec);
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, condition, delInfoVec);

    // PERMISSION_DEF is only persisted for system resources (same as master
    // AddHapTokenInfoToDb); non-system-resource tokens skip this table.
    if (AccessTokenInfoUtils::IsSystemResource(installInfo.baseInfo.bundleName) && !permDefValues.empty()) {
        AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, permDefValues, addInfoVec);
        AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, condition, delInfoVec);
    }
    return RET_SUCCESS;
}

int32_t InstallDbRepository::BuildDbOpsVec(const InstallCache& cache,
    const FinishContext& context, const std::map<std::string, std::string>& modulePathMap,
    std::vector<AddInfo>& addInfoVec, std::vector<DelInfo>& delInfoVec)
{
    // collect session uids for reserved bundleId cleanup below
    std::vector<int32_t> sessionUids;
    for (size_t i = 0; i < context.hapInfos.size(); ++i) {
        int32_t ret = GenerateTokenDbOpsVec(cache, context, i, addInfoVec, delInfoVec);
        if (ret != RET_SUCCESS) {
            return ret;
        }
        if (context.hapInfos[i].baseInfo.uid != INVALID_UID) {
            sessionUids.emplace_back(context.hapInfos[i].baseInfo.uid);
        }
    }

    if (!cache.bundleInfos.empty()) {
        std::vector<GenericValues> signValues;
        GenericValues delCondition;
        int32_t ret = ConvertInstallCacheToBundleInfoItems(cache, modulePathMap, signValues, delCondition);
        if (ret != RET_SUCCESS) {
            return ret;
        }
        AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, signValues, addInfoVec);
        AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, delCondition, delInfoVec);
    }

    if (cache.reserved == ReservedType::RESERVED_IDENTITY) {
        GenericValues condition;
        condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(cache.oldTokenId));
        DelInfo delInfo;
        // hap_token_info is required for reserved-identity;
        delInfo.delType = AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO;
        delInfo.delValue = condition;
        delInfoVec.emplace_back(delInfo);
    }
    // Clean up reserved bundleId persist records for all tokens in this session.
    // Batch call: one lock acquisition, one set copy, one DEL + one ADD pair
    AccessTokenIDManager::GetInstance().GetReservedBundleIdsPersistInfo(sessionUids, delInfoVec, addInfoVec);
    return RET_SUCCESS;
}

int32_t InstallDbRepository::GetAppIdFromDb(const std::string& bundleName, MultipleMode mode,
    std::string& appId)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    std::vector<GenericValues> hapTokenResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, hapTokenResults);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Query failed, ret: %{public}d", ret);
        return ERR_DATABASE_OPERATE_FAILED;
    }

    // mode-scoped: hap_token_info has no mode column (mode is encoded in
    // instIndex); pick the first row within the session's mode domain
    for (const auto& tokenValue : hapTokenResults) {
        int32_t instIndex = tokenValue.GetInt(TokenFiledConst::FIELD_INST_INDEX);
        if (!MultipleModeUtils::IsModeInstIndexMatch(static_cast<int32_t>(mode), instIndex)) {
            continue;
        }
        appId = tokenValue.GetString(TokenFiledConst::FIELD_APP_ID);
        return RET_SUCCESS;
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "No token of bundle %{public}s in mode %{public}d.",
        bundleName.c_str(), static_cast<int32_t>(mode));
    return ERR_PARAM_INVALID;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
