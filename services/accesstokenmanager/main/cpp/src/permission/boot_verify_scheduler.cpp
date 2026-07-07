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
#include <memory>
#include <set>
#include <thread>
#include <utility>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_info_manager.h"
#include "add_spm_data_task.h"
#include "data_translator.h"
#include "hisysevent_adapter.h"
#ifdef IS_SUPPORT_HAP_RUNNING
#include "hap_sign_verify_helper.h"
#include "permission_map.h"
#include "permission_constraint_check.h"
#include "permission_manager.h"
#endif
#include "parameter.h"
#include "time_util.h"
#include "user_policy_manager.h"
#include "accesstoken_info_utils.h"
#include "add_spm_data_task.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
#ifndef IS_SUPPORT_HAP_RUNNING
BootVerifyScheduler& BootVerifyScheduler::GetInstance()
{
    static BootVerifyScheduler instance;
    return instance;
}

int32_t BootVerifyScheduler::VerifyBundleSignInfoWhenStart(uint32_t& hapSize)
{
    (void)hapSize;
    return RET_SUCCESS;
}

void BootVerifyScheduler::StartVerifyNormalBundleListAsync()
{}

int32_t BootVerifyScheduler::PreVerifyBundle(const std::string& bundleName)
{
    (void)bundleName;
    return RET_SUCCESS;
}

int32_t BootVerifyScheduler::PreVerifyBundle(uint32_t tokenID)
{
    (void)tokenID;
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
const std::string APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
const std::string APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL = "enterprise_normal";
const std::string APP_DISTRIBUTION_TYPE_NONE = "none";

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

void ReportPreVerifyAddHapEvent(const std::string& bundleName,
    const std::map<std::string, std::shared_ptr<BundleInfoInner>>& bundleInfoMap,
    const std::map<int, HapTokenInfoItem>& hapTokenInfoMap)
{
    AccessTokenID tokenId = INVALID_TOKEN_ID;
    const HapTokenInfoItem* hapInfo = nullptr;
    auto bundleIter = bundleInfoMap.find(bundleName);
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
    dfxInfo.bundleName = bundleName;
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
        uint32_t permCode = 0;
        if (!TransferPermissionToOpcode(permissionName, permCode)) {
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

int32_t BootVerifyScheduler::LoadVerifyDataFromDb()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "LoadVerifyDataFromDb Entry!");
    GenericValues conditionValue;
    std::vector<GenericValues> hapTokenRes;
    std::vector<GenericValues> permStateRes;
    std::vector<GenericValues> extendedPermRes;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, hapTokenRes);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Load hap token info failed, ret=%{public}d.", ret);
        return ret;
    }
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
    InitBundleVerifyContext(hapTokenRes, permStateRes, extendedPermRes);
    return RefreshBundleSignInfoMap();
}

std::vector<DelInfo> BootVerifyScheduler::BuildDeleteInfos(const std::vector<BundleSignInfo>& infos)
{
    std::vector<DelInfo> delInfoVec;
    for (const auto& info : infos) {
        GenericValues conditionValue;
        conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, info.bundleName);
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
            LOGE(ATM_DOMAIN, ATM_TAG, "Translate extended permission failed, tokenId=%{public}u.", tokenId);
            continue;
        }
        uint32_t permCode = 0;
        if (!TransferPermissionToOpcode(perm.permissionName, permCode)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Transfer permission to opcode failed, tokenId=%{public}u.", tokenId);
            continue;
        }
        (void)permCode;
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

bool BootVerifyScheduler::HandleHapInfoUid(const std::string& bundleName, AccessTokenID tokenId, int32_t uid)
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
    if (AccessTokenInfoManager::GetInstance().AddReservedHapInfoFromDbValues(tokenValue)) {
#ifdef SPM_DATA_ENABLE
        int32_t uid = tokenValue.GetInt(TokenFiledConst::FIELD_UID);
        (void)HandleHapInfoUid(bundleName, tokenId, uid);
#endif
        return false;
    }

    const std::vector<GenericValues> emptyPermState;
    auto permStateIter = permStateMap.find(tokenId);
    const auto& permStateValues = (permStateIter == permStateMap.end()) ? emptyPermState : permStateIter->second;
    HapTokenInfoItem hapTokenInfoItem;
    if (!BuildHapTokenInfoItemFromDb(tokenId, tokenValue, hapTokenInfoItem)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build hap token info failed, tokenId=%{public}u.", tokenId);
        return false;
    }

    std::vector<BriefPermData> briefPermData;
    BuildBriefPermDataFromDb(permStateValues, briefPermData);

    int32_t ret = AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "RegisterTokenId failed, tokenId=%{public}u, ret=%{public}d.", tokenId, ret);
        ReportSysCommonEventError(AccessTokenServiceStartSceneCode::REGISTER_TOKEN_ID,
            AccessTokenServiceStartErrorCode::REGISTER_TOKEN_ID_FAILED);
        return false;
    }
#if SPM_DATA_ENABLE
    if (!HandleHapInfoUid(bundleName, tokenId, static_cast<int32_t>(hapTokenInfoItem.uid))) {
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
    auto& bundleInfo = bundleInfoMap_[bundleName];
    if (bundleInfo == nullptr) {
        bundleInfo = std::make_shared<BundleInfoInner>();
    }
    bundleInfo->tokenIds.emplace_back(tokenId);
    bundleNoCachedInfoMap_[bundleName].apl =
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
    std::set<std::string> bundleNameSet;
    for (const auto& item : bundleSignInfoMap_) {
        bundleNameSet.insert(item.first);
    }
    for (const auto& item : hapTokenInfoMap_) {
        if (!item.second.bundleName.empty()) {
            bundleNameSet.insert(item.second.bundleName);
        }
    }

    for (const auto& bundleName : bundleNameSet) {
        if (bundleInfoMap_[bundleName] == nullptr) {
            bundleInfoMap_[bundleName] = std::make_shared<BundleInfoInner>();
        }
        isVerifiedMap_[bundleName] = false;
        isVerifyingMap_[bundleName] = false;

        auto signInfoIter = bundleSignInfoMap_.find(bundleName);
        if (signInfoIter == bundleSignInfoMap_.end()) {
            highPrivilegeBundleList_.emplace_back(bundleName);
            continue;
        }
        if (signInfoIter->second.isPreInstalled) {
            highPrivilegeBundleList_.emplace_back(bundleName);
        } else {
            normalBundleList_.emplace_back(bundleName);
        }
    }

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
        auto& info = bundleSignInfoMap_[bundleName];
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
        info.isPreInstalled = (result.GetInt(TokenFiledConst::FIELD_IS_PREINSTALLED) != 0);
        info.moduleNameList.emplace_back(result.GetString(TokenFiledConst::FIELD_MODULE_NAME));
        info.pathList.emplace_back(result.GetString(TokenFiledConst::FIELD_PATH));
        info.persistDataList.emplace_back(result.GetBlob(TokenFiledConst::FIELD_PERSIST_DATA));
    }
#endif

    return RET_SUCCESS;
}

void BootVerifyScheduler::CommitBundleCacheLocked(const std::string& bundleName)
{
    auto bundleIter = bundleInfoMap_.find(bundleName);
    if (bundleIter == bundleInfoMap_.end() || bundleIter->second == nullptr) {
        return;
    }

    std::vector<AccessTokenInfoManager::HapTokenRestoreData> tokenRestoreDataList;
    for (const auto tokenId : bundleIter->second->tokenIds) {
        auto hapIter = hapTokenInfoMap_.find(tokenId);
        if (hapIter == hapTokenInfoMap_.end()) {
            continue;
        }

        int32_t tryTime = 3;
        for (int32_t i = 0; i < tryTime; ++i) {
            int32_t ret = PermissionKernelUtils::AddHapPermToKernel(tokenId, requestedPermData_[tokenId]);
            if (ret == RET_SUCCESS) {
                break;
            }
        }

        AccessTokenInfoManager::HapTokenRestoreData restoreData;
        restoreData.hapTokenInfoItem = hapIter->second;
        restoreData.requestedPermData = requestedPermData_[tokenId];
        auto extendedPermIter = extendedPermMap_.find(tokenId);
        if (extendedPermIter != extendedPermMap_.end()) {
            restoreData.extendedPermList = extendedPermIter->second;
        }
        tokenRestoreDataList.emplace_back(restoreData);
    }

    AccessTokenInfoManager::GetInstance().RestoreHapCache(
        bundleName, bundleIter->second, tokenRestoreDataList);
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
        if (index >= infoSize) {
            continue;
        }
        if (trustedInfos[index].bootstrapInfo == nullptr) {
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

int32_t BootVerifyScheduler::VerifySingleBundle(const std::string& bundleName, BundleSignInfo& updatedInfo,
    VerifiedBundleState& state)
{
    state.bundleName = bundleName;
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
                bundleName.c_str(), updatedInfo.pathList[i].c_str(), ret);
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
            bundleName.c_str(), ret);
        return ret;
    }
    if (!trustedInfos.empty() && bundleName != trustedInfos[0].GetBundleName()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Bundle name mismatch, bundleName=%{public}s, trustedBundleName=%{public}s.",
            bundleName.c_str(), trustedInfos[0].GetBundleName().c_str());
        return ERR_HAP_SIGN_VERIFY_FAILED;
    }

    UpdateVerifiedSignInfo(bundleName, updatedInfo, changedIndexList, trustedInfos, state);

    HapPolicy policy;
    BundleParam param;
    ret = verifyManager.BuildHapPolicy(trustedInfos, policy, param);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "BuildHapPolicy failed, bundleName=%{public}s, ret=%{public}d.",
            bundleName.c_str(), ret);
        return ret;
    }

    return ReconcileVerifiedBundleCache(bundleName, policy, param, state);
}

void BootVerifyScheduler::UpdateVerifiedSignInfo(const std::string& bundleName, BundleSignInfo& updatedInfo,
    const std::vector<uint32_t>& changedIndexList, const std::vector<TrustedBundleInfoInner>& trustedInfos,
    VerifiedBundleState& state)
{
    if (changedIndexList.empty()) {
        return;
    }
    UpdateBundleSignInfoByTrustedInfos(updatedInfo, changedIndexList, trustedInfos);
    state.needUpdateSignInfo = true;
    std::lock_guard<std::mutex> lock(verifyMutex_);
    bundleSignInfoMap_[bundleName] = updatedInfo;
}

int32_t BootVerifyScheduler::ReconcileVerifiedBundleCache(
    const std::string& bundleName, const HapPolicy& policy, const BundleParam& param, VerifiedBundleState& state)
{
    std::shared_ptr<BundleInfoInner> bundleInfo = nullptr;
    BundleNoCachedInfo noCachedInfo;
    AccessTokenInfoUtils::BuildBundleFullInfo(param, policy, bundleInfo, noCachedInfo);
    std::vector<PermissionWithValue> fixedExtendPerms;
    BuildExtendedPermListFromPolicy(policy, fixedExtendPerms);

    std::lock_guard<std::mutex> lock(verifyMutex_);
    auto bundleIter = bundleInfoMap_.find(bundleName);
    if (bundleIter == bundleInfoMap_.end() || bundleIter->second == nullptr) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Bundle info not exist, bundleName=%{public}s.", bundleName.c_str());
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
        if (!fixedExtendPerms.empty()) {
            extendedPermMap_[tokenId] = fixedExtendPerms;
        }
    }
    bundleNoCachedInfoMap_[bundleName] = noCachedInfo;
    bundleInfo->tokenIds = tokenIds;
    bundleInfoMap_[bundleName] = bundleInfo;
    return RET_SUCCESS;
}

int32_t BootVerifyScheduler::BuildVerifyBundleData(const std::string& bundleName, BundleSignInfo& signInfo)
{
    std::unique_lock<std::mutex> lock(verifyMutex_);
    auto verifiedIter = isVerifiedMap_.find(bundleName);
    if (verifiedIter == isVerifiedMap_.end()) {
        return ERR_BUNDLE_NOT_EXIST;
    }
    if (IsAllBundlesVerified() || verifiedIter->second) {
        return RET_SUCCESS;
    }

    while (isVerifyingMap_[bundleName]) {
        verifyCondition_.wait(lock, [this, &bundleName]() {
            return !isVerifyingMap_[bundleName];
        });
        if (isVerifiedMap_[bundleName]) {
            return RET_SUCCESS;
        }
    }

    auto signInfoIter = bundleSignInfoMap_.find(bundleName);
    if (signInfoIter == bundleSignInfoMap_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build verify bundle data failed, sign info not exist, bundleName=%{public}s.",
            bundleName.c_str());
        return ERR_BUNDLE_NOT_EXIST;
    }
    auto bundleInfoIter = bundleInfoMap_.find(bundleName);
    if (bundleInfoIter == bundleInfoMap_.end() || bundleInfoIter->second == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build verify bundle data failed, bundle info not exist, bundleName=%{public}s.",
            bundleName.c_str());
        return ERR_BUNDLE_NOT_EXIST;
    }
    signInfo = signInfoIter->second;
    isVerifyingMap_[bundleName] = true;
    lock.unlock();

    return RET_SUCCESS;
}

int32_t BootVerifyScheduler::VerifyBundleWithState(const std::string& bundleName, bool isPreVerify)
{
    if (IsAllBundlesVerified()) {
        return RET_SUCCESS;
    }
    BundleSignInfo updatedInfo;
    VerifiedBundleState state;
    int32_t ret = BuildVerifyBundleData(bundleName, updatedInfo);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build verify bundle data failed, bundleName=%{public}s, ret=%{public}d.",
            bundleName.c_str(), ret);
        return ret;
    }

    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        if (isVerifiedMap_[bundleName]) {
            LOGD(ATM_DOMAIN, ATM_TAG, "Bundle already verified, bundleName=%{public}s.", bundleName.c_str());
            return RET_SUCCESS;
        }
        if (ShouldSkipVerifyLocked(bundleName)) {
            FinishSkippedBundleVerifyLocked(bundleName);
            verifyCondition_.notify_all();
            return RET_SUCCESS;
        }
    }

    ret = VerifySingleBundle(bundleName, updatedInfo, state);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Verify single bundle failed, bundleName=%{public}s, ret=%{public}d.",
            bundleName.c_str(), ret);
        ChangeTokenIdToUntrustedStatus(bundleName);
        if (!AccessTokenInfoUtils::IsSystemSpmEnforcing()) {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            FinishCommitBundleVerifyLocked(bundleName);
            verifyCondition_.notify_all();
        } else {
            HandleVerifyBundleFailure(bundleName, ret);
        }
        ReportSysCommonEventError(AccessTokenServiceStartSceneCode::VERIFY_HAP, ret);
    }

    if (ret == RET_SUCCESS) {
        ret = AddSpmDataAndCommitCache(bundleName, { state });
        if (ret == RET_SUCCESS && isPreVerify) {
            ReportPreVerifyAddHapEvent(bundleName, bundleInfoMap_, hapTokenInfoMap_);
        }
    }
    verifyCondition_.notify_all();
    return ret;
}

void BootVerifyScheduler::ChangeTokenIdToUntrustedStatus(const std::string& bundleName)
{
    if (!AccessTokenInfoUtils::IsSystemSpmEnforcing()) {
        return;
    }
    auto bundleIter = bundleInfoMap_.find(bundleName);
    if (bundleIter == bundleInfoMap_.end() || bundleIter->second == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Change tokenId status failed, bundle info not exist, bundleName=%{public}s.",
            bundleName.c_str());
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
    for (const auto& bundleName : normalBundleList_) {
        {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            if (IsAllBundlesVerified()) {
                break;
            }
            auto iter = isVerifiedMap_.find(bundleName);
            if (iter == isVerifiedMap_.end() || iter->second) {
                continue;
            }
        }

        int32_t ret = VerifyBundleWithState(bundleName);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Verify normal bundle failed, bundleName=%{public}s, ret=%{public}d.",
                bundleName.c_str(), ret);
        }
    }
    isAllHapBundlesVerified_.store(true);
    ClearBundleVerifyContext();
    verifyCondition_.notify_all();
    AccessTokenInfoUtils::AccessTokenServiceAppVerifyParamSet();
}

int32_t BootVerifyScheduler::VerifyBundleSignInfoWhenStart(uint32_t& hapSize)
{
    ClearBundleVerifyContext();
    isAllHapBundlesVerified_.store(false);
    int32_t ret = LoadVerifyDataFromDb();
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Load verify data failed, ret=%{public}d.", ret);
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

        const std::string& bundleName = highPrivilegeBundleList_[bundleIndex];
        BundleSignInfo updatedInfo;
        VerifiedBundleState state;
        {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            if (!PrepareBundleForBatchVerifyLocked(bundleName, updatedInfo)) {
                continue;
            }
        }
        int32_t ret = VerifySingleBundle(bundleName, updatedInfo, state);
        if (ret != RET_SUCCESS) {
            ChangeTokenIdToUntrustedStatus(bundleName);
            HandleVerifyBundleFailure(bundleName, ret);
            ReportSysCommonEventError(AccessTokenServiceStartSceneCode::VERIFY_HAP, ret);
            continue;
        }
        stateList.emplace(bundleName, state);
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
    for (const auto& bundleName : highPrivilegeBundleList_) {
        auto stateIter = stateMap.find(bundleName);
        if (stateIter == stateMap.end()) {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            if (!AccessTokenInfoUtils::IsSystemSpmEnforcing()) {
                FinishCommitBundleVerifyLocked(bundleName);
            }
            verifyCondition_.notify_all();
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            if (ShouldSkipVerifyLocked(bundleName)) {
                FinishCommitBundleVerifyLocked(bundleName);
                verifyCondition_.notify_all();
                continue;
            }
        }
        int32_t ret = AddSpmDataForBundle(bundleName);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Add spm data failed, bundleName=%{public}s, ret=%{public}d.",
                bundleName.c_str(), ret);
            continue;
        }
        bundleStatesToPersist.emplace_back(bundleName, stateIter->second);
    }

    int32_t ret = PersistVerifiedBundleStates(bundleStatesToPersist);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Persist verified bundle states failed, ret=%{public}d.", ret);
        ReportSysCommonEventError(AccessTokenServiceStartSceneCode::PERSIST_BUNDLE_DATA, ret);
    }

    for (const auto& [bundleName, state] : bundleStatesToPersist) {
        (void)state;
        {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            FinishCommitBundleVerifyLocked(bundleName);
            LOGI(ATM_DOMAIN, ATM_TAG, "Fast verify finished, bundleName=%{public}s.", bundleName.c_str());
        }
        verifyCondition_.notify_all();
    }
}

bool BootVerifyScheduler::ShouldSkipVerifyLocked(const std::string& bundleName) const
{
    auto bundleIter = bundleInfoMap_.find(bundleName);
    if (bundleIter == bundleInfoMap_.end() || bundleIter->second == nullptr || bundleIter->second->tokenIds.empty()) {
        return true;
    }
    return bundleSignInfoMap_.find(bundleName) == bundleSignInfoMap_.end();
}

void BootVerifyScheduler::FinishSkippedBundleVerifyLocked(const std::string& bundleName)
{
    if (isVerifiedMap_[bundleName]) {
        return;
    }
    CommitBundleCacheLocked(bundleName);
    isVerifiedMap_[bundleName] = true;
    isVerifyingMap_[bundleName] = false;
    LOGI(ATM_DOMAIN, ATM_TAG, "Skip fast verify finished, bundleName=%{public}s.", bundleName.c_str());
}

int32_t BootVerifyScheduler::BuildSpmParams(const std::string& bundleName, BundleNoCachedInfo& noCachedInfo,
    std::vector<HapTokenInfo>& hapInfoCache, std::vector<std::vector<BriefPermData>>& permBriefDataListCache,
    std::vector<std::vector<PermissionWithValue>>& extendPermListCache, std::vector<SpmDataParam>& params)
{
    params.clear();
    hapInfoCache.clear();
    permBriefDataListCache.clear();
    extendPermListCache.clear();
    std::lock_guard<std::mutex> lock(verifyMutex_);
    auto bundleIter = bundleInfoMap_.find(bundleName);
    auto noCachedIter = bundleNoCachedInfoMap_.find(bundleName);
    if (bundleIter == bundleInfoMap_.end() || bundleIter->second == nullptr ||
        noCachedIter == bundleNoCachedInfoMap_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build spm params failed, bundleName=%{public}s.", bundleName.c_str());
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
                "bundleName=%{public}s, tokenId=%{public}u skip load to kernel.", bundleName.c_str(), tokenId);
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

int32_t BootVerifyScheduler::GetBundleTokenIds(const std::string& bundleName, std::vector<AccessTokenID>& tokenIds)
{
    std::lock_guard<std::mutex> lock(verifyMutex_);
    auto bundleIter = bundleInfoMap_.find(bundleName);
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
}

void BootVerifyScheduler::BuildSignInfoPersistInfo(
    const std::string& bundleName, std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec)
{
    BundleSignInfo bundleSignInfo;
    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        bundleSignInfo = bundleSignInfoMap_[bundleName];
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
    const std::string& bundleName, const VerifiedBundleState& state)
{
    if (!state.needUpdateSignInfo && !state.needPersistHapInfo &&
        !state.needPersistPermState) {
        return RET_SUCCESS;
    }
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    int32_t ret = BuildVerifiedBundlePersistInfo(bundleName, state, delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        HandleVerifyBundleFailure(bundleName, ret);
        return ret;
    }

    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        HandleVerifyBundleFailure(bundleName, ret);
        return ret;
    }
    return ret;
}

int32_t BootVerifyScheduler::BuildVerifiedBundlePersistInfo(const std::string& bundleName,
    const VerifiedBundleState& state, std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec)
{
    delInfoVec.clear();
    addInfoVec.clear();
    std::vector<AccessTokenID> tokenIds;
    int32_t ret = GetBundleTokenIds(bundleName, tokenIds);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    for (const auto tokenId : tokenIds) {
        BuildBundlePersistInfos(tokenId, state, delInfoVec, addInfoVec);
    }
    if (state.needUpdateSignInfo) {
        BuildSignInfoPersistInfo(bundleName, delInfoVec, addInfoVec);
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
    for (const auto& [bundleName, state] : bundleStates) {
        std::vector<DelInfo> currentDelInfoVec;
        std::vector<AddInfo> currentAddInfoVec;
        int32_t ret = BuildVerifiedBundlePersistInfo(bundleName, state, currentDelInfoVec, currentAddInfoVec);
        if (ret != RET_SUCCESS) {
            HandleVerifyBundleFailure(bundleName, ret);
            LOGC(ATM_DOMAIN, ATM_TAG, "Failed to build persist info %{public}s", bundleName.c_str());
            continue;
        }
        delInfoVec.insert(delInfoVec.end(), currentDelInfoVec.begin(), currentDelInfoVec.end());
        addInfoVec.insert(addInfoVec.end(), currentAddInfoVec.begin(), currentAddInfoVec.end());
    }
    int tryTime = 2;
    int32_t ret = RET_SUCCESS;
    for (int i = 0; i < tryTime; ++i) {
        ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
        if (ret == RET_SUCCESS) {
            break;
        }
    }
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to persist verified bundle states, ret=%{public}d.", ret);
        for (const auto& [bundleName, state] : bundleStates) {
            (void)state;
            HandleVerifyBundleFailure(bundleName, ret);
        }
    }
    return ret;
}

void BootVerifyScheduler::FinishCommitBundleVerifyLocked(const std::string& bundleName)
{
    if (isVerifiedMap_[bundleName]) {
        return;
    }
    CommitBundleCacheLocked(bundleName);
    isVerifiedMap_[bundleName] = true;
    isVerifyingMap_[bundleName] = false;
}

int32_t BootVerifyScheduler::AddSpmDataAndCommitCache(
    const std::string& bundleName, const VerifiedBundleState& state)
{
    int32_t ret = AddSpmDataForBundle(bundleName);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    int32_t result = PersistVerifiedBundleState(bundleName, state);
    if (result != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to modify database, bundleName=%{public}s.", bundleName.c_str());
        ReportSysCommonEventError(AccessTokenServiceStartSceneCode::PERSIST_BUNDLE_DATA, ret);
        return result;
    }

    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        FinishCommitBundleVerifyLocked(bundleName);
    }
    verifyCondition_.notify_all();

    LOGI(ATM_DOMAIN, ATM_TAG, "Fast verify finished, bundleName=%{public}s.", bundleName.c_str());
    return RET_SUCCESS;
}

int32_t BootVerifyScheduler::AddSpmDataForBundle(const std::string& bundleName)
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
        bundleName, noCachedInfo, hapInfoCache, permBriefDataListCache, extendPermListCache, params);
    if (ret != RET_SUCCESS) {
        HandleVerifyBundleFailure(bundleName, ret);
        return ret;
    }
    if (hapInfoCache.empty()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "No valid hap info found, bundleName=%{public}s.", bundleName.c_str());
        return RET_SUCCESS;
    }

    AddSpmDataTask addSpmDataTask(params);
    uint32_t errIndex = 0;
    ret = addSpmDataTask.Add(errIndex);
    if (ret != RET_SUCCESS && ret != ERR_DATA_CONFLICT_WITH_KERNEL) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Add spm data failed, bundleName=%{public}s, ret=%{public}d.",
            bundleName.c_str(), ret);
        HandleVerifyBundleFailure(bundleName, ret);
        return ret;
    }
    return RET_SUCCESS;
}

bool BootVerifyScheduler::PrepareBundleForBatchVerifyLocked(
    const std::string& bundleName, BundleSignInfo& updatedInfo)
{
    if (ShouldSkipVerifyLocked(bundleName)) {
        FinishSkippedBundleVerifyLocked(bundleName);
        verifyCondition_.notify_all();
        return false;
    }

    auto signInfoIter = bundleSignInfoMap_.find(bundleName);
    if (signInfoIter == bundleSignInfoMap_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Prepare batch verify failed, bundleName=%{public}s.", bundleName.c_str());
        return false;
    }
    updatedInfo = signInfoIter->second;
    isVerifyingMap_[bundleName] = true;
    return true;
}

void BootVerifyScheduler::HandleVerifyBundleFailure(const std::string& bundleName, int32_t ret)
{
    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        isVerifyingMap_[bundleName] = false;
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "Verify bundle failed, bundleName=%{public}s, ret=%{public}d.",
        bundleName.c_str(), ret);
    verifyCondition_.notify_all();
}

int32_t BootVerifyScheduler::PreVerifyBundle(const std::string& bundleName)
{
    if (IsAllBundlesVerified() || bundleInfoMap_.empty()) {
        return RET_SUCCESS;
    }

    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        auto bundleInfoIter = bundleInfoMap_.find(bundleName);
        if (bundleInfoIter == bundleInfoMap_.end()) {
            LOGW(ATM_DOMAIN, ATM_TAG,
                "Pre verify skipped, bundle not exist, bundleName=%{public}s.", bundleName.c_str());
            return RET_SUCCESS;
        }
    }
    return PreVerifyBundleInner(bundleName);
}

int32_t BootVerifyScheduler::PreVerifyBundleInner(const std::string& bundleName)
{
    return VerifyBundleWithState(bundleName, true);
}

int32_t BootVerifyScheduler::PreVerifyBundle(uint32_t tokenID)
{
    if (IsAllBundlesVerified() || hapTokenInfoMap_.empty()) {
        return RET_SUCCESS;
    }

    std::string bundleName;
    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        auto tokenIter = hapTokenInfoMap_.find(tokenID);
        if (tokenIter == hapTokenInfoMap_.end()) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Pre verify skipped, token not exist, tokenId=%{public}u.", tokenID);
            return RET_SUCCESS;
        }
        bundleName = tokenIter->second.bundleName;
    }
    if (bundleName.empty()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Pre verify skipped, bundle name empty, tokenId=%{public}u.", tokenID);
        return RET_SUCCESS;
    }
    return PreVerifyBundleInner(bundleName);
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
