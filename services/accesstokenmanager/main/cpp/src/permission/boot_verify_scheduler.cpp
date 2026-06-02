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
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "add_spm_data_task.h"
#include "data_translator.h"
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

int32_t BootVerifyScheduler::VerifyBundleSignInfoWhenStart()
{
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
constexpr int32_t INVALID_UID = -1;
constexpr AccessTokenID INVALID_TOKEN_ID = 0;
constexpr uint32_t TOKEN_ID_SHIFT = 32;
constexpr uint32_t IS_KERNEL_EFFECT = (0x1 << 0);
constexpr uint32_t HAS_VALUE = (0x1 << 1);
constexpr uint32_t API_VERSION_SUFFIX_LEN = 3;
const std::string APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM = "enterprise_mdm";
const std::string APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL = "enterprise_normal";
const std::string APP_DISTRIBUTION_TYPE_NONE = "none";
static const char* ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY = "accesstoken.permission.appverify";
static constexpr int32_t VALUE_MAX_LEN = 32;

int32_t GetStoredApiVersion(int32_t apiVersion)
{
    std::string apiStr = std::to_string(apiVersion);
    if (apiStr.length() <= API_VERSION_SUFFIX_LEN) {
        return apiVersion;
    }
    return std::atoi(apiStr.substr(apiStr.length() - API_VERSION_SUFFIX_LEN).c_str());
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

void BootVerifyScheduler::AccessTokenServiceAppVerifyParamSet() const
{
    int32_t res = SetParameter(ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY, std::to_string(1).c_str());
    if (res != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SetParameter ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY 1 failed %{public}d.", res);
        return;
    }
}

bool BootVerifyScheduler::IsSystemAppVerified() const
{
    char value[VALUE_MAX_LEN] = {0};
    int32_t ret = GetParameter(ACCESS_TOKEN_SERVICE_APP_VERIFY_KEY, "", value, VALUE_MAX_LEN - 1);
    if (ret < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "At service has been started, ret=%{public}d.", ret);
        return false;
    }
    if (static_cast<uint64_t>(std::atoll(value)) != 0) {
        return true;
    }
    return false;
}

int32_t BootVerifyScheduler::LoadVerifyDataFromDb()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "LoadVerifyDataFromDb Entry!");
    GenericValues conditionValue;
    std::vector<GenericValues> hapTokenRes;
    std::vector<GenericValues> permStateRes;
    std::vector<GenericValues> extendedPermRes;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_INFO, conditionValue, hapTokenRes);
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
    if (AccessTokenInfoManager::GetInstance().AddReservedHapInfoFromDb(tokenValue)) {
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
        LOGE(ATM_DOMAIN, ATM_TAG, "RegisterTokenId failed, tokenId=%{public}u, ret=%{public}d.", tokenId, ret);
        return false;
    }
#if SPM_DATA_ENABLE
    if (hapTokenInfoItem.uid > 0) {
        if (uidSet_.count(static_cast<int32_t>(hapTokenInfoItem.uid)) == 0) {
            uidSet_.insert(static_cast<int32_t>(hapTokenInfoItem.uid));
            AccessTokenIDManager::GetInstance().InitSingleBundleIdCache(static_cast<int32_t>(hapTokenInfoItem.uid));
        } else {
            LOGW(ATM_DOMAIN, ATM_TAG, "Duplicate uid found for tokenId=%{public}u, uid=%{public}d.", tokenId,
                hapTokenInfoItem.uid);
            return false;
        }
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
    hapTokenInfoItem.reserved = static_cast<ReservedType>(tokenValue.GetInt(TokenFiledConst::FIELD_RESERVED));
    hapTokenInfoItem.permDialogCapState = tokenValue.GetInt(TokenFiledConst::FIELD_FORBID_PERM_DIALOG) != 0;
#ifdef SPM_DATA_ENABLE
    hapTokenInfoItem.migrated = tokenValue.GetInt(TokenFiledConst::FIELD_MIGRATED) != 0;
    hapTokenInfoItem.uid = static_cast<uint32_t>(tokenValue.GetInt(TokenFiledConst::FIELD_UID));
#endif

    if (static_cast<char>(hapTokenInfoItem.version) != DEFAULT_TOKEN_VERSION) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid token version, tokenId=%{public}u, version=%{public}d.",
            tokenId, hapTokenInfoItem.version);
        return false;
    }
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
        if (!TransferPermissionToOpcode(state.permissionName, permCode)) {
            continue;
        }
        PermissionBriefDef briefDef;
        GetPermissionBriefDef(permCode, briefDef);
        if (!briefDef.isEnable) {
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
            LOGW(ATM_DOMAIN, ATM_TAG, "Invalid bundle type in db, bundleName=%{public}s, bundleType=%{public}d.",
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

    for (const auto tokenId : bundleIter->second->tokenIds) {
        auto hapIter = hapTokenInfoMap_.find(tokenId);
        if (hapIter == hapTokenInfoMap_.end()) {
            continue;
        }
        std::map<uint64_t, std::string> extendValueMap;
        auto extendedPermIter = extendedPermMap_.find(tokenId);
        if (extendedPermIter != extendedPermMap_.end() && !extendedPermIter->second.empty()) {
            for (const auto& perm : extendedPermIter->second) {
                uint32_t permCode = 0;
                if (!TransferPermissionToOpcode(perm.permissionName, permCode)) {
                    continue;
                }
                extendValueMap[(static_cast<uint64_t>(tokenId) << TOKEN_ID_SHIFT) | permCode] = perm.value;
            }
        }

        int32_t tryTime = 3;
        for (int32_t i = 0; i < tryTime; ++i) {
            int32_t ret = PermissionKernelUtils::AddHapPermToKernel(tokenId, requestedPermData_[tokenId]);
            if (ret == RET_SUCCESS) {
                break;
            }
        }
        PermissionDataBrief::GetInstance().ReplaceExtendedValueByTokenId(tokenId, extendValueMap);
        HapTokenInfo hapInfo = ConvertToHapTokenInfo(hapIter->second);
        AccessTokenInfoManager::GetInstance().CommitCreateHapCache(
            hapInfo, requestedPermData_[tokenId], bundleIter->second);
    }
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

std::vector<std::vector<std::string>> BootVerifyScheduler::SplitBundleList(
    const std::vector<std::string>& bundleNameList, uint32_t size)
{
    std::vector<std::vector<std::string>> splitList(size);
    if (size == 0) {
        return splitList;
    }
    for (size_t i = 0; i < bundleNameList.size(); ++i) {
        splitList[i % size].emplace_back(bundleNameList[i]);
    }
    return splitList;
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
            updatedInfo.pathList[i], Verify::VerifyType::Fast, -1, trustedInfo, isChanged);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Check hap sign info failed, bundleName=%{public}s, path=%{public}s, ret=%{public}d.",
                bundleName.c_str(), updatedInfo.pathList[i].c_str(), ret);
            return ERR_HAP_VERIFY_FAILED;
        }
        trustedInfos.emplace_back(trustedInfo);
        if (isChanged) {
            changedIndexList.emplace_back(i);
        }
    }

    ret = verifyManager.CheckMultipleHaps(trustedInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Check multiple haps failed, bundleName=%{public}s, ret=%{public}d.",
            bundleName.c_str(), ret);
        return ret;
    }

    UpdateVerifiedSignInfo(bundleName, updatedInfo, changedIndexList, trustedInfos, state);

    HapPolicy policy;
    BundleParam param;
    ret = verifyManager.BuildHapPolicy(trustedInfos, policy, param);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "BuildHapPolicy failed, bundleName=%{public}s, ret=%{public}d.",
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Bundle info not exist, bundleName=%{public}s.", bundleName.c_str());
        return ERR_BUNDLE_NOT_EXIST;
    }
    const auto tokenIds = bundleIter->second->tokenIds;
    for (const auto tokenId : tokenIds) {
        auto hapIter = hapTokenInfoMap_.find(tokenId);
        if (hapIter == hapTokenInfoMap_.end()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Hap token info not exist, tokenId=%{public}u.", tokenId);
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

int32_t BootVerifyScheduler::VerifyBundleWithState(const std::string& bundleName)
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Verify single bundle failed, bundleName=%{public}s, ret=%{public}d.",
            bundleName.c_str(), ret);
        HandleVerifyBundleFailure(bundleName, ret);
    }

    if (ret == RET_SUCCESS) {
        ret = AddSpmDataAndCommitCache(bundleName, { state });
    }
    verifyCondition_.notify_all();
    return ret;
}

int32_t BootVerifyScheduler::VerifyBundleList(const std::vector<std::string>& bundleNameList,
    std::map<std::string, VerifiedBundleState>& stateList)
{
    for (const auto& bundleName : bundleNameList) {
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
            HandleVerifyBundleFailure(bundleName, ret);
            continue;
        }
        stateList.emplace(bundleName, state);
    }
    return RET_SUCCESS;
}

void BootVerifyScheduler::StartNormalBundleVerifyThread()
{
    if (normalBundleList_.empty()) {
        isAllHapBundlesVerified_.store(true);
        ClearBundleVerifyContext();
        AccessTokenServiceAppVerifyParamSet();
        return;
    }
    std::thread([this]() {
        VerifyNormalBundleListAsync();
    }).detach();
}

void BootVerifyScheduler::StartVerifyNormalBundleListAsync()
{
    StartNormalBundleVerifyThread();
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
    AccessTokenServiceAppVerifyParamSet();
}

int32_t BootVerifyScheduler::VerifyBundleSignInfoWhenStart()
{
    ClearBundleVerifyContext();
    isAllHapBundlesVerified_.store(false);
    int32_t ret = LoadVerifyDataFromDb();
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Load verify data failed, ret=%{public}d.", ret);
        return ret;
    }

    BuildPriorityBundleList();
    std::map<std::string, VerifiedBundleState> stateList;
    ret = VerifyHighPrivilegeBundleList(stateList);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Verify high privilege bundle list failed, ret=%{public}d.", ret);
        return ret;
    }
    HandleHighPrivilegeBundleSpmData(stateList);
    return RET_SUCCESS;
}

int32_t BootVerifyScheduler::VerifyHighPrivilegeBundleList(std::map<std::string, VerifiedBundleState>& stateList)
{
    std::vector<std::map<std::string, VerifiedBundleState>> stateGroups;
    int32_t ret = RunHighPrivilegeBundleVerifyTasks(stateGroups);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Run high privilege bundle verify tasks failed, ret=%{public}d.", ret);
        return ret;
    }
    stateList.clear();
    for (const auto& infoGroup : stateGroups) {
        stateList.insert(infoGroup.begin(), infoGroup.end());
    }
    return RET_SUCCESS;
}

int32_t BootVerifyScheduler::RunHighPrivilegeBundleVerifyTasks(
    std::vector<std::map<std::string, VerifiedBundleState>>& stateGroups)
{
    auto splitLists = SplitBundleList(highPrivilegeBundleList_, VERIFY_THREAD_COUNT);
    std::vector<std::thread> threads;
    std::vector<int32_t> verifyResults(splitLists.size(), RET_SUCCESS);
    stateGroups.assign(splitLists.size(), {});
    threads.reserve(splitLists.size());
    for (size_t i = 0; i < splitLists.size(); ++i) {
        threads.emplace_back([this, &splitLists, &verifyResults, &stateGroups, i]() {
            verifyResults[i] = VerifyBundleList(splitLists[i], stateGroups[i]);
        });
    }
    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    int32_t ret = GetVerifyTaskResult(verifyResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get verify task result failed, ret=%{public}d.", ret);
    }
    return ret;
}

int32_t BootVerifyScheduler::GetVerifyTaskResult(const std::vector<int32_t>& verifyResults)
{
    for (const auto& result : verifyResults) {
        if (result != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Verify task failed, ret=%{public}d.", result);
            return result;
        }
    }
    return RET_SUCCESS;
}

bool BootVerifyScheduler::ShouldSkipAddSpmData(const std::string& bundleName)
{
    std::lock_guard<std::mutex> lock(verifyMutex_);
    auto bundleIter = bundleInfoMap_.find(bundleName);
    if (bundleIter == bundleInfoMap_.end()) {
        return true;
    }
    if (bundleIter->second == nullptr || bundleIter->second->tokenIds.empty()) {
        return false;
    }
    return std::all_of(bundleIter->second->tokenIds.begin(), bundleIter->second->tokenIds.end(),
        [this](AccessTokenID tokenId) {
            auto hapIter = hapTokenInfoMap_.find(tokenId);
            return hapIter != hapTokenInfoMap_.end() &&
                static_cast<int32_t>(hapIter->second.uid) == INVALID_UID && !hapIter->second.migrated;
        });
}

void BootVerifyScheduler::HandleHighPrivilegeBundleSpmData(const std::map<std::string, VerifiedBundleState>& stateMap)
{
    for (const auto& bundleName : highPrivilegeBundleList_) {
        auto stateIter = stateMap.find(bundleName);
        if (ShouldSkipAddSpmData(bundleName) || (stateIter == stateMap.end())) {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            FinishCommitBundleVerifyLocked(bundleName);
            verifyCondition_.notify_all();
            continue;
        }
        int32_t ret = AddSpmDataAndCommitCache(bundleName, stateIter->second);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Add spm data failed, bundleName=%{public}s, ret=%{public}d.",
                bundleName.c_str(), ret);
            continue;
        }
    }
}

bool BootVerifyScheduler::IsInvalidUid(AccessTokenID tokenId) const
{
    auto hapIter = hapTokenInfoMap_.find(tokenId);
    return hapIter != hapTokenInfoMap_.end() && static_cast<int32_t>(hapIter->second.uid) == INVALID_UID;
}

bool BootVerifyScheduler::ShouldSkipVerifyLocked(const std::string& bundleName) const
{
    auto bundleIter = bundleInfoMap_.find(bundleName);
    if (bundleIter == bundleInfoMap_.end() || bundleIter->second == nullptr) {
        return false;
    }
    return bundleSignInfoMap_.find(bundleName) == bundleSignInfoMap_.end() ||
        std::all_of(bundleIter->second->tokenIds.begin(), bundleIter->second->tokenIds.end(),
        [this](AccessTokenID tokenId) {
            return IsInvalidUid(tokenId);
        });
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
        delInfoVec.emplace_back(DelInfo { AtmDataType::ACCESSTOKEN_HAP_INFO, condition });
        std::vector<GenericValues> hapInfoValues;
        {
            std::lock_guard<std::mutex> lock(verifyMutex_);
            hapTokenInfoMap_[tokenId].BuildAddValue(hapInfoValues);
        }
        if (!hapInfoValues.empty()) {
            addInfoVec.emplace_back(AddInfo { AtmDataType::ACCESSTOKEN_HAP_INFO, hapInfoValues });
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
    const std::string& bundleName, const VerifiedBundleState& state, AddSpmDataTask& addSpmDataTask)
{
    if (!state.needUpdateSignInfo && !state.needPersistHapInfo &&
        !state.needPersistPermState) {
        return RET_SUCCESS;
    }
    std::vector<AccessTokenID> tokenIds;
    int32_t ret = GetBundleTokenIds(bundleName, tokenIds);
    if (ret != RET_SUCCESS) {
        (void)addSpmDataTask.Rollback();
        HandleVerifyBundleFailure(bundleName, ret);
        return ret;
    }

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    for (const auto tokenId : tokenIds) {
        BuildBundlePersistInfos(tokenId, state, delInfoVec, addInfoVec);
    }
    if (state.needUpdateSignInfo) {
        BuildSignInfoPersistInfo(bundleName, delInfoVec, addInfoVec);
    }

    ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        (void)addSpmDataTask.Rollback();
        HandleVerifyBundleFailure(bundleName, ret);
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
    if (!IsSystemAppVerified()) {
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

        AddSpmDataTask addSpmDataTask(params);
        uint32_t errIndex = 0;
        ret = addSpmDataTask.Add(errIndex);
        if (ret != RET_SUCCESS && ret != ERR_DATA_CONFLICT_WITH_KERNEL) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Add spm data failed, bundleName=%{public}s, ret=%{public}d.",
                bundleName.c_str(), ret);
            HandleVerifyBundleFailure(bundleName, ret);
            return ret;
        }
        ret = PersistVerifiedBundleState(bundleName, state, addSpmDataTask);
        if (ret != RET_SUCCESS) {
            return ret;
        }
    }

    {
        std::lock_guard<std::mutex> lock(verifyMutex_);
        FinishCommitBundleVerifyLocked(bundleName);
    }
    verifyCondition_.notify_all();

    LOGI(ATM_DOMAIN, ATM_TAG, "Fast verify finished, bundleName=%{public}s.", bundleName.c_str());
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
    return VerifyBundleWithState(bundleName);
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
    return PreVerifyBundle(bundleName);
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
