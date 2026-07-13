/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "accesstoken_info_manager.h"

#include "delete_bundle_manager.h"

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <map>
#include <unistd.h>
#include <securec.h>
#include "access_token.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_utils.h"
#include "accesstoken_common_log.h"
#include "accesstoken_remote_token_manager.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "atm_tools_param_info_parcel.h"
#include "callback_manager.h"
#include "constant_common.h"
#include "data_translator.h"
#include "data_validator.h"
#ifdef SUPPORT_SANDBOX_APP
#include "dlp_permission_set_manager.h"
#endif
#include "generic_values.h"
#include "hap_token_info_inner.h"
#include "hisysevent_adapter.h"
#include "ipc_skeleton.h"
#include "json_parse_loader.h"
#include "libraryloader.h"
#include "permission_change_notifier.h"
#include "permission_constraint_check.h"
#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
#include "os_account_manager_lite.h"
#endif
#include "permission_feature_manager.h"
#include "permission_kernel_utils.h"
#include "permission_map.h"
#include "permission_manager.h"
#include "permission_validator.h"
#include "permission_data_brief.h"
#include "idl_common.h"
#include "perm_setproc.h"
#include "spm_setproc.h"
#include "tokenid_attributes.h"
#include "token_field_const.h"
#include "token_setproc.h"
#include "user_policy_manager.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_modify_notifier.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
static const uint32_t SYSTEM_APP_FLAG = 0x0001;
static const uint32_t ATOMIC_SERVICE_FLAG = 0x0002;
static const uint32_t TOKEN_RESERVED_FLAG = 0x0004;
static const uint32_t DEBUG_APP_FLAG = 0x0008;
static constexpr int32_t BASE_USER_RANGE = 200000;
static constexpr int32_t INVALID_HAP_UID = -1;
#ifdef TOKEN_SYNC_ENABLE
static const int MAX_PTHREAD_NAME_LEN = 15; // pthread name max length
static const char* ACCESS_TOKEN_PACKAGE_NAME = "ohos.security.distributed_token_sync";
#endif
static constexpr uint32_t TOKEN_ID_LOWMASK = 0xffffffff;
static constexpr int32_t DEFAULT_MAX_QUERY_RESULT_SIZE = ACCESS_TOKEN_DEFAULT_MAX_QUERY_RESULT_SIZE;
static constexpr int32_t DEFAULT_SUBPROFILE_INDEX = -1;

void ClearNonPersistedUserPolicyFlags(std::vector<GenericValues>& permStateValues)
{
    for (auto& permStateValue : permStateValues) {
        uint32_t permCode = 0;
        const std::string permissionName = permStateValue.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        if (!TransferPermissionToOpcode(permissionName, permCode)) {
            continue;
        }
        if (UserPolicyManager::GetInstance().IsPolicyPersisted(permCode)) {
            continue;
        }
        uint32_t grantFlag = static_cast<uint32_t>(permStateValue.GetInt(TokenFiledConst::FIELD_GRANT_FLAG));
        grantFlag = ConstantCommon::GetFlagWithoutSpecifiedElement(grantFlag, PERMISSION_RESTRICTED_BY_ADMIN);
        permStateValue.Remove(TokenFiledConst::FIELD_GRANT_FLAG);
        permStateValue.Put(TokenFiledConst::FIELD_GRANT_FLAG, static_cast<int32_t>(grantFlag));
    }
}

uint64_t GetPermissionTimestamp(const GenericValues& stateValue)
{
    int64_t timestamp = stateValue.GetInt64(TokenFiledConst::FIELD_TIMESTAMP);
    return timestamp <= 0 ? 0 : static_cast<uint64_t>(timestamp);
}

PermissionStatus BuildPermissionStatusFromBrief(const BriefPermData& briefPermData)
{
    PermissionStatus permState;
    permState.permissionName = TransferOpcodeToPermission(briefPermData.permCode);
    permState.grantStatus = static_cast<int32_t>(briefPermData.status);
    permState.grantFlag = briefPermData.flag;
    return permState;
}

std::shared_ptr<BundleInfoInner> BuildBundleInfoWithoutToken(
    const std::shared_ptr<BundleInfoInner>& bundleInfo, AccessTokenID tokenId)
{
    if (bundleInfo == nullptr) {
        return nullptr;
    }
    auto result = std::make_shared<BundleInfoInner>(*bundleInfo);
    result->tokenIds.erase(std::remove(result->tokenIds.begin(), result->tokenIds.end(), tokenId),
        result->tokenIds.end());
    return result;
}

void RollbackRestrictedFlag(AccessTokenID tokenId, uint32_t permCode, bool isRestricted)
{
    PermissionDataBrief::PermissionStatusChangeType rollbackChangeType =
        PermissionDataBrief::PermissionStatusChangeType::NO_CHANGE;
    int32_t ret = PermissionDataBrief::GetInstance().UpdatePermissionFlag(
        tokenId, permCode, PERMISSION_RESTRICTED_BY_ADMIN, !isRestricted, rollbackChangeType);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Rollback restricted flag failed, tokenId=%{public}u, permCode=%{public}u, ret=%{public}d.",
            tokenId, permCode, ret);
    }
}

void AddGrantedNativePermissionStatus(
    AccessTokenID tokenID, uint32_t permCode, std::vector<PermissionStatusIdl>& permissionInfoList)
{
    PermissionStatusIdl idl;
    idl.tokenID = tokenID;
    idl.permCode = permCode;
    idl.grantStatus = PERMISSION_GRANTED;
    idl.grantFlag = PERMISSION_SYSTEM_FIXED;
    idl.timestamp = 0;
    permissionInfoList.emplace_back(idl);
}

void AddNativePermissionsFromCache(const NativeTokenInfoCache& cache, AccessTokenID tokenID,
    const std::unordered_set<uint32_t>& permCodeSet, std::vector<PermissionStatusIdl>& permissionInfoList)
{
    for (const auto opCode : cache.opCodeList) {
        uint32_t permCode = static_cast<uint16_t>(opCode);
        if (permCodeSet.find(permCode) == permCodeSet.end()) {
            continue;
        }
        AddGrantedNativePermissionStatus(tokenID, permCode, permissionInfoList);
    }
}

void AddNativePermissionsFromKernel(const std::vector<uint32_t>& permCodeList, AccessTokenID tokenID,
    std::vector<PermissionStatusIdl>& permissionInfoList)
{
    std::vector<uint32_t> grantedPermCodeList;
    int32_t ret = GetPermissionsFromKernel(static_cast<uint32_t>(tokenID), grantedPermCodeList);
    if (ret != ACCESS_TOKEN_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Get native perms from kernel failed, tokenId=%{public}u, ret=%{public}d.", tokenID, ret);
        return;
    }

    std::unordered_set<uint32_t> grantedPermCodeSet(grantedPermCodeList.begin(), grantedPermCodeList.end());
    for (const auto permCode : permCodeList) {
        if (grantedPermCodeSet.find(permCode) != grantedPermCodeSet.end()) {
            AddGrantedNativePermissionStatus(tokenID, permCode, permissionInfoList);
        }
    }
}

int32_t RestoreRestrictedFlag(AccessTokenID tokenId, uint32_t permCode, uint32_t originalFlag)
{
    int32_t currentStatus = PERMISSION_DENIED;
    uint32_t currentFlag = 0;
    int32_t ret = PermissionDataBrief::GetInstance().QueryStoredPermissionStatusAndFlag(
        tokenId, permCode, currentStatus, currentFlag);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    bool currentRestricted = (currentFlag & PERMISSION_RESTRICTED_BY_ADMIN) != 0;
    bool originalRestricted = (originalFlag & PERMISSION_RESTRICTED_BY_ADMIN) != 0;
    if (currentRestricted == originalRestricted) {
        return RET_SUCCESS;
    }

    PermissionDataBrief::PermissionStatusChangeType rollbackChangeType =
        PermissionDataBrief::PermissionStatusChangeType::NO_CHANGE;
    return PermissionDataBrief::GetInstance().UpdatePermissionFlag(
        tokenId, permCode, PERMISSION_RESTRICTED_BY_ADMIN, originalRestricted, rollbackChangeType);
}

void RestoreKernelPermissionState(
    AccessTokenID tokenId, uint32_t permCode, int32_t originalStatus, uint32_t originalFlag)
{
    std::string permissionName = TransferOpcodeToPermission(permCode);
    bool kernelStatus = ((originalFlag & PERMISSION_RESTRICTED_BY_ADMIN) == 0) &&
        (originalStatus == PERMISSION_GRANTED);
    PermissionKernelUtils::SetPermToKernel(tokenId, permissionName, kernelStatus);
}
}

int32_t AccessTokenInfoManager::FindPermissionByNameFromDb(const std::vector<uint32_t>& permCodeList,
    std::unordered_map<std::string, uint32_t>& permissionNameToCodeMap, std::vector<GenericValues>& permStateResults)
{
    std::unordered_set<AccessTokenID> hapTokenIdSet;
    int32_t userId = IPCSkeleton::GetCallingUid() / BASE_USER_RANGE;
    if (userId == 0) {
        GetAllHapTokenId(hapTokenIdSet);
    } else {
        GetTokenIDByUserID(userId, -1, hapTokenIdSet);
    }

    if (hapTokenIdSet.empty()) {
        return RET_SUCCESS;
    }

    std::vector<VariantValue> permissionValues;
    permissionValues.reserve(permCodeList.size());
    for (const auto permCode : permCodeList) {
        const std::string permissionName = TransferOpcodeToPermission(permCode);
        if (permissionName.empty()) {
            return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
        }
        if (permissionNameToCodeMap.find(permissionName) != permissionNameToCodeMap.end()) {
            continue;
        }

        permissionNameToCodeMap.emplace(permissionName, permCode);
        permissionValues.emplace_back(permissionName);
    }

    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE,
        TokenFiledConst::FIELD_PERMISSION_NAME, permissionValues, permStateResults);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    permStateResults.erase(std::remove_if(permStateResults.begin(), permStateResults.end(),
        [&hapTokenIdSet](const GenericValues& value) {
            return hapTokenIdSet.count(static_cast<AccessTokenID>(value.GetInt(TokenFiledConst::FIELD_TOKEN_ID))) == 0;
        }), permStateResults.end());
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::FindPermissionByTokenIdFromDb(const std::vector<AccessTokenID>& tokenIDList,
    std::vector<GenericValues>& permStateResults)
{
    std::unordered_set<AccessTokenID> tokenIdSet;
    tokenIdSet.reserve(tokenIDList.size());
    std::vector<VariantValue> tokenIdValues;
    tokenIdValues.reserve(tokenIDList.size());
    for (const auto tokenID : tokenIDList) {
        if (tokenIdSet.find(tokenID) != tokenIdSet.end()) {
            continue;
        }
        if (tokenID == 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TokenID cannot be 0.");
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        if (!IsTokenIdExist(tokenID)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TokenID %{public}u does not exist.", tokenID);
            return AccessTokenError::ERR_TOKENID_NOT_EXIST;
        }
        if (TokenIDAttributes::GetTokenIdTypeEnum(tokenID) != TOKEN_HAP) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TokenID %{public}u is not HAP type.", tokenID);
            return AccessTokenError::ERR_PARAM_INVALID;
        }

        tokenIdSet.emplace(tokenID);
        tokenIdValues.emplace_back(static_cast<int32_t>(tokenID));
    }

    return AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, TokenFiledConst::FIELD_TOKEN_ID, tokenIdValues, permStateResults);
}

AccessTokenInfoManager::AccessTokenInfoManager()
    : hasInited_(false), maxQueryResultSize_(DEFAULT_MAX_QUERY_RESULT_SIZE) {}

std::shared_ptr<BundleInfoInner> AccessTokenInfoManager::GetBundleInfoInner(const std::string& bundleName)
{
    if (bundleName.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Bundle name is empty.");
        return nullptr;
    }

    std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    auto iter = bundleInfoMap_.find(bundleName);
    if (iter != bundleInfoMap_.end() && iter->second != nullptr) {
        return iter->second;
    }
    return nullptr;
}

void AccessTokenInfoManager::UpsertBundleInfoInnerCache(
    const std::string& bundleName, const std::shared_ptr<BundleInfoInner>& bundleInfo)
{
    if (bundleName.empty() || bundleInfo == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Bundle info cache upsert input is invalid.");
        return;
    }

    std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    UpsertBundleInfoInnerCacheWithoutLock(bundleName, bundleInfo);
}

void AccessTokenInfoManager::UpsertBundleInfoInnerCacheWithoutLock(
    const std::string& bundleName, const std::shared_ptr<BundleInfoInner>& bundleInfo)
{
    if (bundleName.empty() || bundleInfo == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Bundle info cache upsert input is invalid.");
        return;
    }

    bundleInfoMap_[bundleName] = bundleInfo;
}

void AccessTokenInfoManager::AddTokenIdToBundleInfoInner(
    const std::shared_ptr<BundleInfoInner>& bundleInfo, AccessTokenID tokenId)
{
    if (bundleInfo == nullptr) {
        return;
    }

    if (std::find(bundleInfo->tokenIds.begin(), bundleInfo->tokenIds.end(), tokenId) == bundleInfo->tokenIds.end()) {
        bundleInfo->tokenIds.emplace_back(tokenId);
    }
}

void AccessTokenInfoManager::RemoveTokenIdFromBundleInfoInner(
    const std::shared_ptr<BundleInfoInner>& bundleInfo, AccessTokenID tokenId)
{
    if (bundleInfo == nullptr) {
        return;
    }
    bundleInfo->tokenIds.erase(std::remove(bundleInfo->tokenIds.begin(), bundleInfo->tokenIds.end(), tokenId),
        bundleInfo->tokenIds.end());
}

void AccessTokenInfoManager::RestoreHapCache(const std::string& bundleName,
    const std::shared_ptr<BundleInfoInner>& bundleInfo,
    const std::vector<HapTokenRestoreData>& tokenRestoreDataList)
{
    std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    for (const auto& tokenRestoreData : tokenRestoreDataList) {
        AccessTokenID tokenID = tokenRestoreData.hapTokenInfoItem.tokenId;
        std::shared_ptr<HapTokenInfoInner> hapInfoInner =
            std::make_shared<HapTokenInfoInner>(tokenRestoreData.hapTokenInfoItem);
        hapTokenInfoMap_[tokenID] = hapInfoInner;
        hapTokenIdMap_[AccessTokenInfoUtils::GetHapUniqueStr(hapInfoInner)] = tokenID;
        PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(
            tokenID, tokenRestoreData.requestedPermData, tokenRestoreData.extendedPermList);
    }
    if (bundleInfo != nullptr) {
        UpsertBundleInfoInnerCacheWithoutLock(bundleName, bundleInfo);
    }
}

void AccessTokenInfoManager::CommitCreateHapCache(const HapTokenInfo& hapInfo,
    const std::vector<BriefPermData>& briefPermData,
    const std::vector<PermissionWithValue>& aclExtendedList,
    const std::shared_ptr<BundleInfoInner>& bundleInfo)
{
    AccessTokenID tokenID = hapInfo.tokenID;
    std::shared_ptr<HapTokenInfoInner> hapInfoInner =
        std::make_shared<HapTokenInfoInner>(tokenID, hapInfo, std::vector<PermissionStatus>{});
    std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    hapTokenInfoMap_[tokenID] = hapInfoInner;
    hapTokenIdMap_[AccessTokenInfoUtils::GetHapUniqueStr(hapInfoInner)] = tokenID;
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(tokenID, briefPermData, aclExtendedList);
    if (bundleInfo != nullptr) {
        auto bundleIter = bundleInfoMap_.find(hapInfo.bundleName);
        if (bundleIter != bundleInfoMap_.end() && bundleIter->second != nullptr && bundleIter->second != bundleInfo) {
            for (const auto oldTokenId : bundleIter->second->tokenIds) {
                AddTokenIdToBundleInfoInner(bundleInfo, oldTokenId);
            }
        }
        AddTokenIdToBundleInfoInner(bundleInfo, tokenID);
        UpsertBundleInfoInnerCacheWithoutLock(hapInfo.bundleName, bundleInfo);
    }
}

void AccessTokenInfoManager::CommitUpdateHapCache(const HapTokenInfo& hapInfo,
    const std::vector<BriefPermData>& briefPermData,
    const std::vector<PermissionWithValue>& aclExtendedList,
    const std::shared_ptr<BundleInfoInner>& bundleInfo)
{
    AccessTokenID tokenID = hapInfo.tokenID;
    std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    auto oldHapIter = hapTokenInfoMap_.find(tokenID);
    if (oldHapIter == hapTokenInfoMap_.end() || oldHapIter->second == nullptr) {
        return;
    }
    std::shared_ptr<HapTokenInfoInner> oldHapInfo = oldHapIter->second;
    if (!oldHapInfo->IsRemote()) {
        std::string oldUniqueKey = AccessTokenInfoUtils::GetHapUniqueStr(oldHapInfo);
        auto iter = hapTokenIdMap_.find(oldUniqueKey);
        if (iter != hapTokenIdMap_.end() && iter->second == tokenID) {
            hapTokenIdMap_.erase(iter);
        }
    }
    oldHapInfo->SetTokenBaseInfo(hapInfo);
    if (!oldHapInfo->IsRemote()) {
        hapTokenIdMap_[AccessTokenInfoUtils::GetHapUniqueStr(oldHapInfo)] = tokenID;
    }
    PermissionDataBrief::GetInstance().ReplaceBriefPermDataByTokenId(tokenID, briefPermData, aclExtendedList);
    if (bundleInfo != nullptr) {
        auto bundleIter = bundleInfoMap_.find(hapInfo.bundleName);
        if (bundleIter != bundleInfoMap_.end() && bundleIter->second != nullptr && bundleIter->second != bundleInfo) {
            bundleInfo->tokenIds = bundleIter->second->tokenIds;
        }
        AddTokenIdToBundleInfoInner(bundleInfo, tokenID);
        UpsertBundleInfoInnerCacheWithoutLock(hapInfo.bundleName, bundleInfo);
    }
}

int32_t AccessTokenInfoManager::CommitDeleteHapCache(AccessTokenID tokenID, const std::string& bundleName)
{
    std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);

    std::shared_ptr<HapTokenInfoInner> oldHapInfo = nullptr;
    auto oldHapIter = hapTokenInfoMap_.find(tokenID);
    if (oldHapIter != hapTokenInfoMap_.end()) {
        oldHapInfo = oldHapIter->second;
    }

    // Check if remote token can not be deleted
    if (oldHapInfo != nullptr && oldHapInfo->IsRemote()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Remote hap token %{public}u can not delete.", tokenID);
        return ERR_IDENTITY_CHECK_FAILED;
    }

    if (oldHapInfo != nullptr) {
        std::string uniqueKey = AccessTokenInfoUtils::GetHapUniqueStr(oldHapInfo);
        auto iter = hapTokenIdMap_.find(uniqueKey);
        if (iter != hapTokenIdMap_.end() && iter->second == tokenID) {
            hapTokenIdMap_.erase(iter);
        }
    }
    hapTokenInfoMap_.erase(tokenID);
    (void)PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(tokenID);

    auto bundleIter = bundleInfoMap_.find(bundleName);
    auto bundleInfo = (bundleIter == bundleInfoMap_.end()) ? nullptr :
        BuildBundleInfoWithoutToken(bundleIter->second, tokenID);
    if (bundleInfo == nullptr || bundleInfo->tokenIds.empty()) {
        bundleInfoMap_.erase(bundleName);
    } else {
        UpsertBundleInfoInnerCacheWithoutLock(bundleName, bundleInfo);
    }

    return RET_SUCCESS;
}

AccessTokenInfoManager::~AccessTokenInfoManager()
{
    if (!hasInited_) {
        return;
    }

#ifdef TOKEN_SYNC_ENABLE
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().UnInitDeviceManager(ACCESS_TOKEN_PACKAGE_NAME);
    if (ret != ERR_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "UnInitDeviceManager failed, code: %{public}d", ret);
    }
#endif

    this->hasInited_ = false;
    std::unique_lock<std::shared_mutex> monitorLock(this->monitorLock_);
    this->tokenMonitor_ = nullptr;
}

void AccessTokenInfoManager::Init(uint32_t& nativeSize, uint32_t& pefDefSize, uint32_t& dlpSize)
{
    std::unique_lock<std::shared_mutex> lk(this->managerLock_);
    if (hasInited_) {
        return;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Init begin!");
    LibraryLoader loader(CONFIG_PARSE_LIBPATH);
    ConfigPolicyLoaderInterface* policy = loader.GetObject<ConfigPolicyLoaderInterface>();
    if (policy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Dlopen libaccesstoken_json_parse failed.");
        return;
    }
    std::vector<NativeTokenInfoBase> tokenInfos;
    int ret = policy->GetAllNativeTokenInfo(tokenInfos);
    if (ret != RET_SUCCESS) {
        ReportSysEventServiceStartError(
            INIT_NATIVE_TOKENINFO_ERROR, "GetAllNativeTokenInfo fail from native json.", ret);
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to load native from native json, err=%{public}d.", ret);
        return;
    }

#ifdef SUPPORT_SANDBOX_APP
    std::vector<PermissionDlpMode> dlpPerms;
    ret = policy->GetDlpPermissions(dlpPerms);
    dlpSize = dlpPerms.size();
    if (ret == RET_SUCCESS) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Load dlpPer size=%{public}u.", dlpSize);
        DlpPermissionSetManager::GetInstance().ProcessDlpPermInfos(dlpPerms);
    }
#endif

    AccessTokenConfigValue featureValue;
    if (policy->GetConfigValue(ConfigType::PERMISSION_FEATURES, featureValue)) {
        PermissionFeatureManager::GetInstance().SetFeatures(featureValue.permissionFeatures);
    }

    LoadPermissionDefinitionExt(*policy);
    nativeSize = tokenInfos.size();
    InitNativeTokenInfos(tokenInfos);
    pefDefSize = GetDefPermissionsSize();

    LOGI(ATM_DOMAIN, ATM_TAG,
        "Init success, nativeSize %{public}u, pefDefSize %{public}u, dlpSize %{public}u.",
        nativeSize, pefDefSize, dlpSize);

    hasInited_ = true;
    {
        std::unique_lock<std::shared_mutex> monitorLock(this->monitorLock_);
        if (this->tokenMonitor_ == nullptr) {
            this->tokenMonitor_ = std::make_shared<VerifyAccessTokenMonitor>();
        }
    }
}

void AccessTokenInfoManager::LoadPermissionDefinitionExt(ConfigPolicyLoaderInterface& policy)
{
    std::vector<std::string> permissions;
    if (policy.GetPermissionDefinitionExt(permissions) != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Failed to get permission definition extension");
        return;
    }
    for (const auto& permissionName : permissions) {
        if (!SetPermissionBriefEnabled(permissionName, true)) {
            LOGW(ATM_DOMAIN, ATM_TAG,
                "Permission in ext file is invalid %{public}s.", permissionName.c_str());
        }
    }
}

#ifdef TOKEN_SYNC_ENABLE
void AccessTokenInfoManager::InitDmCallback(void)
{
    std::function<void()> runner = []() {
        std::string name = "AtmInfoMgrInit";
        pthread_setname_np(pthread_self(), name.substr(0, MAX_PTHREAD_NAME_LEN).c_str());
        std::shared_ptr<AccessTokenDmInitCallback> ptrDmInitCallback = std::make_shared<AccessTokenDmInitCallback>();
        int32_t ret = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(ACCESS_TOKEN_PACKAGE_NAME,
            ptrDmInitCallback);
        if (ret != ERR_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Initialize: InitDeviceManager error, result: %{public}d", ret);
        }
        LOGI(ATM_DOMAIN, ATM_TAG, "device manager part init end");
        return;
    };
    std::thread initThread(runner);
    initThread.detach();
}
#endif

bool AccessTokenInfoManager::AddReservedHapInfoFromDbValues(const GenericValues& tokenValue)
{
    AccessTokenID tokenId = static_cast<AccessTokenID>(tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
    std::string bundle = tokenValue.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
    ReservedType type = AccessTokenInfoUtils::GetReservedTokenTypeDBValue(tokenValue);
    if (type != ReservedType::NONE) {
        AccessTokenIDManager::GetInstance().AddReservedTokenId(tokenId);
        LOGI(ATM_DOMAIN, ATM_TAG, "Restore reserved hap token %{public}u bundle name %{public}s ",
            tokenId, bundle.c_str());
        return true;
    }

    return false;
}

int32_t AccessTokenInfoManager::AddHapInfoToCache(const GenericValues& tokenValue,
    const std::vector<GenericValues>& permStateRes, const std::vector<GenericValues>& extendedPermRes)
{
    AccessTokenID tokenId = static_cast<AccessTokenID>(tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
    std::string bundle = tokenValue.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
    if (AccessTokenInfoUtils::CheckSpecifiedFlag(
        tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ATTR), TOKEN_RESERVED_FLAG)) {
        int32_t instIndex = tokenValue.GetInt(TokenFiledConst::FIELD_INST_INDEX);
        int32_t userId = tokenValue.GetInt(TokenFiledConst::FIELD_USER_ID);
        AccessTokenIDManager::GetInstance().AddReservedTokenId(tokenId);
        LOGI(ATM_DOMAIN, ATM_TAG, "Restore reserved hap token %{public}u bundle name %{public}s user %{public}d,"
            "inst %{public}d ok!", tokenId, bundle.c_str(), userId, instIndex);
        return RET_SUCCESS;
    }
    int result = AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP);
    if (result != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId %{public}u add id failed, error=%{public}d.", tokenId, result);
        ReportSysEventServiceStartError(INIT_HAP_TOKENINFO_ERROR,
            "RegisterTokenId fail, " + bundle + std::to_string(tokenId), result);
        return result;
    }
    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
    result = hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes, extendedPermRes);
    if (result != RET_SUCCESS) {
        AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId %{public}u restore failed.", tokenId);
        return result;
    }

    AccessTokenID oriTokenId = 0;
    if ((result = AddHapTokenInfo(hap, oriTokenId)) != RET_SUCCESS) {
        AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId %{public}u add failed.", tokenId);
        ReportSysEventServiceStartError(INIT_HAP_TOKENINFO_ERROR,
            "AddHapTokenInfo fail, " + bundle + std::to_string(tokenId), result);
        return result;
    }

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    tokenIdEx.tokenIdExStruct.tokenAttr = hap->GetAttr();

    HapDfxInfo dfxInfo;
    dfxInfo.sceneCode = AddHapSceneCode::INIT;
    dfxInfo.tokenId = tokenId;
    dfxInfo.oriTokenId = oriTokenId;
    dfxInfo.tokenIdEx = tokenIdEx;
    dfxInfo.userID = hap->GetUserID();
    dfxInfo.bundleName = hap->GetBundleName();
    dfxInfo.instIndex = hap->GetInstIndex();
    ReportSysEventAddHap(RET_SUCCESS, dfxInfo, false);

    LOGI(ATM_DOMAIN, ATM_TAG, "Restore hap token %{public}u bundle name %{public}s user %{public}d,"
        " permSize %{public}d, inst %{public}d ok!",
        tokenId, hap->GetBundleName().c_str(), hap->GetUserID(), hap->GetReqPermissionSize(), hap->GetInstIndex());

    return RET_SUCCESS;
}

int AccessTokenInfoManager::AddHapTokenInfo(const std::shared_ptr<HapTokenInfoInner>& info, AccessTokenID& oriTokenId)
{
    if (info == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token info is null.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    AccessTokenID id = info->GetTokenID();
    AccessTokenID idRemoved = INVALID_TOKENID;
    {
        std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(id) > 0) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Token %{public}u info has exist.", id);
            return AccessTokenError::ERR_TOKENID_HAS_EXISTED;
        }

        if (!info->IsRemote()) {
            std::string hapUniqueKey = AccessTokenInfoUtils::GetHapUniqueStr(info);
            auto iter = hapTokenIdMap_.find(hapUniqueKey);
            if (iter != hapTokenIdMap_.end()) {
                LOGI(ATM_DOMAIN, ATM_TAG, "Token %{public}u Unique info has exist, update.", id);
                idRemoved = iter->second;
            }
            hapTokenIdMap_[hapUniqueKey] = id;
        }
        hapTokenInfoMap_[id] = info;
    }
    if (idRemoved != INVALID_TOKENID) {
        oriTokenId = idRemoved;
        (void)DeleteIdentity(idRemoved, info->GetBundleName(), ReservedType::NONE);
    }
    // add hap to kernel
    std::vector<uint32_t> opCodeList;
    HapTokenInfoInner::GetGrantedPermCodeList(id, opCodeList);
    (void)PermissionKernelUtils::AddHapPermToKernel(id, opCodeList);
    return RET_SUCCESS;
}

std::shared_ptr<HapTokenInfoInner> AccessTokenInfoManager::GetHapTokenInfoInnerFromDb(AccessTokenID id)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(id));

    std::vector<GenericValues> hapTokenResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, hapTokenResults);
    if (ret != RET_SUCCESS || hapTokenResults.empty()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to find Id(%{public}u) from hap_token_table, err: %{public}d, "
            "hapSize: %{public}zu, mapSize: %{public}zu.", id, ret, hapTokenResults.size(), hapTokenInfoMap_.size());
        return nullptr;
    }

    if (AddReservedHapInfoFromDbValues(hapTokenResults[0])) {
#ifdef SPM_DATA_ENABLE
        int32_t uid = hapTokenResults[0].GetInt(TokenFiledConst::FIELD_UID);
        AccessTokenIDManager::GetInstance().InitSingleBundleIdCache(uid);
#endif
        return nullptr;
    }

    std::vector<GenericValues> permStateRes;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateRes);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to find Id(%{public}u) from perm_state_table, err: %{public}d, "
            "mapSize: %{public}zu.", id, ret, hapTokenInfoMap_.size());
        return nullptr;
    }

    std::vector<GenericValues> extendedPermRes;
    ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, conditionValue,
        extendedPermRes);
    if (ret != RET_SUCCESS) { // extendedPermRes may be empty
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to find Id(%{public}u) from perm_extend_value_table, err: %{public}d, "
            "mapSize: %{public}zu.", id, ret, hapTokenInfoMap_.size());
        return nullptr;
    }

    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
    ret = hap->RestoreHapTokenInfo(id, hapTokenResults[0], permStateRes, extendedPermRes);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Id %{public}u restore failed, err: %{public}d, mapSize: %{public}zu.",
            id, ret, hapTokenInfoMap_.size());
        return nullptr;
    }

    return hap;
}

std::shared_ptr<HapTokenInfoInner> AccessTokenInfoManager::GetActiveTokenInfoFromDb(AccessTokenID id)
{
    std::shared_ptr<HapTokenInfoInner> hap = GetHapTokenInfoInnerFromDb(id);
    if (hap == nullptr) {
        return nullptr;
    }
    std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    (void)AccessTokenIDManager::GetInstance().RegisterTokenId(id, TOKEN_HAP);
    hapTokenIdMap_[AccessTokenInfoUtils::GetHapUniqueStr(hap)] = id;
    hapTokenInfoMap_[id] = hap;
    std::vector<uint32_t> opCodeList;
    HapTokenInfoInner::GetGrantedPermCodeList(id, opCodeList);
    (void)PermissionKernelUtils::AddHapPermToKernel(id, opCodeList);
    LOGI(ATM_DOMAIN, ATM_TAG, " Token %{public}u is not found in map(mapSize: %{public}zu), begin load from DB,"
        " restore bundle %{public}s user %{public}d, idx %{public}d, permSize %{public}d.", id, hapTokenInfoMap_.size(),
        hap->GetBundleName().c_str(), hap->GetUserID(), hap->GetInstIndex(), hap->GetReqPermissionSize());
    return hap;
}

std::shared_ptr<HapTokenInfoInner> AccessTokenInfoManager::GetHapTokenInfoInner(AccessTokenID id, bool isActive)
{
    {
        std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
        auto iter = hapTokenInfoMap_.find(id);
        if (iter != hapTokenInfoMap_.end()) {
            return iter->second;
        }
    }
    // if found in reserved set, return nullptr;
    TokenIdStatus status;
    if (AccessTokenIDManager::GetInstance().GetTokenIdStatus(id, status) != RET_SUCCESS) {
        return nullptr;
    }
    if (status == TokenIdStatus::ACTIVE) {
        return GetActiveTokenInfoFromDb(id);
    } else if (!isActive) {
        return GetInactiveTokenInfoInner(id);
    }
    return nullptr;
}

std::shared_ptr<HapTokenInfoInner> AccessTokenInfoManager::GetInactiveTokenInfoInner(AccessTokenID id)
{
    {
        std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
        auto iter = inactiveTokenInfoMap_.find(id);
        if (iter != inactiveTokenInfoMap_.end()) {
            return iter->second;
        }
    }

    auto hapInfoInner = GetHapTokenInfoInnerFromDb(id);
    std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    inactiveTokenInfoMap_[id] = hapInfoInner;
    return hapInfoInner;
}

void AccessTokenInfoManager::ReleaseInactiveTokenInfoInner(AccessTokenID id)
{
    std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    inactiveTokenInfoMap_.erase(id);
}

int32_t AccessTokenInfoManager::GetHapTokenDlpType(AccessTokenID id)
{
    std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    auto iter = hapTokenInfoMap_.find(id);
    if ((iter != hapTokenInfoMap_.end()) && (iter->second != nullptr)) {
        return iter->second->GetDlpType();
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid, mapSize: %{public}zu.", id, hapTokenInfoMap_.size());
    return BUTT_DLP_TYPE;
}

bool AccessTokenInfoManager::IsTokenIdExist(AccessTokenID id)
{
    {
        std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(id) != 0) {
            return true;
        }
    }
    {
        std::shared_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
        if (nativeTokenInfoMap_.count(id) != 0) {
            return true;
        }
    }
    return false;
}

bool AccessTokenInfoManager::IsHapTokenIdExist(AccessTokenID id)
{
    std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    return hapTokenInfoMap_.count(id) != 0;
}

void AccessTokenInfoManager::GetTokenIDByUserID(
    int32_t userID, int32_t subProfileId, std::unordered_set<AccessTokenID>& tokenIdList)
{
    int32_t resolvedIndex = DEFAULT_SUBPROFILE_INDEX;
#ifdef ACCESS_TOKEN_SUPPORT_SUBPROFILE
    if (subProfileId >= 0) {
        int32_t ret = OHOS::AccountSA::OsAccountManagerLite::GetOsAccountSubProfileIndex(
            userID, subProfileId, resolvedIndex);
        if ((ret != ERR_OK) || (resolvedIndex < 0)) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Get subProfile index failed, userID=%{public}d, subProfileId=%{public}d, ret=%{public}d, "
                "index=%{public}d.",
                userID, subProfileId, ret, resolvedIndex);
            return;
        }
    }
#endif
    std::shared_lock<std::shared_mutex> infoGuard(hapTokenInfoLock_);
    for (const auto& [key, tokenInfoPtr] : hapTokenInfoMap_) {
        if ((tokenInfoPtr == nullptr) || (tokenInfoPtr->GetUserID() != userID)) {
            continue;
        }
        if ((resolvedIndex != DEFAULT_SUBPROFILE_INDEX) && (tokenInfoPtr->GetInstIndex() != resolvedIndex)) {
            continue;
        }
        tokenIdList.emplace(tokenInfoPtr->GetTokenID());
    }
}

void AccessTokenInfoManager::GetAllNativeTokenPerms(const std::vector<uint32_t>& permCodeList,
    std::vector<PermissionStatusIdl>& permissionInfoList)
{
    std::shared_lock<std::shared_mutex> infoGuard(nativeTokenInfoLock_);
    std::unordered_set<uint32_t> permCodeSet(permCodeList.begin(), permCodeList.end());
    for (const auto& [tokenID, cache] : nativeTokenInfoMap_) {
        if (!PermissionKernelUtils::IsKernelSupportSpm()) {
            AddNativePermissionsFromCache(cache, tokenID, permCodeSet, permissionInfoList);
            continue;
        }
        AddNativePermissionsFromKernel(permCodeList, tokenID, permissionInfoList);
    }
}

void AccessTokenInfoManager::GetAllHapTokenId(std::unordered_set<AccessTokenID>& tokenIdList)
{
    std::shared_lock<std::shared_mutex> infoGuard(hapTokenInfoLock_);
    for (const auto& [key, tokenInfoPtr] : hapTokenInfoMap_) {
        if (tokenInfoPtr != nullptr) {
            tokenIdList.emplace(tokenInfoPtr->GetTokenID());
        }
    }
}

int32_t AccessTokenInfoManager::GetHapTokenIdListByBundleName(
    const std::string& bundleName, std::vector<AccessTokenID>& tokenIdList)
{
    tokenIdList.clear();
    std::shared_lock<std::shared_mutex> infoGuard(hapTokenInfoLock_);
    for (const auto& item : hapTokenInfoMap_) {
        const auto& tokenInfoPtr = item.second;
        if (tokenInfoPtr != nullptr && !tokenInfoPtr->IsRemote() &&
            tokenInfoPtr->GetBundleName() == bundleName) {
            tokenIdList.emplace_back(tokenInfoPtr->GetTokenID());
        }
    }
    if (tokenIdList.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Bundle %{public}s does not exist.", bundleName.c_str());
        return ERR_BUNDLE_NOT_EXIST;
    }
    return RET_SUCCESS;
}

void AccessTokenInfoManager::GetAllNativeTokenId(std::unordered_set<AccessTokenID>& tokenIdList)
{
    std::shared_lock<std::shared_mutex> infoGuard(nativeTokenInfoLock_);
    for (const auto& [tokenID, cache] : nativeTokenInfoMap_) {
        tokenIdList.emplace(tokenID);
    }
}

int AccessTokenInfoManager::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& info)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    infoPtr->TranslateToHapTokenInfo(info);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoBase& info)
{
    std::shared_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
    auto iter = nativeTokenInfoMap_.find(tokenID);
    if (iter == nativeTokenInfoMap_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id %{public}u is not exist.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    info.apl = iter->second.apl;
    info.processName = iter->second.processName;
    return RET_SUCCESS;
}

int AccessTokenInfoManager::RemoveHapTokenInfo(AccessTokenID id, bool isTokenReserved)
{
    ReservedType deleteType = isTokenReserved ? ReservedType::RESERVED_IDENTITY : ReservedType::NONE;
    ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdType(id);
    if (type != TOKEN_HAP) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Token %{public}u is not hap.", id);
        return ERR_PARAM_INVALID;
    }
    std::shared_ptr<HapTokenInfoInner> info = GetHapTokenInfoInner(id);
    if (info == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is not exist.", id);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    return DeleteIdentityInner(info, deleteType);
}

int32_t AccessTokenInfoManager::DeleteIdentityInner(std::shared_ptr<HapTokenInfoInner> info, ReservedType delType)
{
    AccessTokenID id = info->GetTokenID();
    // 1. remove from kernel
    PermissionKernelUtils::RemovePermFromKernel(id); // remove permission from kernel
    PermissionKernelUtils::RemoveSpmEntryFromKernel(id); // remove spm entry from kernel

    // 2. remove from db
    int32_t dbRet = DeleteBundleManager::RemoveHapTokenInfoFromDb(info, delType, id);
    if (dbRet != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remove info from db failed, ret is %{public}d", dbRet);
    }
    int32_t ret = DeleteBundleManager::TryCleanBundleInfo(info);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Try clean bundle info failed, ret is %{public}d", ret);
    }

    // 3. get data to invoke notifier
    std::vector<std::string> permissionList;
    HapTokenInfoInner::GetGrantedPermList(id, permissionList);

    // 4. Remove from cache (includes hapTokenInfoMap_, hapTokenIdMap_, and bundleInfoMap_)
    ret = CommitDeleteHapCache(id, info->GetBundleName());
    if (ret != RET_SUCCESS) {
        return ret;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Remove hap token %{public}u ok!", id);

    // 5. Release or Reserve TokenID
    if (dbRet == RET_SUCCESS) {
        if (delType != ReservedType::NONE) {
            (void)AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
                id, TokenIdStatus::RESERVED);
        } else {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(id);
        }
    }

    // 6. trigger change callback
    if (!permissionList.empty()) {
        PermissionChangeNotifier::GetInstance().ParamUpdate(permissionList[0], 0, true);
    }
    for (const auto& perm : permissionList) {
        CallbackManager::GetInstance().ExecuteCallbackAsync(id, perm, STATE_CHANGE_REVOKED);
    }

#ifdef TOKEN_SYNC_ENABLE
    TokenModifyNotifier::GetInstance().NotifyTokenDelete(id);
#endif

    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::DeleteIdentity(AccessTokenID id, const std::string &bundleName, ReservedType type)
{
    // 0. Check Token Type
    ATokenTypeEnum tokenType = TokenIDAttributes::GetTokenIdTypeEnum(id);
    if (tokenType != TOKEN_HAP) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Token %{public}u is not hap.", id);
        return ERR_PARAM_INVALID;
    }
    // 1. Look up the token in the active map.
    std::shared_ptr<HapTokenInfoInner> info = GetHapTokenInfoInner(id);
    if (info == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is not exist.", id);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    // 2. Validate bundleName match.
    if (info->GetBundleName() != bundleName) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u does not belong to bundle %{public}s.", id, bundleName.c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return DeleteIdentityInner(info, type);
}

int32_t AccessTokenInfoManager::RefreshTokenStatus(const Identity& identity, ReservedType reserved)
{
    AccessTokenID id = static_cast<AccessTokenID>(identity.tokenId);
    int32_t newUid = identity.uid;
    LOGI(ATM_DOMAIN, ATM_TAG, "RefreshTokenStatus tokenId=%{public}u, uid=%{public}d.", id, newUid);

    std::shared_ptr<HapTokenInfoInner> info = GetHapTokenInfoInner(id, false);
    if (info == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u not exist.", id);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    int32_t originalUid = info->GetUid();
    if (originalUid == newUid) {
        return RET_SUCCESS;
    }

    if (originalUid != INVALID_HAP_UID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u already has UID %{public}d.", id, originalUid);
        return AccessTokenError::ERR_MIGRATION_COMPLETED;
    }

    int32_t ret = CheckUidConflictInDb(id, newUid);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    ret = UpdateTokenUidToDb(id, newUid, originalUid, reserved);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    AccessTokenIDManager::GetInstance().InitSingleBundleIdCache(newUid);
    AccessTokenInfoManager::GetInstance().ReleaseInactiveTokenInfoInner(id);
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::CheckUidConflictInDb(AccessTokenID id, int32_t newUid)
{
    GenericValues uidCondition;
    uidCondition.Put(TokenFiledConst::FIELD_UID, newUid);
    std::vector<GenericValues> uidResults;
    if (AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, uidCondition, uidResults)
        == RET_SUCCESS) {
        for (const auto& row : uidResults) {
            AccessTokenID existingTokenId = static_cast<AccessTokenID>(row.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
            if (existingTokenId != id) {
                LOGE(ATM_DOMAIN, ATM_TAG, "UID %{public}d exists for token %{public}u.", newUid, existingTokenId);
                return AccessTokenError::ERR_MIGRATION_UID_DUPLICATED;
            }
        }
    }
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::UpdateTokenUidToDb(
    AccessTokenID id, int32_t newUid, int32_t originalUid, ReservedType reserved)
{
    std::shared_ptr<HapTokenInfoInner> info = GetHapTokenInfoInner(id, false);
    if (info == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u not exist.", id);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    info->SetUid(newUid);
    info->SetMigrated(true);

    GenericValues modifyValue;
    modifyValue.Put(TokenFiledConst::FIELD_UID, newUid);
    modifyValue.Put(TokenFiledConst::FIELD_MIGRATED, 1);
    if (reserved != ReservedType::NONE) {
        modifyValue.Put(TokenFiledConst::FIELD_RESERVED, static_cast<int32_t>(reserved));
        modifyValue.Put(TokenFiledConst::FIELD_TOKEN_ATTR,
            static_cast<int32_t>(info->GetAttr() | TOKEN_RESERVED_FLAG));
        AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(id, TokenIdStatus::RESERVED);
    }

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(id));
    int32_t dbRet = AccessTokenDbOperator::Modify(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO,
        modifyValue, conditionValue);
    if (dbRet != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Update database failed, ret=%{public}d.", dbRet);
        info->SetUid(originalUid);
        info->SetMigrated(false);
        return ERR_DATABASE_OPERATE_FAILED;
    }

    return RET_SUCCESS;
}

int AccessTokenInfoManager::RemoveNativeTokenInfo(AccessTokenID id)
{
    ATokenTypeEnum type = AccessTokenIDManager::GetInstance().GetTokenIdType(id);
    if ((type != TOKEN_NATIVE) && (type != TOKEN_SHELL)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is not native or shell.", id);
        return ERR_PARAM_INVALID;
    }

    {
        std::unique_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
        if (nativeTokenInfoMap_.count(id) == 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Native token %{public}u is null.", id);
            return ERR_TOKENID_NOT_EXIST;
        }

        nativeTokenInfoMap_.erase(id);
    }
    AccessTokenIDManager::GetInstance().ReleaseTokenId(id);
    LOGI(ATM_DOMAIN, ATM_TAG, "Remove native token %{public}u ok!", id);

    // remove native to kernel
    PermissionKernelUtils::RemovePermFromKernel(id);
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::CheckHapInfoParam(const HapInfoParams& info, const HapPolicy& policy)
{
    if ((!DataValidator::IsUserIdValid(info.userID)) || (!DataValidator::IsBundleNameValid(info.bundleName)) ||
        (!DataValidator::IsAppIDDescValid(info.appIDDesc)) || (!DataValidator::IsDomainValid(policy.domain)) ||
        (!DataValidator::IsDlpTypeValid(info.dlpType)) || (info.isRestore && info.tokenID == INVALID_TOKENID) ||
        (!DataValidator::IsAclExtendedMapSizeValid(policy.aclExtendedMap)) ||
        (!DataValidator::IsAppProvisionTypeValid(info.appProvisionType))) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Hap token param failed");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    for (const auto& extendValue : policy.aclExtendedMap) {
        if (!IsDefinedPermissionInner(extendValue.first)) {
            continue;
        }
        if (!DataValidator::IsAclExtendedMapContentValid(extendValue.first, extendValue.second)) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Acl extended content is invalid.");
            return AccessTokenError::ERR_PARAM_INVALID;
        }
    }
    return ERR_OK;
}

void AccessTokenInfoManager::RemoveReservedTokenForBundle(const HapInfoParams& info,
    std::vector<AccessTokenID>& tokenIds)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, info.bundleName);
    condition.Put(TokenFiledConst::FIELD_USER_ID, static_cast<int32_t>(info.userID));
    condition.Put(TokenFiledConst::FIELD_INST_INDEX, static_cast<int32_t>(info.instIndex));

    std::vector<GenericValues> tokenValues;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, tokenValues);
    if (ret == RET_SUCCESS && !tokenValues.empty()) {
        for (auto value: tokenValues) {
            AccessTokenID reservedTokenId = static_cast<AccessTokenID>(value.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
            tokenIds.emplace_back(reservedTokenId);
            LOGI(ATM_DOMAIN, ATM_TAG, "Found reserved token %{public}u in db for bundle %{public}s.",
                reservedTokenId, info.bundleName.c_str());
        }
    }
}

void AccessTokenInfoManager::DeleteOldReservedTokens(const std::vector<AccessTokenID>& reservedTokenIds,
    const std::string& bundleName)
{
    for (auto curTokenId : reservedTokenIds) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Deleting old token %{public}u after new token created.", curTokenId);
        if (AccessTokenIDManager::GetInstance().IsReservedTokenId(curTokenId)) {
            DeleteBundleManager::GetInstance().DeleteReservedToken(curTokenId, bundleName);
        } else if (AccessTokenIDManager::GetInstance().RegisterTokenId(curTokenId, TOKEN_HAP) == RET_SUCCESS) {
            DeleteBundleManager::GetInstance().DeleteDataByTokenId(curTokenId, bundleName);
            AccessTokenIDManager::GetInstance().ReleaseTokenId(curTokenId);
        } else {
            // Use DeleteIdentity to delete both DB data and memory maps
            (void)DeleteIdentity(curTokenId, bundleName, ReservedType::NONE);
            AccessTokenIDManager::GetInstance().ReleaseTokenId(curTokenId);
        }
    }
}

void AccessTokenInfoManager::ReportAddHapIdChange(const std::shared_ptr<HapTokenInfoInner>& hapInfo,
    AccessTokenID oriTokenId)
{
    HapDfxInfo dfxInfo;
    dfxInfo.sceneCode = AddHapSceneCode::TOKEN_ID_CHANGE;
    dfxInfo.tokenId = hapInfo->GetTokenID();
    dfxInfo.oriTokenId = oriTokenId;
    dfxInfo.userID = hapInfo->GetUserID();
    dfxInfo.bundleName = hapInfo->GetBundleName();
    dfxInfo.instIndex = hapInfo->GetInstIndex();
    ReportSysEventAddHap(RET_SUCCESS, dfxInfo, false);
}

int32_t AccessTokenInfoManager::RegisterTokenId(const HapInfoParams& info, AccessTokenID& tokenId)
{
    int32_t res = RET_SUCCESS;

    if (info.isRestore) {
        LOGI(ATM_DOMAIN, ATM_TAG, "IsRestore is true, tokenId is %{public}u.", info.tokenID);

        res = AccessTokenIDManager::GetInstance().RegisterTokenId(info.tokenID, TOKEN_HAP);
        if (res != RET_SUCCESS) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Token Id register failed, errCode is %{public}d.", res);
            return res;
        }

        tokenId = info.tokenID;
    } else {
        int32_t dlpFlag = (info.dlpType > DLP_COMMON) ? 1 : 0;
        int32_t cloneFlag = ((dlpFlag == 0) && (info.instIndex) > 0) ? 1 : 0;
        tokenId = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(TOKEN_HAP, dlpFlag, cloneFlag, 0);
        if (tokenId == 0) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Token Id create failed");
            return ERR_TOKENID_CREATE_FAILED;
        }
    }

    return res;
}

void AccessTokenInfoManager::AddTokenIdToUndefValues(AccessTokenID tokenId, std::vector<GenericValues>& undefValues)
{
    for (auto& value : undefValues) {
        value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    }
}

const std::vector<GenericValues>& AccessTokenInfoManager::HapTokenDbContext::GetEmptyPermStateValues()
{
    static const std::vector<GenericValues> emptyPermStateValues;
    return emptyPermStateValues;
}

AccessTokenInfoManager::HapTokenDbContext::HapTokenDbContext(const std::string& appIdValue,
    const HapPolicy& policyValue, const std::vector<GenericValues>& undefValuesValue,
    const std::vector<GenericValues>& oldPermStateValuesValue, bool isUpdateValue)
    : appId(appIdValue), policy(policyValue), undefValues(undefValuesValue),
      oldPermStateValues(oldPermStateValuesValue), isUpdate(isUpdateValue)
{
}

int AccessTokenInfoManager::CreateHapTokenInfo(const HapInfoParams& info, const HapPolicy& policy,
    AccessTokenIDEx& tokenIdEx, std::vector<GenericValues>& undefValues)
{
    if (CheckHapInfoParam(info, policy) != ERR_OK) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    AccessTokenID tokenId;
    int32_t ret = RegisterTokenId(info, tokenId);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    HapPolicy policyNew = policy;
#ifdef SUPPORT_SANDBOX_APP
    if (info.dlpType != DLP_COMMON) {
        DlpPermissionSetManager::GetInstance().UpdatePermStateWithDlpInfo(info.dlpType, policyNew.permStateList);
    }
#endif
    UserPolicyManager::GetInstance().UpdatePermissionStatusListForUserPolicy(
        tokenId, info.userID, policyNew.permStateList);

    // Check if there are any reserved tokens for the same bundle
    std::vector<AccessTokenID> reservedTokenIds;
    RemoveReservedTokenForBundle(info, reservedTokenIds);

    std::shared_ptr<HapTokenInfoInner> tokenInfo = std::make_shared<HapTokenInfoInner>(tokenId, info, policyNew);
    HapTokenDbContext context(info.appIDDesc, policyNew, undefValues);
    ret = AddHapTokenInfoToDb(tokenInfo, context);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "AddHapTokenInfoToDb failed, errCode is %{public}d.", ret);
        AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        return ret;
    }

    AccessTokenID oriTokenID = 0;
    ret = AddHapTokenInfo(tokenInfo, oriTokenID);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "%{public}s add token info failed", info.bundleName.c_str());
        AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        return ret;
    }

    DeleteOldReservedTokens(reservedTokenIds, info.bundleName);

    if (oriTokenID != 0) {
        ReportAddHapIdChange(tokenInfo, oriTokenID);
    }

    LOGI(ATM_DOMAIN, ATM_TAG,
        "Create hap token %{public}u bundleName %{public}s user %{public}d inst %{public}d isRestore %{public}d ok",
        tokenId, tokenInfo->GetBundleName().c_str(), tokenInfo->GetUserID(), tokenInfo->GetInstIndex(), info.isRestore);
    (void)AllocAccessTokenIDEx(info, tokenId, tokenIdEx);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::AllocAccessTokenIDEx(
    const HapInfoParams& info, AccessTokenID tokenId, AccessTokenIDEx& tokenIdEx)
{
    tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    if (info.isSystemApp) {
        tokenIdEx.tokenIdExStruct.tokenAttr |= SYSTEM_APP_FLAG;
    }
    if (info.isAtomicService) {
        tokenIdEx.tokenIdExStruct.tokenAttr |= ATOMIC_SERVICE_FLAG;
    }
    if (info.appProvisionType == "debug") {
        tokenIdEx.tokenIdExStruct.tokenAttr |= DEBUG_APP_FLAG;
    }
    return RET_SUCCESS;
}

AccessTokenIDEx AccessTokenInfoManager::GetHapTokenID(
    int32_t userID, const std::string& bundleName, int32_t instIndex)
{
    std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    std::string hapUniqueKey = AccessTokenInfoUtils::GetHapUniqueStr(userID, bundleName, instIndex);
    AccessTokenIDEx tokenIdEx = {0};
    auto iter = hapTokenIdMap_.find(hapUniqueKey);
    if (iter != hapTokenIdMap_.end()) {
        AccessTokenID tokenId = iter->second;
        auto infoIter = hapTokenInfoMap_.find(tokenId);
        if (infoIter != hapTokenInfoMap_.end()) {
            if (infoIter->second == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "HapTokenInfoInner is nullptr");
                return tokenIdEx;
            }
            HapTokenInfo info = infoIter->second->GetHapInfoBasic();
            tokenIdEx.tokenIdExStruct.tokenID = info.tokenID;
            tokenIdEx.tokenIdExStruct.tokenAttr = info.tokenAttr;
        }
    }
    return tokenIdEx;
}

int32_t AccessTokenInfoManager::GetHapIdentity(const HapBaseInfo& info, Identity& identity)
{
    AccessTokenIDEx tokenIdEx = GetHapTokenID(info.userID, info.bundleName, info.instIndex);
    if (tokenIdEx.tokenIdExStruct.tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Hap info not exist, userId=%{public}d, bundleName=%{public}s, instIndex=%{public}d.",
            info.userID, info.bundleName.c_str(), info.instIndex);
        return ERR_TOKENID_NOT_EXIST;
    }

    HapTokenInfo hapInfo;
    int32_t ret = GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapInfo);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    identity.uid = hapInfo.uid;
    identity.tokenId = tokenIdEx.tokenIDEx;
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::GetHapBaseInfoByUid(int32_t uid, HapBaseInfo& info)
{
    if (uid <= 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Uid %{public}d is invalid.", uid);
        return ERR_PARAM_INVALID;
    }

    std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    for (const auto& [tokenId, hapInfoPtr] : hapTokenInfoMap_) {
        if (hapInfoPtr == nullptr) {
            continue;
        }
        HapTokenInfo hapInfo = hapInfoPtr->GetHapInfoBasic();
        if (hapInfo.uid != uid) {
            continue;
        }
        info.userID = hapInfo.userID;
        info.bundleName = hapInfo.bundleName;
        info.instIndex = hapInfo.instIndex;
        return RET_SUCCESS;
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "Uid %{public}d is not exist.", uid);
    return ERR_UID_NOT_EXIST;
}

void AccessTokenInfoManager::GetNativePermissionList(const NativeTokenInfoBase& native,
    std::vector<uint32_t>& opCodeList, std::vector<bool>& statusList)
{
    // need to process aclList
    for (const auto& state : native.permStateList) {
        uint32_t code;
        // add IsPermissionReqValid to filter invalid permission
        if (TransferPermissionToOpcode(state.permissionName, code)) {
            opCodeList.emplace_back(code);
            statusList.emplace_back(state.grantStatus == PERMISSION_GRANTED);
        }
    }
}

void AccessTokenInfoManager::InitNativeTokenInfos(const std::vector<NativeTokenInfoBase>& tokenInfos)
{
    for (const auto& info: tokenInfos) {
        AccessTokenID tokenId = info.tokenID;
        std::string process = info.processName;
        // add tokenId to cache
        ATokenTypeEnum type = TokenIDAttributes::GetTokenIdTypeEnum(tokenId);
        int32_t res = AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, type);
        if (res != RET_SUCCESS && res != ERR_TOKENID_HAS_EXISTED) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Token id register fail, res is %{public}d.", res);
            ReportSysEventServiceStartError(INIT_NATIVE_TOKENINFO_ERROR,
                "RegisterTokenId fail, " + process + std::to_string(tokenId), res);
            continue;
        }
        std::vector<uint32_t> opCodeList;
        std::vector<bool> statusList;
        GetNativePermissionList(info, opCodeList, statusList);
        // add native token info to cache
        std::unique_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
        NativeTokenInfoCache cache;
        cache.processName = process;
        cache.apl = static_cast<ATokenAplEnum>(info.apl);
        if (!PermissionKernelUtils::IsKernelSupportSpm()) {
            for (const auto& code : opCodeList) {
                cache.opCodeList.emplace_back(static_cast<uint16_t>(code));
            }
        }

        nativeTokenInfoMap_[tokenId] = cache;
        PermissionKernelUtils::AddNativePermToKernel(tokenId, opCodeList, statusList);
        LOGI(ATM_DOMAIN, ATM_TAG,
            "Init native token %{public}u process name %{public}s, permSize %{public}zu ok!",
            tokenId, process.c_str(), info.permStateList.size());
    }
}

void AccessTokenInfoManager::UpdateTokenAttr(const UpdateHapInfoParams& info, AccessTokenIDEx& tokenIdEx)
{
    if (info.isSystemApp) {
        tokenIdEx.tokenIdExStruct.tokenAttr |= SYSTEM_APP_FLAG;
    } else {
        tokenIdEx.tokenIdExStruct.tokenAttr &= ~SYSTEM_APP_FLAG;
    }
    if (info.isAtomicService) {
        tokenIdEx.tokenIdExStruct.tokenAttr |= ATOMIC_SERVICE_FLAG;
    } else {
        tokenIdEx.tokenIdExStruct.tokenAttr &= ~ATOMIC_SERVICE_FLAG;
    }
    if (info.appProvisionType == "release") {
        tokenIdEx.tokenIdExStruct.tokenAttr &= ~DEBUG_APP_FLAG;
    } else if (info.appProvisionType == "debug") {
        tokenIdEx.tokenIdExStruct.tokenAttr |= DEBUG_APP_FLAG;
    }
}

int32_t AccessTokenInfoManager::UpdateHapToken(AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info,
    const std::vector<PermissionStatus>& permStateList, const HapPolicy& hapPolicy,
    std::vector<GenericValues>& undefValues)
{
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    if (!DataValidator::IsAppIDDescValid(info.appIDDesc)) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Token %{public}u parm format error!", tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid, can not update!", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    if (infoPtr->IsRemote()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Remote hap token %{public}u can not update!", tokenID);
        return ERR_IDENTITY_CHECK_FAILED;
    }
    UpdateTokenAttr(info, tokenIdEx);

    std::vector<GenericValues> oldPermStateValues;
    std::vector<PermissionStatus> adjustedPermStateList = permStateList;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE,
        conditionValue, oldPermStateValues);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to find old permission states for token %{public}u, ret %{public}d.",
            tokenID, ret);
        return ret;
    }
    UserPolicyManager::GetInstance().UpdatePermissionStatusListForUserPolicy(
        tokenID, infoPtr->GetUserID(), adjustedPermStateList);
    {
        std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
        infoPtr->Update(info, adjustedPermStateList, hapPolicy);
    }

    HapTokenDbContext context(info.appIDDesc, hapPolicy, undefValues, oldPermStateValues, true);
    ret = AddHapTokenInfoToDb(infoPtr, context);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Add hap info %{public}u to db failed!", tokenID);
        return ret;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Token %{public}u bundle name %{public}s user %{public}d \
        inst %{public}d tokenAttr %{public}d update ok!", tokenID, infoPtr->GetBundleName().c_str(),
        infoPtr->GetUserID(), infoPtr->GetInstIndex(), infoPtr->GetHapInfoBasic().tokenAttr);

#ifdef TOKEN_SYNC_ENABLE
    TokenModifyNotifier::GetInstance().NotifyTokenModify(tokenID);
#endif
    // update hap to kernel
    std::vector<uint32_t> opCodeList;
    HapTokenInfoInner::GetGrantedPermCodeList(tokenID, opCodeList);
    (void)PermissionKernelUtils::AddHapPermToKernel(tokenID, opCodeList);
    return RET_SUCCESS;
}

#ifdef TOKEN_SYNC_ENABLE
int AccessTokenInfoManager::GetHapTokenSync(AccessTokenID tokenID, HapTokenInfoForSync& hapSync)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr || infoPtr->IsRemote()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", tokenID);
        return ERR_IDENTITY_CHECK_FAILED;
    }
    hapSync.baseInfo = infoPtr->GetHapInfoBasic();
    return infoPtr->GetPermissionStateList(hapSync.permStateList);
}

int AccessTokenInfoManager::GetHapTokenInfoFromRemote(AccessTokenID tokenID,
    HapTokenInfoForSync& hapSync)
{
    int ret = GetHapTokenSync(tokenID, hapSync);
    TokenModifyNotifier::GetInstance().AddHapTokenObservation(tokenID);
    return ret;
}

int AccessTokenInfoManager::UpdateRemoteHapTokenInfo(AccessTokenID mapID, HapTokenInfoForSync& hapSync)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoInner(mapID);
    if (infoPtr == nullptr || !infoPtr->IsRemote()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Token %{public}u is null or not remote, can not update!", mapID);
        return ERR_IDENTITY_CHECK_FAILED;
    }
    std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    infoPtr->UpdateRemoteHapTokenInfo(mapID, hapSync.baseInfo, hapSync.permStateList);
    // update remote hap to kernel
    std::vector<uint32_t> opCodeList;
    HapTokenInfoInner::GetGrantedPermCodeList(mapID, opCodeList);
    (void)PermissionKernelUtils::AddHapPermToKernel(mapID, opCodeList);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::CreateRemoteHapTokenInfo(AccessTokenID mapID, HapTokenInfoForSync& hapSync)
{
    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>(mapID, hapSync);
    hap->SetRemote(true);

    AccessTokenID oriTokenId = 0;
    int ret = AddHapTokenInfo(hap, oriTokenId);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Add local token failed, err: %{public}d.", ret);
        return ret;
    }

    HapDfxInfo dfxInfo;
    dfxInfo.sceneCode = AddHapSceneCode::MAP;
    dfxInfo.tokenId = hap->GetTokenID();
    dfxInfo.oriTokenId = oriTokenId;
    dfxInfo.userID = hap->GetUserID();
    dfxInfo.bundleName = hap->GetBundleName();
    dfxInfo.instIndex = hap->GetInstIndex();
    ReportSysEventAddHap(RET_SUCCESS, dfxInfo, false);

    return RET_SUCCESS;
}

bool AccessTokenInfoManager::IsRemoteHapTokenValid(const std::string& deviceID, const HapTokenInfoForSync& hapSync)
{
    std::string errReason;
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        errReason = "respond deviceID error";
    } else if (!DataValidator::IsUserIdValid(hapSync.baseInfo.userID)) {
        errReason = "respond userID error";
    } else if (!DataValidator::IsBundleNameValid(hapSync.baseInfo.bundleName)) {
        errReason = "respond bundleName error";
    } else if (!DataValidator::IsTokenIDValid(hapSync.baseInfo.tokenID)) {
        errReason = "respond tokenID error";
    } else if (!DataValidator::IsDlpTypeValid(hapSync.baseInfo.dlpType)) {
        errReason = "respond dlpType error";
    } else if (hapSync.baseInfo.ver != DEFAULT_TOKEN_VERSION) {
        errReason = "respond version error";
    } else if (TokenIDAttributes::GetTokenIdTypeEnum(hapSync.baseInfo.tokenID) != TOKEN_HAP) {
        errReason = "respond token type error";
    } else {
        return true;
    }

    ReportPermissionSyncEvent(TOKEN_SYNC_RESPONSE_ERROR, ConstantCommon::EncryptDevId(deviceID), errReason);
    return false;
}

int AccessTokenInfoManager::SetRemoteHapTokenInfo(const std::string& deviceID, HapTokenInfoForSync& hapSync)
{
    if (!IsRemoteHapTokenValid(deviceID, hapSync)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s parms invalid", ConstantCommon::EncryptDevId(deviceID).c_str());
        return ERR_IDENTITY_CHECK_FAILED;
    }

    AccessTokenID remoteID = hapSync.baseInfo.tokenID;
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, remoteID);
    if (mapID != 0) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Device %{public}s token %{public}u update exist remote hap token %{public}u.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID, mapID);
        // update remote token mapping id
        hapSync.baseInfo.tokenID = mapID;
        return UpdateRemoteHapTokenInfo(mapID, hapSync);
    }

    mapID = AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID);
    if (mapID == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s token %{public}u map failed.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID);
        return ERR_TOKEN_MAP_FAILED;
    }

    // update remote token mapping id
    hapSync.baseInfo.tokenID = mapID;
    int ret = CreateRemoteHapTokenInfo(mapID, hapSync);
    if (ret != RET_SUCCESS) {
        int result = AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, mapID);
        if (result != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "remove device map token id failed");
        }
        LOGI(ATM_DOMAIN, ATM_TAG, "Device %{public}s token %{public}u map to local token %{public}u failed.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID, mapID);
        return ret;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Device %{public}s token %{public}u map to local token %{public}u success.",
        ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID, mapID);
    return RET_SUCCESS;
}

int AccessTokenInfoManager::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s parms invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, tokenID);
    if (mapID == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s tokenId %{public}u is not mapped.",
            ConstantCommon::EncryptDevId(deviceID).c_str(), tokenID);
        return ERR_TOKEN_MAP_FAILED;
    }

    ATokenTypeEnum type = TokenIDAttributes::GetTokenIdTypeEnum(mapID);
    if (type == TOKEN_HAP) {
        std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
        if (hapTokenInfoMap_.count(mapID) == 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Hap token %{public}u no exist.", mapID);
            return ERR_TOKEN_INVALID;
        }
        hapTokenInfoMap_.erase(mapID);
    } else if ((type == TOKEN_NATIVE) || (type == TOKEN_SHELL)) {
        std::unique_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
        if (nativeTokenInfoMap_.count(mapID) == 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Native token %{public}u is null.", mapID);
            return ERR_TOKEN_INVALID;
        }
        nativeTokenInfoMap_.erase(mapID);
    } else {
        LOGE(ATM_DOMAIN, ATM_TAG, "Mapping tokenId %{public}u type is unknown.", mapID);
    }

    return AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, tokenID);
}

AccessTokenID AccessTokenInfoManager::GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID)
{
    if ((!DataValidator::IsDeviceIdValid(deviceID)) || (tokenID == 0) ||
        ((TokenIDAttributes::GetTokenIdTypeEnum(tokenID) != TOKEN_NATIVE) &&
        (TokenIDAttributes::GetTokenIdTypeEnum(tokenID) != TOKEN_SHELL))) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s parms invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return 0;
    }
    return AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(deviceID, tokenID);
}

int AccessTokenInfoManager::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    if (!DataValidator::IsDeviceIdValid(deviceID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s parms invalid.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    std::vector<AccessTokenID> remoteTokens;
    int ret = AccessTokenRemoteTokenManager::GetInstance().GetDeviceAllRemoteTokenID(deviceID, remoteTokens);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s have no remote token.",
            ConstantCommon::EncryptDevId(deviceID).c_str());
        return ret;
    }
    for (AccessTokenID remoteID : remoteTokens) {
        ret = DeleteRemoteToken(deviceID, remoteID);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "delete remote token failed! deviceId=%{public}s, remoteId=%{public}d.", \
                ConstantCommon::EncryptDevId(deviceID).c_str(), remoteID);
        }
    }
    return ret;
}

FullTokenID AccessTokenInfoManager::GetFullRemoteTokenId(AccessTokenID id)
{
    HapTokenInfo info;
    int32_t ret = GetHapTokenInfo(id, info);
    if (ret != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to GetHapTokenInfo, ret is %{public}d.", ret);
        return id;
    }
    AccessTokenIDEx idEx;
    idEx.tokenIdExStruct.tokenID = id;
    idEx.tokenIdExStruct.tokenAttr = info.tokenAttr;
    return idEx.tokenIDEx;
}

FullTokenID AccessTokenInfoManager::AllocLocalTokenID(const std::string& remoteDeviceID,
    AccessTokenID remoteTokenID)
{
    if (!DataValidator::IsDeviceIdValid(remoteDeviceID)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s parms invalid.",
            ConstantCommon::EncryptDevId(remoteDeviceID).c_str());
        ReportPermissionSyncEvent(
            TOKEN_SYNC_CALL_ERROR, ConstantCommon::EncryptDevId(remoteDeviceID), "deviceID error");
        return 0;
    }
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    int result = SetFirstCallerTokenID(fullTokenId); // for debug
    LOGI(ATM_DOMAIN, ATM_TAG, "Set first caller %{public}" PRIu64 "., ret is %{public}d", fullTokenId, result);

    std::string remoteUdid;
    DistributedHardware::DeviceManager::GetInstance().GetUdidByNetworkId(ACCESS_TOKEN_PACKAGE_NAME, remoteDeviceID,
        remoteUdid);
    LOGI(ATM_DOMAIN, ATM_TAG, "Device %{public}s remoteUdid.", ConstantCommon::EncryptDevId(remoteUdid).c_str());
    AccessTokenID mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(remoteUdid,
        remoteTokenID);
    if (mapID != 0) {
        return GetFullRemoteTokenId(mapID);
    }
    int ret = TokenModifyNotifier::GetInstance().GetRemoteHapTokenInfo(remoteUdid, remoteTokenID);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Device %{public}s token %{public}u sync failed",
            ConstantCommon::EncryptDevId(remoteUdid).c_str(), remoteTokenID);
        ReportPermissionSyncEvent(TOKEN_SYNC_CALL_ERROR, ConstantCommon::EncryptDevId(remoteDeviceID),
            "token sync call error, error number is " + std::to_string(ret));
        return 0;
    }

    mapID = AccessTokenRemoteTokenManager::GetInstance().GetDeviceMappingTokenID(remoteUdid, remoteTokenID);
    return GetFullRemoteTokenId(mapID);
}
#else
uint64_t AccessTokenInfoManager::AllocLocalTokenID(const std::string& remoteDeviceID,
    AccessTokenID remoteTokenID)
{
    LOGE(ATM_DOMAIN, ATM_TAG, "Tokensync is disable, check dependent components");
    return 0;
}
#endif

AccessTokenInfoManager& AccessTokenInfoManager::GetInstance()
{
    static AccessTokenInfoManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            AccessTokenInfoManager* tmp = new (std::nothrow) AccessTokenInfoManager();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

static void GeneratePermExtendValues(AccessTokenID tokenID, const std::vector<PermissionWithValue> kernelPermList,
    std::vector<GenericValues>& permExtendValues)
{
    for (auto& extendValue : kernelPermList) {
        GenericValues genericValues;
        genericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
        genericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, extendValue.permissionName);
        genericValues.Put(TokenFiledConst::FIELD_VALUE, extendValue.value);
        permExtendValues.emplace_back(genericValues);
    }
}

static void GetUserGrantPermFromDef(const std::vector<PermissionDef>& permList, AccessTokenID tokenID,
    std::vector<GenericValues>& permDefValues)
{
    for (const auto& def : permList) {
        GenericValues value;
        value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
        DataTranslator::TranslationIntoGenericValues(def, value);
        permDefValues.emplace_back(value);
    }
}

void AccessTokenInfoManager::GenerateAddInfoToVec(AtmDataType type, const std::vector<GenericValues>& addValues,
    std::vector<AddInfo>& addInfoVec)
{
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues = addValues;
    addInfoVec.emplace_back(addInfo);
}

void AccessTokenInfoManager::GenerateDelInfoToVec(AtmDataType type, const GenericValues& delValue,
    std::vector<DelInfo>& delInfoVec)
{
    DelInfo delInfo;
    delInfo.delType = type;
    delInfo.delValue = delValue;
    delInfoVec.emplace_back(delInfo);
}

int AccessTokenInfoManager::AddHapTokenInfoToDb(
    const std::shared_ptr<HapTokenInfoInner>& hapInfo, const HapTokenDbContext& context)
{
    if ((hapInfo == nullptr) || hapInfo->IsRemote()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "%{public}s", hapInfo == nullptr ? "Token info is null!" : "It is a remote hap!");
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }

    AccessTokenID tokenID = hapInfo->GetTokenID();
    bool isSystemRes = AccessTokenInfoUtils::IsSystemResource(hapInfo->GetBundleName());

    std::vector<AddInfo> addInfoVec;
    std::vector<GenericValues> undefValues = context.undefValues;
    AddTokenIdToUndefValues(tokenID, undefValues);
    GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, undefValues, addInfoVec);

    std::vector<GenericValues> hapInfoValues;
    hapInfo->GenerateHapInfoValues(context.appId, context.policy.apl, hapInfoValues);
    GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, hapInfoValues, addInfoVec);

    std::vector<GenericValues> permStateValues;
    hapInfo->GeneratePermStateValues(context.oldPermStateValues, permStateValues);
    ClearNonPersistedUserPolicyFlags(permStateValues);
    GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, permStateValues, addInfoVec);

    std::vector<PermissionWithValue> extendedPermList;
    PermissionDataBrief::GetInstance().GetExtendedValueList(tokenID, extendedPermList);
    std::vector<GenericValues> permExtendValues;
    GeneratePermExtendValues(tokenID, extendedPermList, permExtendValues);
    AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE,
        permExtendValues, addInfoVec);

    if (isSystemRes) {
        std::vector<GenericValues> permDefValues;
        GetUserGrantPermFromDef(context.policy.permList, tokenID, permDefValues);
        GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, permDefValues, addInfoVec);
    }

    std::vector<DelInfo> delInfoVec;
    GenericValues delValue;
    delValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    if (context.isUpdate) {
        for (auto const& addInfo : addInfoVec) {
            AccessTokenInfoUtils::GenerateDelInfoToVec(addInfo.addType, delValue, delInfoVec);
        }
    }

    return AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
}

int32_t AccessTokenInfoManager::GetHapAppIdByTokenId(AccessTokenID tokenID, std::string& appId)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    std::vector<GenericValues> hapTokenResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, hapTokenResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Failed to find Id(%{public}u) from hap_token_table, err: %{public}d.", tokenID, ret);
        return ret;
    }

    if (hapTokenResults.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id(%{public}u) is not in hap_token_table.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    std::string result = hapTokenResults[0].GetString(TokenFiledConst::FIELD_APP_ID);
    if (!DataValidator::IsAppIDDescValid(result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID: 0x%{public}x appID is error.", tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    appId = result;
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::FillInstallPolicyWithoutHaps(
    const std::string& bundleName, const BundlePolicy& bundlePolicy, BundleParam& param, HapPolicy& policy)
{
    std::shared_ptr<BundleInfoInner> bundleInfo = nullptr;
    std::shared_ptr<HapTokenInfoInner> baseHapInfo = nullptr;
    AccessTokenID baseTokenId = INVALID_TOKENID;
    {
        std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
        auto bundleIter = bundleInfoMap_.find(bundleName);
        if (bundleIter == bundleInfoMap_.end() || bundleIter->second == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Bundle info of %{public}s does not exist.", bundleName.c_str());
            return ERR_BUNDLE_NOT_EXIST;
        }
        bundleInfo = bundleIter->second;

        for (const auto tokenId : bundleInfo->tokenIds) {
            auto hapIter = hapTokenInfoMap_.find(tokenId);
            if (hapIter == hapTokenInfoMap_.end() || hapIter->second == nullptr || hapIter->second->IsRemote()) {
                continue;
            }
            if (hapIter->second->GetInstIndex() != 0) {
                continue;
            }
            baseTokenId = tokenId;
            baseHapInfo = hapIter->second;
            break;
        }
    }
    if (baseTokenId == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId with index = 0 not found.");
        return ERR_TOKENID_NOT_EXIST;
    }

    BundleNoCachedInfo noCached;
    std::vector<PermissionWithValue> extendedPermList;
    int32_t ret = PermissionKernelUtils::GetBundleInfoFromKernel(baseTokenId, noCached, extendedPermList);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get kernel bundle info failed, tokenId=%{public}u, ret=%{public}d.",
            baseTokenId, ret);
        return ret;
    }
    std::vector<BriefPermData> briefPermDataList;
    bool isFixed = false;
    policy = HapPolicy();
    policy.apl = noCached.apl;
    policy.preAuthorizationInfo = bundlePolicy.preAuthorizationInfo;
    policy.isDebugGrant = bundlePolicy.isDebugGrant;
    PermissionConstraintCheck::FixBriefPermData(*bundleInfo, bundlePolicy.dlpType, briefPermDataList, isFixed);

    HapTokenInfo hapInfo;
    baseHapInfo->TranslateToHapTokenInfo(hapInfo);

    param = BundleParam();
    param.bundleName = bundleName;
    param.appIdentifier = noCached.ownerid;
    param.apiVersion = hapInfo.apiVersion;
    param.distributionType = noCached.distributionType;
    param.isSystem = AccessTokenInfoUtils::CheckSpecifiedFlag(hapInfo.tokenAttr, SYSTEM_APP_FLAG);
    param.isAtomicService = AccessTokenInfoUtils::CheckSpecifiedFlag(hapInfo.tokenAttr, ATOMIC_SERVICE_FLAG);
    param.isDebug = AccessTokenInfoUtils::CheckSpecifiedFlag(hapInfo.tokenAttr, DEBUG_APP_FLAG);
    param.idType = noCached.idType;

    policy.permStateList.reserve(briefPermDataList.size());
    for (const auto& briefPermData : briefPermDataList) {
        policy.permStateList.emplace_back(BuildPermissionStatusFromBrief(briefPermData));
    }
    for (const auto& extendedPerm : extendedPermList) {
        policy.aclExtendedMap[extendedPerm.permissionName] = extendedPerm.value;
    }
    return RET_SUCCESS;
}

AccessTokenID AccessTokenInfoManager::GetNativeTokenId(const std::string& processName)
{
    AccessTokenID tokenID = INVALID_TOKENID;
    std::shared_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
    for (auto iter = nativeTokenInfoMap_.begin(); iter != nativeTokenInfoMap_.end(); ++iter) {
        if (iter->second.processName == processName) {
            tokenID = iter->first;
            break;
        }
    }
    return tokenID;
}

void AccessTokenInfoManager::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    if (ClearUserGrantedPermission(tokenID) != RET_SUCCESS) {
        return;
    }
    std::vector<AccessTokenID> tokenIdList;
    GetRelatedSandBoxHapList(tokenID, tokenIdList);
    for (const auto& id : tokenIdList) {
        (void)ClearUserGrantedPermission(id);
    }
    // DFX
    ReportClearUserPermStateEvent(tokenID, static_cast<uint32_t>(tokenIdList.size()));
}

int32_t AccessTokenInfoManager::ClearUserGrantedPermission(AccessTokenID id)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(id);
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", id);
        return ERR_PARAM_INVALID;
    }
    if (infoPtr->IsRemote()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "It is a remote hap token %{public}u!", id);
        return ERR_IDENTITY_CHECK_FAILED;
    }
    std::vector<std::string> grantedPermListBefore;
    HapTokenInfoInner::GetGrantedPermList(id, grantedPermListBefore);

    // reset permission.
    int32_t ret = infoPtr->ResetUserGrantPermissionStatus();
    if (ret != RET_SUCCESS) {
        return ret;
    }

    std::vector<uint32_t> opCodeList;
    HapTokenInfoInner::GetGrantedPermCodeList(id, opCodeList);
    (void)PermissionKernelUtils::AddHapPermToKernel(id, opCodeList);
    std::vector<std::string> grantedPermListAfter;
    for (auto opCode: opCodeList) {
        grantedPermListAfter.emplace_back(TransferOpcodeToPermission(opCode));
    }
    LOGI(ATM_DOMAIN, ATM_TAG,
        "grantedPermListBefore size %{public}zu, grantedPermListAfter size %{public}zu!",
        grantedPermListBefore.size(), grantedPermListAfter.size());
    PermissionManager::GetInstance().NotifyUpdatedPermList(grantedPermListBefore, grantedPermListAfter, id);
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::UpdateRestrictedFlag(
    AccessTokenID tokenId, uint32_t permCode, bool isRestricted, bool isPersist, bool& hasFlagChanged)
{
    hasFlagChanged = false;
    PermissionDataBrief::PermissionStatusChangeType changeType =
        PermissionDataBrief::PermissionStatusChangeType::NO_CHANGE;
    int32_t ret = PermissionDataBrief::GetInstance().UpdatePermissionFlag(
        tokenId, permCode, PERMISSION_RESTRICTED_BY_ADMIN, isRestricted, changeType);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    hasFlagChanged = (changeType != PermissionDataBrief::PermissionStatusChangeType::NO_CHANGE);
    if (!hasFlagChanged || !isPersist) {
        return RET_SUCCESS;
    }

    ret = UpdateRestrictedFlagToDb(tokenId, permCode);
    if (ret != RET_SUCCESS) {
        RollbackRestrictedFlag(tokenId, permCode, isRestricted);
    }
    return ret;
}

int32_t AccessTokenInfoManager::UpdateRestrictedFlagToDb(AccessTokenID tokenId, uint32_t permCode)
{
    std::string permissionName = TransferOpcodeToPermission(permCode);
    std::vector<GenericValues> permStateValues;
    int32_t ret = PermissionDataBrief::GetInstance().BuildPermissionStateValues(tokenId, {}, permStateValues);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build permission state failed, id=%{public}u, permCode=%{public}u, ret=%{public}d.",
            tokenId, permCode, ret);
        return ret;
    }
    bool hasUpdatedTargetPermState = false;
    for (const auto& permStateValue : permStateValues) {
        if (permStateValue.GetString(TokenFiledConst::FIELD_PERMISSION_NAME) != permissionName) {
            continue;
        }
        GenericValues conditionValue;
        conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        conditionValue.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
        ret = AccessTokenDbOperator::Modify(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, permStateValue, conditionValue);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Modify permission state failed, tokenId=%{public}u, permission=%{public}s, ret=%{public}d.",
                tokenId, permissionName.c_str(), ret);
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }
        hasUpdatedTargetPermState = true;
        break;
    }
    if (!hasUpdatedTargetPermState) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission %{public}s not found when update restricted flag db, tokenId=%{public}u.",
            permissionName.c_str(), tokenId);
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::UpdateRestrictedFlagAndRefreshKernel(
    AccessTokenID tokenId, uint32_t permCode, bool isRestricted, bool isPersist, const char* source)
{
    int32_t originalStatus = PERMISSION_DENIED;
    uint32_t originalFlag = 0;
    int32_t ret = PermissionDataBrief::GetInstance().QueryStoredPermissionStatusAndFlag(
        tokenId, permCode, originalStatus, originalFlag);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    bool isFlagChanged = false;
    ret = UpdateRestrictedFlag(tokenId, permCode, isRestricted, isPersist, isFlagChanged);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    std::string permissionName = TransferOpcodeToPermission(permCode);
    bool kernelStatusBefore =
        ((originalFlag & PERMISSION_RESTRICTED_BY_ADMIN) == 0) && (originalStatus == PERMISSION_GRANTED);
    bool kernelStatusAfter = !isRestricted && (originalStatus == PERMISSION_GRANTED);
    if (isFlagChanged) {
        PermissionChangeNotifier::GetInstance().ParamFlagUpdate();
    }
    if (kernelStatusBefore != kernelStatusAfter) {
        PermissionKernelUtils::SetPermToKernel(tokenId, permissionName, kernelStatusAfter);
        int32_t changeType = kernelStatusAfter ? STATE_CHANGE_GRANTED : STATE_CHANGE_REVOKED;
        CallbackManager::GetInstance().ExecuteCallbackAsync(tokenId, permissionName, changeType);
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Perm %{public}s refreshed by %{public}s, isAllowed %{public}d.",
        permissionName.c_str(), source, kernelStatusAfter);
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::RefreshUserPolicyFlagForUser(int32_t userId, const UserPolicyChange& policy,
    std::vector<UserPolicyRefreshSnapshot>& appliedSnapshots)
{
    std::unordered_set<AccessTokenID> hapTokenIdSet;
    GetTokenIDByUserID(userId, -1, hapTokenIdSet);
    for (const auto tokenId : hapTokenIdSet) {
        bool isRestricted = UserPolicyManager::GetInstance().IsPermissionRestricted(tokenId, userId, policy.permCode);
        int32_t originalStatus = PERMISSION_DENIED;
        uint32_t originalFlag = 0;
        int32_t ret = PermissionDataBrief::GetInstance().QueryStoredPermissionStatusAndFlag(
            tokenId, policy.permCode, originalStatus, originalFlag);
        if (ret == AccessTokenError::ERR_PERMISSION_NOT_EXIST) {
            continue;
        }
        if (ret != RET_SUCCESS) {
            return ret;
        }
        ret = UpdateRestrictedFlagAndRefreshKernel(
            tokenId, policy.permCode, isRestricted, policy.isPersist, "user policy");
        if (ret == AccessTokenError::ERR_PERMISSION_NOT_EXIST) {
            continue;
        }
        if (ret != RET_SUCCESS) {
            return ret;
        }
        appliedSnapshots.emplace_back(UserPolicyRefreshSnapshot {
            .target = UserPolicyRefreshTarget::HAP,
            .tokenId = tokenId,
            .permCode = policy.permCode,
            .originalStatus = originalStatus,
            .originalFlag = originalFlag
        });
    }
    return RET_SUCCESS;
}

void AccessTokenInfoManager::RollbackUserPolicyFlag(const std::vector<UserPolicyRefreshSnapshot>& appliedSnapshots)
{
    for (auto iter = appliedSnapshots.rbegin(); iter != appliedSnapshots.rend(); ++iter) {
        if (iter->target != UserPolicyRefreshTarget::HAP) {
            continue;
        }
        int32_t ret = RestoreRestrictedFlag(iter->tokenId, iter->permCode, iter->originalFlag);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Rollback restricted flag failed, tokenId=%{public}u, permCode=%{public}u, ret=%{public}d.",
                iter->tokenId, iter->permCode, ret);
            continue;
        }
        ret = UpdateRestrictedFlagToDb(iter->tokenId, iter->permCode);
        if (ret != RET_SUCCESS && ret != AccessTokenError::ERR_PERMISSION_NOT_EXIST) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Rollback restricted flag db failed, tokenId=%{public}u, permCode=%{public}u, ret=%{public}d.",
                iter->tokenId, iter->permCode, ret);
        }
        RestoreKernelPermissionState(iter->tokenId, iter->permCode, iter->originalStatus, iter->originalFlag);
    }
}

int32_t AccessTokenInfoManager::RefreshUserPolicyFlag(const std::vector<UserPolicyChange>& changedPolicyList,
    std::vector<UserPolicyRefreshSnapshot>& appliedSnapshots)
{
    for (const auto& policy : changedPolicyList) {
        for (const auto& userId : policy.changedUserList) {
            int32_t ret = RefreshUserPolicyFlagForUser(userId, policy, appliedSnapshots);
            if (ret != RET_SUCCESS) {
                return ret;
            }
        }
    }
    return RET_SUCCESS;
}

void AccessTokenInfoManager::GetRelatedSandBoxHapList(AccessTokenID tokenId, std::vector<AccessTokenID>& tokenIdList)
{
    std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);

    auto infoIter = hapTokenInfoMap_.find(tokenId);
    if (infoIter == hapTokenInfoMap_.end()) {
        return;
    }
    if (infoIter->second == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "HapTokenInfoInner is nullptr.");
        return;
    }
    std::string bundleName = infoIter->second->GetBundleName();
    int32_t userID = infoIter->second->GetUserID();
    int32_t index = infoIter->second->GetInstIndex();
    int32_t dlpType = infoIter->second->GetDlpType();
    // the permissions of a common application whose index is not equal 0 are managed independently.
    if ((dlpType == DLP_COMMON) && (index != 0)) {
        return;
    }

    for (auto iter = hapTokenInfoMap_.begin(); iter != hapTokenInfoMap_.end(); ++iter) {
        if (iter->second == nullptr) {
            continue;
        }
        if ((bundleName == iter->second->GetBundleName()) && (userID == iter->second->GetUserID()) &&
            (tokenId != iter->second->GetTokenID())) {
            if ((iter->second->GetDlpType() == DLP_COMMON) && (iter->second->GetInstIndex() != 0)) {
                continue;
            }
            tokenIdList.emplace_back(iter->second->GetTokenID());
        }
    }
}

int32_t AccessTokenInfoManager::SetPermDialogCap(AccessTokenID tokenID, bool enable)
{
    std::unique_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    auto infoIter = hapTokenInfoMap_.find(tokenID);
    if ((infoIter == hapTokenInfoMap_.end()) || (infoIter->second == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id %{publid}u is not exits.", tokenID);
        return ERR_TOKENID_NOT_EXIST;
    }
    infoIter->second->SetPermDialogForbidden(enable);

    if (!UpdateCapStateToDatabase(tokenID, enable)) {
        return RET_FAILED;
    }

    return RET_SUCCESS;
}


bool AccessTokenInfoManager::GetPermDialogCap(AccessTokenID tokenID)
{
    if (tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid tokenId.");
        return true;
    }
    std::shared_lock<std::shared_mutex> infoGuard(this->hapTokenInfoLock_);
    auto infoIter = hapTokenInfoMap_.find(tokenID);
    if ((infoIter == hapTokenInfoMap_.end()) || (infoIter->second == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenId is not exist in map.");
        return true;
    }
    return infoIter->second->IsPermDialogForbidden();
}

bool AccessTokenInfoManager::UpdateCapStateToDatabase(AccessTokenID tokenID, bool enable)
{
    GenericValues modifyValue;
    modifyValue.Put(TokenFiledConst::FIELD_FORBID_PERM_DIALOG, enable);

    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));

    int32_t res = AccessTokenDbOperator::Modify(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, modifyValue, conditionValue);
    if (res != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Update tokenID %{public}u permissionDialogForbidden %{public}d to database failed", tokenID, enable);
        return false;
    }

    return true;
}

static bool IsCallerNormalApp(uint64_t fulltokenID)
{
    ATokenTypeEnum tokenType =
        TokenIDAttributes::GetTokenIdTypeEnum(static_cast<AccessTokenID>(fulltokenID & TOKEN_ID_LOWMASK));
    if (tokenType != TOKEN_HAP) {
        return false;
    }
    return !TokenIDAttributes::IsSystemApp(fulltokenID);
}

static bool GetPermissionFromKernelCache(AccessTokenID tokenID, const std::string& permissionName, int32_t& res)
{
    uint32_t code = 0;
    if (!IsDefinedPermissionInner(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission=%{public}s is not defined.", permissionName.c_str());
        res = PERMISSION_DENIED;
        return true;
    }
    (void)TransferPermissionToOpcode(permissionName, code);

    bool isGranted = false;
    if (GetPermissionFromKernel(tokenID, static_cast<int32_t>(code), isGranted) != RET_SUCCESS) {
        return false;
    }
    res = isGranted ? PERMISSION_GRANTED : PERMISSION_DENIED;
    return true;
}

int AccessTokenInfoManager::VerifyNativeAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    if (!IsDefinedPermissionInner(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "No definition for permission: %{public}s!", permissionName.c_str());
        return PERMISSION_DENIED;
    }
    uint32_t code;
    if (!TransferPermissionToOpcode(permissionName, code)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid perm(%{public}s)", permissionName.c_str());
        return PERMISSION_DENIED;
    }

    std::shared_lock<std::shared_mutex> infoGuard(this->nativeTokenInfoLock_);
    auto iter = nativeTokenInfoMap_.find(tokenID);
    if (iter == nativeTokenInfoMap_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Id %{public}u is not exist.", tokenID);
        return PERMISSION_DENIED;
    }
    if (!PermissionKernelUtils::IsKernelSupportSpm()) {
        NativeTokenInfoCache cache = iter->second;
        for (size_t i = 0; i < cache.opCodeList.size(); ++i) {
            if (code == static_cast<uint32_t>(cache.opCodeList[i])) {
                return PERMISSION_GRANTED;
            }
        }
    }

    return PERMISSION_DENIED;
}

int32_t AccessTokenInfoManager::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    if (tokenID == INVALID_TOKENID) {
        ReportPermissionCheckEvent(VERIFY_TOKEN_ID_ERROR, "TokenID is invalid, permission: " + permissionName);
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid");
        return PERMISSION_DENIED;
    }

    if (!PermissionValidator::IsPermissionNameValid(permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "%{public}s of %{public}u is invalid!", permissionName.c_str(), tokenID);
        return PERMISSION_DENIED;
    }
    uint64_t callerFullTokenID = IPCSkeleton::GetCallingFullTokenID();
    AccessTokenID callertokenID = static_cast<AccessTokenID>(callerFullTokenID & TOKEN_ID_LOWMASK);
    bool isCallerNormalApp = IsCallerNormalApp(callerFullTokenID);
    ATokenTypeEnum tokenType = AccessTokenIDManager::GetInstance().GetTokenIdType(tokenID);
    if (isCallerNormalApp && tokenID != callertokenID) {
        std::shared_lock<std::shared_mutex> monitorLock(this->monitorLock_);
        tokenMonitor_->ReportExceptionalAccessTokenUsage();
        if (tokenType == ATokenTypeEnum::TOKEN_INVALID) {
            // record
            std::shared_ptr<HapTokenInfoInner> hap = GetHapTokenInfoInner(callertokenID);
            if (hap == nullptr) {
                LOGE(ATM_DOMAIN, ATM_TAG, "TokenID(%{public}u) not exist!", callertokenID);
                return PERMISSION_DENIED;
            }
            tokenMonitor_->RecordExceptionalBehavior(hap->GetHapInfoBasic(), tokenID, permissionName);
            return PERMISSION_DENIED;
        }
        if (tokenMonitor_->IsInPunishingTime(callertokenID)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TokenID(%{public}u) is in punishing time!", callertokenID);
            return PERMISSION_DENIED;
        }
    }
    int32_t res = PERMISSION_DENIED;
    if (GetPermissionFromKernelCache(tokenID, permissionName, res)) {
        return res;
    }
    if ((tokenType == TOKEN_NATIVE) || (tokenType == TOKEN_SHELL)) {
        return VerifyNativeAccessToken(tokenID, permissionName);
    }
    if (tokenType == TOKEN_HAP) {
        return HapTokenInfoInner::VerifyPermissionStatus(tokenID, permissionName);
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d, invalid tokenType!", tokenID);
    return PERMISSION_DENIED;
}

bool AccessTokenInfoManager::GetApiVersionByTokenId(AccessTokenID tokenID, int32_t& apiVersion)
{
    AccessTokenIDInner* idInner = reinterpret_cast<AccessTokenIDInner*>(&tokenID);
    ATokenTypeEnum tokenType = static_cast<ATokenTypeEnum>(idInner->type);
    if (tokenType != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid token type %{public}d", tokenType);
        return false;
    }

    HapTokenInfo hapInfo;
    int32_t ret = GetHapTokenInfo(tokenID, hapInfo);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get hap token info error!");
        return false;
    }

    apiVersion = hapInfo.apiVersion;
    return true;
}

int32_t AccessTokenInfoManager::GetKernelPermissions(
    AccessTokenID tokenId, std::vector<PermissionWithValue>& kernelPermList)
{
    return PermissionDataBrief::GetInstance().GetKernelPermissions(tokenId, kernelPermList);
}

int32_t AccessTokenInfoManager::QueryStatusByPermission(const std::vector<uint32_t>& permCodeList,
    std::vector<PermissionStatusIdl>& permissionInfoList, bool onlyHap)
{
    permissionInfoList.clear();

    std::unordered_map<std::string, uint32_t> permissionNameToCodeMap;
    std::vector<GenericValues> permStateResults;
    int32_t ret = FindPermissionByNameFromDb(permCodeList, permissionNameToCodeMap, permStateResults);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    permissionInfoList.reserve(permStateResults.size());
    for (const auto& stateValue : permStateResults) {
        const auto tokenID = static_cast<AccessTokenID>(stateValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
        const std::string permissionName = stateValue.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        const auto permIter = permissionNameToCodeMap.find(permissionName);

        int32_t status = PERMISSION_DENIED;
        uint32_t flag = 0;
        (void)PermissionDataBrief::GetInstance().QueryEffectivePermissionStatusAndFlag(
            tokenID, permIter->second, status, flag);

        PermissionStatusIdl idl;
        idl.tokenID = tokenID;
        idl.permCode = permIter->second;
        idl.grantStatus = status;
        idl.grantFlag = flag;
        idl.timestamp = GetPermissionTimestamp(stateValue);
        permissionInfoList.emplace_back(idl);
    }

    if (!onlyHap) {
        GetAllNativeTokenPerms(permCodeList, permissionInfoList);
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "End result size: %{public}zu", permissionInfoList.size());
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::QueryStatusByTokenID(const std::vector<AccessTokenID>& tokenIDList,
    std::vector<PermissionStatusIdl>& permissionInfoList)
{
    permissionInfoList.clear();
    std::vector<GenericValues> permStateResults;
    int32_t ret = FindPermissionByTokenIdFromDb(tokenIDList, permStateResults);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    permissionInfoList.reserve(permStateResults.size());
    for (const auto& stateValue : permStateResults) {
        const auto tokenID = static_cast<AccessTokenID>(stateValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
        const std::string permissionName = stateValue.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        uint32_t permCode = 0;
        if (!TransferPermissionToOpcode(permissionName, permCode)) {
            continue;
        }

        int32_t status = PERMISSION_DENIED;
        uint32_t flag = 0;
        (void)PermissionDataBrief::GetInstance().QueryEffectivePermissionStatusAndFlag(
            tokenID, permCode, status, flag);

        PermissionStatusIdl idl;
        idl.tokenID = tokenID;
        idl.permCode = permCode;
        idl.grantStatus = status;
        idl.grantFlag = flag;
        idl.timestamp = GetPermissionTimestamp(stateValue);
        permissionInfoList.emplace_back(idl);
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "QueryPermissionInfosByTokenID result: %{public}zu",
        permissionInfoList.size());
    return RET_SUCCESS;
}

int32_t AccessTokenInfoManager::GetReqPermissionByName(
    AccessTokenID tokenId, const std::string& permissionName, std::string& value)
{
    return PermissionDataBrief::GetInstance().GetReqPermissionByName(
        tokenId, permissionName, value, true);
}

size_t AccessTokenInfoManager::GetMaxQueryResultSize() const
{
    return maxQueryResultSize_;
}

#ifdef ATM_TEST_ENABLE
void AccessTokenInfoManager::SetMaxQueryResultSize(size_t maxSize)
{
    maxQueryResultSize_ = maxSize;
}
#endif

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
