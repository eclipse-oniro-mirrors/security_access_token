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

#include "install_session_manager.h"

#include <iostream>
#include <numeric>
#include <sstream>

#include "access_token.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_utils.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_common_log.h"
#include "app_manager_access_client.h"
#include "callback_manager.h"
#include "constant_common.h"
#include "data_translator.h"
#ifdef SUPPORT_SANDBOX_APP
#include "dlp_permission_set_manager.h"
#endif
#include "hap_data_structure.h"
#include "hap_sign_verify_manager.h"
#include "hisysevent_adapter.h"
#include "iaccess_token_manager.h"
#include "ipc_skeleton.h"
#include "parameter.h"
#include "parameters.h"
#include "permission_feature_manager.h"
#include "permission_manager.h"
#include "permission_map.h"
#include "permission_validator.h"
#include "perm_setproc.h"
#include "spm_data_kernel_common.h"
#include "table_item.h"
#include "time_util.h"
#include "tokenid_attributes.h"
#include "token_field_const.h"
#include "user_policy_manager.h"
#include "install_session_proxy_death_param.h"
#include "ipc_skeleton.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_modify_notifier.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int64_t ONE_HOUR_MS = 3600000;
const uint32_t IS_KERNEL_EFFECT = (0x1 << 0);
const uint32_t HAS_VALUE = (0x1 << 1);
static const uint32_t SYSTEM_APP_FLAG = 0x0001;
static const uint32_t ATOMIC_SERVICE_FLAG = 0x0002;
static const uint32_t DEBUG_APP_FLAG = 0x0008;
}
InstallSessionManager* InstallSessionManager::implInstance_ = nullptr;
std::mutex InstallSessionManager::mutex_;

InstallSessionManager& InstallSessionManager::GetInstance()
{
    if (implInstance_ == nullptr) {
        std::lock_guard<std::mutex> lock_l(mutex_);
        if (implInstance_ == nullptr) {
            implInstance_ = new InstallSessionManager();
        }
    }
    return *implInstance_;
}

InstallSessionManager::InstallSessionManager()
{}

InstallSessionManager::~InstallSessionManager()
{}

int32_t InstallSessionManager::CheckPermissionList(InstallCache& cache, HapInfoCheckResult& result)
{
    if (cache.bundleInfos.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "bundleInfos is empty");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    std::vector<PermissionStatus> initializedList;
    if (!PermissionManager::GetInstance().InitPermissionList(
        cache.bundleParam, cache.policy, initializedList, result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "CheckPermissionList failed.");
        return AccessTokenError::ERR_CHECK_ACL_OR_EDM_FAILED;
    }

    cache.policy.permStateList = initializedList;
    return RET_SUCCESS;
}

void InstallSessionManager::InitPermissionList(const BundleParam& bundleParam, HapPolicy& policy)
{
    std::vector<PermissionStatus> initializedList;
    HapInfoCheckResult result;
    (void)PermissionManager::GetInstance().InitPermissionList(bundleParam, policy, initializedList, result);
    policy.permStateList = initializedList;
}

bool InstallSessionManager::NoNeedPermissionInheritance(
    const BundleParam& bundleParam, const HapPolicy& policy, AccessTokenAttr oldAttr)
{
    return (bundleParam.isDebug && policy.isDebugGrant) || (!bundleParam.isDebug && (oldAttr & DEBUG_APP_FLAG));
}

void InstallSessionManager::MergePermission(std::vector<BriefPermData>& permBriefDataList,
    const std::vector<BriefPermData>& oldPermBriefDataList, bool noNeedPermissionInheritance)
{
    for (auto& newPerm : permBriefDataList) {
        auto iter = std::find_if(oldPermBriefDataList.begin(), oldPermBriefDataList.end(),
            [newPerm](const BriefPermData& oldPermData) {
                return newPerm.permCode == oldPermData.permCode;
            });
        if (iter != oldPermBriefDataList.end()) {
            if (noNeedPermissionInheritance &&
                (iter->flag & PERMISSION_FIXED_BY_ADMIN_POLICY) == 0 &&
                (iter->flag & PERMISSION_RESTRICTED_BY_ADMIN) == 0) {
                continue;
            }
            PermissionDataBrief::GetInstance().UpdatePermStatus(*iter, newPerm);
        }
    }
}

int32_t InstallSessionManager::GetHapPathFromDb(std::string bundleName,
    std::vector<std::string>& paths, std::vector<std::vector<uint8_t>>& persistDatas)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    std::vector<GenericValues> hapTokenResults;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, conditionValue, hapTokenResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Db find failed, ret=%{public}d", ret);
        return ERR_DATABASE_OPERATE_FAILED;
    }

    for (const auto& tokenValue : hapTokenResults) {
        std::string moduleName = tokenValue.GetString(TokenFiledConst::FIELD_MODULE_NAME);
        paths.emplace_back(tokenValue.GetString(TokenFiledConst::FIELD_PATH));
        persistDatas.emplace_back(tokenValue.GetBlob(TokenFiledConst::FIELD_PERSIST_DATA));
    }

    return RET_SUCCESS;
}

int32_t InstallSessionManager::RebuildHapPolicy(InstallCache& cache, const std::vector<std::string>& paths,
    std::vector<std::vector<uint8_t>>& persistDatas)
{
    std::vector<TrustedBundleInfoInner> bundleInfos;
    int32_t ret = FastVerify(paths, persistDatas, bundleInfos, cache.list.userId);
    if (ret != ERR_OK) {
        return ret;
    }

    for (size_t i = 0; i < paths.size() && i < bundleInfos.size(); i++) {
        bool needAdd = true;
        for (auto& info : cache.bundleInfos) {
            if (bundleInfos[i].GetModuleName() == info.GetModuleName()) {
                needAdd = false;
                break;
            }
        }
        if (needAdd) {
            cache.bundleInfos.emplace_back(bundleInfos[i]);
            cache.additionalPaths.emplace_back(paths[i]);
        }
    }

    cache.policy = HapPolicy();
    cache.bundleParam = BundleParam();

    ret = HapSignVerifyManager::GetInstance().CheckMultipleHaps(cache.bundleInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "CheckMultipleHaps failed ret=%{public}d", ret);
        return ERR_CHECK_MULTIPLE_HAP_FAILED;
    }
    ret = HapSignVerifyManager::GetInstance().BuildHapPolicy(cache.bundleInfos, cache.policy, cache.bundleParam);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "BuildHapPolicy failed ret=%{public}d", ret);
        return ERR_BUILD_POLICY_FAILED;
    }
    return ERR_OK;
}

void InstallSessionManager::ClearTimeoutData()
{
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        int64_t timeStamp = TimeUtil::GetCurrentTimestamp();
        for (auto it = sessionToTimestamp.begin(); it != sessionToTimestamp.end();) {
            if (timeStamp - it->second > ONE_HOUR_MS) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Install session %{public}d overtime", it->first);
                sessionToInstallCache.erase(it->first);
                it = sessionToTimestamp.erase(it);
            } else {
                ++it;
            }
        }
    }
}

AccessTokenAttr GetTokenAttr(const BundleParam& param)
{
    AccessTokenAttr attr = 0;
    if (param.isSystem) {
        attr |= SYSTEM_APP_FLAG;
    }
    if (param.isAtomicService) {
        attr |= ATOMIC_SERVICE_FLAG;
    }
    if (param.isDebug) {
        attr |= DEBUG_APP_FLAG;
    }
    return attr;
}

int32_t InstallSessionManager::CreateTokenIdAndUid(InstallCache& cache, const BundlePolicy& bundlePolicy,
    int32_t bundleId)
{
    int32_t dlpFlag = (bundlePolicy.dlpType > DLP_COMMON) ? 1 : 0;
    int32_t cloneFlag = ((dlpFlag == 0) && (cache.baseInfo.instIndex) > 0) ? 1 : 0;
    AccessTokenID tokenId = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(
        TOKEN_HAP, dlpFlag, cloneFlag, 0);
    if (tokenId == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token Id create failed");
        return ERR_TOKENID_CREATE_FAILED;
    }

    AccessTokenIDEx tokenIdEx;
    tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    tokenIdEx.tokenIdExStruct.tokenAttr = GetTokenAttr(cache.bundleParam);
    cache.identity.tokenId = tokenIdEx.tokenIDEx;

    if (bundleId != -1) {
        cache.identity.uid = 0;
        AccessTokenIDManager::GetInstance().TranslateUid(bundleId, cache.baseInfo.userID, cache.identity.uid);
    } else {
        int32_t ret = AccessTokenIDManager::GetInstance().AllocUid(cache.baseInfo.userID, cache.identity.uid);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Uid create failed, ret=%{public}d", ret);
            AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
            return ERR_UID_CREATE_FAILED;
        }
    }
    return RET_SUCCESS;
}

int32_t InstallSessionManager::HandleReservedToken(
    InstallCache& cache, AccessTokenID tokenId, int32_t uid, int32_t oldAttr)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Reserved is 2, reserved_data tokenId=%{public}u, uid=%{public}d", tokenId, uid);
    AccessTokenIDEx tokenIdEx;
    tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    tokenIdEx.tokenIdExStruct.tokenAttr = GetTokenAttr(cache.bundleParam);
    cache.identity.tokenId = tokenIdEx.tokenIDEx;
    cache.identity.uid = uid;
    cache.isNewBundleId = false;
    cache.reserved = static_cast<int32_t>(ReservedType::RESERVED_DATA);
    cache.oldTokenId = tokenId;
    cache.oldAttr = oldAttr;
    (void)AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(tokenId, TokenIdStatus::ACTIVE);
    return RET_SUCCESS;
}

int32_t InstallSessionManager::DeleteFromDbByTokenId(AccessTokenID tokenID)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Find in db but not exist in IDManager, delete token %{public}u", tokenID);
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));

    std::vector<DelInfo> delInfoVec;
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, delInfoVec);
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition, delInfoVec);
    AccessTokenInfoUtils::GenerateDelInfoToVec(
        AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, condition, delInfoVec);
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, condition, delInfoVec);

    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, {});
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to delete token %{public}u from db, ret=%{public}d.", tokenID, ret);
    }
    return ret;
}

int32_t InstallSessionManager::MatchBaseInfo(
    InstallCache& cache, int32_t reserved, AccessTokenID tokenId, int32_t uid, int32_t oldAttr)
{
    if (reserved == static_cast<int32_t>(ReservedType::RESERVED_DATA)) {
        return HandleReservedToken(cache, tokenId, uid, oldAttr);
    } else if (reserved == static_cast<int32_t>(ReservedType::RESERVED_IDENTITY)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Reserved is 1");
        cache.reserved = static_cast<int32_t>(ReservedType::RESERVED_IDENTITY);
        cache.oldTokenId = tokenId;
    } else if (reserved == static_cast<int32_t>(ReservedType::NONE)) {
        if (AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP) != ERR_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Reserved is 0, hap info already exist");
            return AccessTokenError::ERR_TOKENID_HAS_EXISTED;
        }
        AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        int32_t ret = DeleteFromDbByTokenId(tokenId);
        if (ret != ERR_OK) {
            return ERR_SERVICE_ABNORMAL;
        }
    }
    return RET_SUCCESS;
}

int32_t InstallSessionManager::GetTokenIdAndUid(InstallCache& cache, const BundlePolicy& bundlePolicy)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, cache.baseInfo.bundleName);
    conditionValue.Put(TokenFiledConst::FIELD_INST_INDEX, cache.baseInfo.instIndex);
    std::vector<GenericValues> hapTokenResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, hapTokenResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Query failed, ret: %{public}d", ret);
        return ERR_DATABASE_OPERATE_FAILED;
    }

    int32_t bundleId = -1;
    for (const auto& tokenValue : hapTokenResults) {
        int32_t userId = tokenValue.GetInt(TokenFiledConst::FIELD_USER_ID);
        AccessTokenID tokenId = static_cast<AccessTokenID>(tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
        int32_t reserved = tokenValue.GetInt(TokenFiledConst::FIELD_RESERVED);
        int32_t uid = tokenValue.GetInt(TokenFiledConst::FIELD_UID);
        int32_t oldAttr = tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ATTR);
        if (userId == cache.baseInfo.userID) {
            ret = MatchBaseInfo(cache, reserved, tokenId, uid, oldAttr);
            if (ret != ERR_OK || cache.reserved == static_cast<int32_t>(ReservedType::RESERVED_DATA)) {
                return ret;
            }
        } else if (uid != -1) {
            bundleId = uid;
            cache.isNewBundleId = false;
        }
    }

    return CreateTokenIdAndUid(cache, bundlePolicy, bundleId);
}

void InstallSessionManager::SupplementUpdateInfo(InstallCache& cache)
{
    std::shared_ptr<BundleInfoInner> infoInner = AccessTokenInfoManager::GetInstance().GetBundleInfoInner(
        cache.bundleParam.bundleName);
    if (infoInner == nullptr) {
        return;
    }
    std::vector<AccessTokenID> tokenIds = infoInner->tokenIds;
    for (auto tokenId : tokenIds) {
        if (cache.tokenIDToBundlePolicy.find(tokenId) == cache.tokenIDToBundlePolicy.end()) {
            BundlePolicy bundlePolicy;
            bundlePolicy.isDebugGrant = false;
            cache.tokenIDToBundlePolicy[tokenId] = bundlePolicy;
        }
    }
}

void InstallSessionManager::FilterPermissionByFeatures(InstallCache& cache)
{
    if (!cache.bundleParam.isSystem) {
        return;
    }
    for (auto it = cache.policy.permStateList.begin(); it != cache.policy.permStateList.end();) {
        if (PermissionFeatureManager::GetInstance().IsSupportFeature(*it)) {
            ++it;
            continue;
        }

        LOGI(ATM_DOMAIN, ATM_TAG, "%{public}s filter by feature", it->permissionName.c_str());
        it = cache.policy.permStateList.erase(it);
    }
}

bool InstallSessionManager::GetPermissionBriefData(const PermissionStatus &permState, BriefPermData& briefPermData)
{
    uint32_t code;
    PermissionBriefDef briefDef;
    if (GetPermissionBriefDef(permState.permissionName, briefDef, code) && briefDef.isEnable) {
        briefPermData.status = static_cast<int8_t>(permState.grantStatus);
        briefPermData.permCode = code;
        briefPermData.flag = permState.grantFlag;
        briefPermData.type = 0;
        if (briefDef.isKernelEffect) {
            briefPermData.type |= IS_KERNEL_EFFECT;
        }

        if (briefDef.hasValue) {
            briefPermData.type |= HAS_VALUE;
        }

        if (briefPermData.type != 0) {
            LOGI(ATM_DOMAIN, ATM_TAG, "%{public}s with type %{public}d",
                permState.permissionName.c_str(), static_cast<int32_t>(briefPermData.type));
        }
        return true;
    }

    return false;
}

void InstallSessionManager::FillPermBriefDataList(
    const std::vector<PermissionStatus>& permStateList, std::vector<BriefPermData>& permBriefDataList)
{
    for (const auto& permState : permStateList) {
        BriefPermData data;
        if (GetPermissionBriefData(permState, data)) {
            permBriefDataList.emplace_back(data);
        }
    }
}

int32_t InstallSessionManager::InitDlpPermission(const HapBaseInfo& baseInfo, HapPolicy& policy)
{
    HapInfoParams params;
    params.userID = baseInfo.userID;
    params.bundleName = baseInfo.bundleName;
    std::vector<PermissionStatus> initializedList;
    std::vector<GenericValues> undefValues;
    if (!PermissionManager::GetInstance().InitDlpPermissionList(params, initializedList, undefValues)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "InitDlpPermission failed");
        return ERR_PERM_REQUEST_CFG_FAILED;
    }
    policy.permStateList = initializedList;
    return RET_SUCCESS;
}

void TransferPermValue(const HapPolicy& policy, std::vector<PermissionWithValue>& extPerms)
{
    for (const auto& it : policy.aclExtendedMap) {
        auto iter = std::find_if(policy.permStateList.begin(), policy.permStateList.end(),
            [&it](const PermissionStatus& perm) {
                return it.first == perm.permissionName;
            });
        if (iter != policy.permStateList.end()) {
            PermissionWithValue value;
            value.permissionName = it.first;
            value.value = it.second;
            extPerms.emplace_back(value);
        }
    }
}

void FillPermStateFromGenericValues(
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

int32_t InstallSessionManager::FillPermStateFromDb(
    AccessTokenID tokenId, std::vector<BriefPermData>& permBriefDataList, bool noNeedPermissionInheritance)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    std::vector<GenericValues> permStateResults;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_PERMISSION_STATE, conditionValue, permStateResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Find permission state failed, ret=%{public}d", ret);
        return ERR_DATABASE_OPERATE_FAILED;
    }

    std::vector<PermissionStatus> existingPermList;
    FillPermStateFromGenericValues(permStateResults, existingPermList);
    std::vector<BriefPermData> oldPermBriefDataList;
    FillPermBriefDataList(existingPermList, oldPermBriefDataList);

    MergePermission(permBriefDataList, oldPermBriefDataList, noNeedPermissionInheritance);
    return RET_SUCCESS;
}

int32_t InstallSessionManager::AllocHapInfo(const InstallCache& cache, FinishContext& context)
{
    HapPolicy policy = cache.policy;
    policy.preAuthorizationInfo = cache.bundlePolicy.preAuthorizationInfo;
    policy.isDebugGrant = cache.bundlePolicy.isDebugGrant;
    policy.dlpType = cache.bundlePolicy.dlpType;

    InitPermissionList(cache.bundleParam, policy);

    if (policy.dlpType != DLP_COMMON) {
        int32_t ret = InitDlpPermission(cache.baseInfo, policy);
        if (ret != RET_SUCCESS) {
            return ret;
        }
#ifdef SUPPORT_SANDBOX_APP
        DlpPermissionSetManager::GetInstance().UpdatePermStateWithDlpInfo(policy.dlpType, policy.permStateList);
#endif
    }

    std::vector<BriefPermData> permBriefDataList;
    FillPermBriefDataList(policy.permStateList, permBriefDataList);

    std::vector<PermissionWithValue> extPerms;
    TransferPermValue(policy, extPerms);
    
    if (cache.reserved == static_cast<int32_t>(ReservedType::RESERVED_DATA)) {
        bool noNeedPermissionInheritance =
            NoNeedPermissionInheritance(cache.bundleParam, policy, cache.oldAttr);
        int32_t ret = FillPermStateFromDb(cache.oldTokenId, permBriefDataList, noNeedPermissionInheritance);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "FillPermStateFromDb failed, ret=%{public}d", ret);
            return ret;
        }
    }

    HapTokenInfo tokenInfo;
    AccessTokenInfoUtils::BuildHapTokenInfo(cache.identity, cache.bundleParam, tokenInfo);
    tokenInfo.dlpType = policy.dlpType;
    tokenInfo.instIndex = cache.baseInfo.instIndex;

    context.hapInfos.emplace_back(tokenInfo);
    context.permBriefDataLists.emplace_back(permBriefDataList);
    context.extendPermLists.emplace_back(extPerms);
    context.oldPermList.emplace_back(std::make_shared<std::vector<BriefPermData>>());
    context.innerInfo->tokenIds.emplace_back(static_cast<AccessTokenID>(cache.identity.tokenId & 0xffffffff));

    return RET_SUCCESS;
}

void InstallSessionManager::CreateUpdateHapInfo(const InstallCache& cache, FinishContext& context)
{
    for (const auto& [tokenIdInt, bundlePolicy] : cache.tokenIDToBundlePolicy) {
        AccessTokenID tokenId = static_cast<AccessTokenID>(tokenIdInt);
        std::shared_ptr<HapTokenInfoInner> infoPtr =
            AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId, false);
        if (infoPtr == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", tokenId);
            continue;
        }

        HapPolicy newPolicy = cache.policy;
        newPolicy.preAuthorizationInfo = bundlePolicy.preAuthorizationInfo;
        newPolicy.isDebugGrant = bundlePolicy.isDebugGrant;
        newPolicy.dlpType = bundlePolicy.dlpType;
        std::vector<PermissionStatus> existingPermList;
        infoPtr->GetPermissionStateList(existingPermList);
        std::vector<BriefPermData> oldPermBriefDataList;
        FillPermBriefDataList(existingPermList, oldPermBriefDataList);

        InitPermissionList(cache.bundleParam, newPolicy);
        std::vector<BriefPermData> permBriefDataList;
        FillPermBriefDataList(newPolicy.permStateList, permBriefDataList);

        bool noNeedPermissionInheritance =
            NoNeedPermissionInheritance(cache.bundleParam, newPolicy, infoPtr->GetAttr());
        MergePermission(permBriefDataList, oldPermBriefDataList, noNeedPermissionInheritance);

        HapTokenInfo tokenInfo = infoPtr->GetHapInfoBasic();
        tokenInfo.tokenAttr = GetTokenAttr(cache.bundleParam);

        std::vector<PermissionWithValue> extPerms;
        TransferPermValue(newPolicy, extPerms);

        std::vector<BriefPermData> briefPermDataList;
        (void)PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(tokenId, briefPermDataList);
        auto vectorPtr = std::make_shared<std::vector<BriefPermData>>(briefPermDataList);

        context.hapInfos.emplace_back(tokenInfo);
        context.permBriefDataLists.emplace_back(permBriefDataList);
        context.extendPermLists.emplace_back(extPerms);
        context.oldPermList.emplace_back(vectorPtr);
        context.innerInfo->tokenIds.emplace_back(tokenId);
    }
}

void InstallSessionManager::GenerateHapTokenInfoItem(const InstallCache& cache, const HapTokenInfo& hapInfo,
    std::vector<GenericValues>& genericValues)
{
    HapTokenInfoItem item;
    std::shared_ptr<HapTokenInfoInner> infoPtr =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(hapInfo.tokenID, false);
    if (infoPtr != nullptr) {
        item.permDialogCapState = infoPtr->IsPermDialogForbidden();
        item.migrated = infoPtr->IsMigrated();
    } else {
        item.permDialogCapState = false;
        item.migrated = false;
    }
    item.tokenId = hapInfo.tokenID;
    item.userId = static_cast<uint32_t>(hapInfo.userID);
    item.bundleName = hapInfo.bundleName;
    item.instIndex = static_cast<uint32_t>(hapInfo.instIndex);
    item.dlpType = static_cast<HapDlpType>(hapInfo.dlpType);
    item.apiVersion = hapInfo.apiVersion;
    item.uid = hapInfo.uid;
    item.tokenAttr = static_cast<uint32_t>(hapInfo.tokenAttr);

    item.appId = cache.bundleParam.appId;
    item.deviceId = "0";
    item.apl = cache.policy.apl;
    item.version = 1;
    item.reserved = ReservedType::NONE;

    item.BuildAddValue(genericValues);
}

void InstallSessionManager::ConvertBriefPermDataToGenericValues(AccessTokenID tokenId,
    const std::vector<BriefPermData>& briefPermDataList, std::vector<GenericValues>& genericValuesList)
{
    std::vector<GenericValues> oldPermStateValues;
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_PERMISSION_STATE,
        conditionValue, oldPermStateValues);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to find old permission states for token %{public}u, ret %{public}d.",
            tokenId, ret);
    }
    std::vector<PermissionStatus> existingPermList;
    FillPermStateFromGenericValues(oldPermStateValues, existingPermList);

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
        genericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, "PHONE-001");
        genericValues.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, 1);
        genericValues.Put(TokenFiledConst::FIELD_GRANT_STATE, static_cast<int32_t>(data.status));
        genericValues.Put(TokenFiledConst::FIELD_GRANT_FLAG, static_cast<int32_t>(data.flag));

        auto iter = std::find_if(existingPermList.begin(), existingPermList.end(),
            [permissionName, data](const PermissionStatus& oldPerm) {
                return permissionName == oldPerm.permissionName && data.status == oldPerm.grantStatus;
            });
        if (iter != existingPermList.end()) {
            genericValues.Put(TokenFiledConst::FIELD_TIMESTAMP, static_cast<int64_t>(iter->timestamp));
        } else {
            genericValues.Put(TokenFiledConst::FIELD_TIMESTAMP, static_cast<int64_t>(currentTimestamp));
        }

        genericValuesList.emplace_back(genericValues);
    }
}

void InstallSessionManager::GeneratePermDefFromHapPolicy(AccessTokenID tokenId, const HapPolicy& hapPolicy,
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

int32_t InstallSessionManager::ConvertInstallCacheToBundleInfoItems(const InstallCache& cache,
    const std::map<std::string, std::string>& modulePathMap, std::vector<GenericValues>& genericValuesList,
    GenericValues& delCondition)
{
    BundleInfoItems items;
    if (cache.bundleInfos.empty()) {
        return RET_SUCCESS;
    }
    items.bundleName = cache.bundleInfos[0].GetBundleName();
    items.isPreInstalled = cache.list.isPreInstalled;
    size_t fullBundleSize = cache.bundleInfos.size();
    size_t bundleSize = cache.list.hapPaths.size();
    for (size_t i = 0; i < fullBundleSize; ++i) {
        const auto& bundleInfo = cache.bundleInfos[i];
        ModuleInfoItem moduleItem;
        moduleItem.moduleName = bundleInfo.GetModuleName();
        if (i < bundleSize) {
            auto it = modulePathMap.find(cache.list.hapPaths[i]);
            if (it == modulePathMap.end()) {
                LOGC(ATM_DOMAIN, ATM_TAG, "HAP path not found in map on FinishInstall");
                return AccessTokenError::ERR_PARAM_INVALID;
            }
            moduleItem.path = it->second;
        } else {
            moduleItem.path = cache.additionalPaths[i - bundleSize];
        }
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
    delCondition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, items.bundleName);
    return RET_SUCCESS;
}

void InstallSessionManager::GenerateOneDbInfo(const InstallCache& cache, const HapTokenInfo& hapInfo,
    const std::vector<BriefPermData>& permBriefDataList, std::vector<AddInfo>& addInfoVec,
    std::vector<DelInfo>& delInfoVec)
{
    AccessTokenID tokenId = hapInfo.tokenID;
    std::vector<GenericValues> hapTokenInfoValues;
    GenerateHapTokenInfoItem(cache, hapInfo, hapTokenInfoValues);
    std::vector<GenericValues> permStateValues;
    ConvertBriefPermDataToGenericValues(tokenId, permBriefDataList, permStateValues);
    std::vector<GenericValues> permDefValues;
    GeneratePermDefFromHapPolicy(tokenId, cache.policy, hapInfo.bundleName, permDefValues);

    AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, hapTokenInfoValues, addInfoVec);
    AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, permStateValues, addInfoVec);

    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, delInfoVec);
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition, delInfoVec);

    if (!permDefValues.empty()) {
        AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, permDefValues, addInfoVec);
        AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, condition, delInfoVec);
    }
}

bool isInstallInfoHasCache(const HapBaseInfo& baseInfo)
{
    AccessTokenIDEx idEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(
        baseInfo.userID, baseInfo.bundleName, baseInfo.instIndex);
    if (idEx.tokenIDEx != 0) {
        return true;
    }
    return false;
}

int32_t InstallSessionManager::DeleteAndInsertValueToDb(const InstallCache& cache,
    const FinishContext& context, const std::map<std::string, std::string>& modulePathMap)
{
    std::vector<AddInfo> addInfoVec;
    std::vector<DelInfo> delInfoVec;
    for (size_t i = 0; i < context.hapInfos.size(); ++i) {
        GenerateOneDbInfo(cache, context.hapInfos[i], context.permBriefDataLists[i], addInfoVec, delInfoVec);
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

    if (cache.reserved == static_cast<int32_t>(ReservedType::RESERVED_IDENTITY)) {
        GenericValues condition;
        condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(cache.oldTokenId));
        DelInfo delInfo;
        delInfo.delType = AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO;
        delInfo.delValue = condition;
        delInfoVec.emplace_back(delInfo);
    }

    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "DeleteAndInsertValues failed ret=%{public}d", ret);
        return ERR_DATABASE_OPERATE_FAILED;
    }
    return ret;
}

void InstallSessionManager::RefreshCache(int32_t sessionId, const InstallCache& cache, const FinishContext& context)
{
    bool hasNewInstall = (cache.identity.tokenId != 0);
    if (hasNewInstall) {
        AccessTokenInfoManager::GetInstance().CommitCreateHapCache(
            context.hapInfos.front(), context.permBriefDataLists.front(), context.extendPermLists.front(),
            context.innerInfo);
    }

    for (size_t i = hasNewInstall ? 1 : 0; i < context.hapInfos.size(); ++i) {
        AccessTokenInfoManager::GetInstance().CommitUpdateHapCache(
            context.hapInfos[i], context.permBriefDataLists[i], context.extendPermLists[i], context.innerInfo);
#ifdef TOKEN_SYNC_ENABLE
        TokenModifyNotifier::GetInstance().NotifyTokenModify(context.hapInfos[i].tokenID);
#endif
        AccessTokenInfoManager::GetInstance().ReleaseInactiveTokenInfoInner(context.hapInfos[i].tokenID);
        AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(context.hapInfos[i].tokenID, TokenIdStatus::ACTIVE);
    }
    if (cache.reserved == static_cast<int32_t>(ReservedType::RESERVED_IDENTITY)) {
        AccessTokenIDManager::GetInstance().RemoveReservedTokenId(cache.oldTokenId);
    }
    ReportSessionFinish(sessionId, cache, SessionFinishSceneCode::SESSION_FINISH, 0);
}

void InstallSessionManager::RollbackAll(int32_t sessionId, int32_t sceneCode, int32_t errorCode, AccessTokenID tokenId,
    bool eraseCache)
{
    auto it = sessionToInstallCache.find(sessionId);
    if (it == sessionToInstallCache.end()) {
        return;
    }
    ReportSessionError(it->second, sceneCode, errorCode, tokenId);
    if (it->second.identity.tokenId != 0) {
        if (it->second.reserved == static_cast<int32_t>(ReservedType::RESERVED_DATA)) {
            (void)AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(
                static_cast<AccessTokenID>(it->second.identity.tokenId), TokenIdStatus::RESERVED);
        } else {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(
                static_cast<AccessTokenID>(it->second.identity.tokenId));
        }
        
        if (it->second.isNewBundleId) {
            AccessTokenIDManager::GetInstance().RemoveBundleId(it->second.identity.uid);
        }
    }
    for (auto it: it->second.tokenIDToBundlePolicy) {
        TokenIdStatus status;
        if (AccessTokenIDManager::GetInstance().GetTokenIdStatus(it.first, status) != RET_SUCCESS) {
            continue;
        }
        AccessTokenInfoManager::GetInstance().ReleaseInactiveTokenInfoInner(it.first);
    }
    int32_t callerPid = it->second.callerPid;
    if (eraseCache) {
        sessionToInstallCache.erase(sessionId);
        sessionToTimestamp.erase(sessionId);
        ReleaseDeathStub(callerPid);
    }
}

int32_t InstallSessionManager::CheckHapSignInfo(const BundleHapList& list, const sptr<IRemoteObject>& cb,
    int32_t& sessionId, std::vector<TrustedBundleInfo>& bundleInfo, HapVerifyResultInfo& resultInfo)
{
    ClearTimeoutData();

    if (list.hapPaths.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "hapPaths is empty");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    InstallCache cache;
    cache.list = list;

    for (size_t i = 0; i < cache.list.hapPaths.size(); i++) {
        TrustedBundleInfoInner infoInner;
        bool isChanged = false;
        int32_t ret = HapSignVerifyManager::GetInstance().CheckHapsSignInfo(
            HapSignVerifyManager::MakeVerifyParams(cache.list.hapPaths[i],
                Security::Verify::VerifyType::All, list.userId),
            false, infoInner, isChanged);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "CheckHapsSignInfo failed ret=%{public}d", ret);
            resultInfo.index = i;
            resultInfo.errorCode = ret;
            return ERR_HAP_SIGN_VERIFY_FAILED;
        }
        cache.bundleInfos.emplace_back(infoInner);
    }

    HapSignVerifyManager::GetInstance().ConvertTrustedBundleInfo(cache.bundleInfos, bundleInfo);

    int32_t ret = HapSignVerifyManager::GetInstance().CheckMultipleHaps(cache.bundleInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "CheckMultipleHaps failed ret=%{public}d", ret);
        return ERR_CHECK_MULTIPLE_HAP_FAILED;
    }

    int32_t callerPid = IPCSkeleton::GetCallingPid();
    cache.callerPid = callerPid;
    ProcessProxyDeathStub(cb);

    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        sessionId = ++sessionCnt;
        sessionToInstallCache[sessionId] = cache;
        sessionToTimestamp[sessionId] = TimeUtil::GetCurrentTimestamp();
    }
    return RET_SUCCESS;
}

int32_t InstallSessionManager::CheckType(std::vector<std::string>& additionalPaths, InstallTypeEnum type)
{
    if (!additionalPaths.empty() && type == InstallTypeEnum::TYPE_INSTALL) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Already has data, type:0");
        return ERR_BUNDLE_ALREADY_EXIST;
    }

    if (additionalPaths.empty() &&
        (type == InstallTypeEnum::TYPE_MERGE || type == InstallTypeEnum::TYPE_REPLACE)) {
        LOGC(ATM_DOMAIN, ATM_TAG, "No data, type:%{public}d", static_cast<int32_t>(type));
        return ERR_BUNDLE_NOT_EXIST;
    }

    return RET_SUCCESS;
}

int32_t InstallSessionManager::CheckHapPermissionInfo(
    int32_t sessionId, InstallTypeEnum type, HapInfoCheckResult& result)
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    if (sessionToInstallCache.find(sessionId) == sessionToInstallCache.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "sessionId not exist");
        return AccessTokenError::ERR_SESSION_NOT_EXIST;
    }
    InstallCache& cache = sessionToInstallCache[sessionId];
    cache.type = type;

    if (cache.bundleInfos.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "bundleInfos is empty");
        return ERR_PARAM_INVALID;
    }

    std::vector<std::string> additionalPaths;
    std::vector<std::vector<uint8_t>> persistDatas;
    int32_t ret = GetHapPathFromDb(
        cache.bundleInfos.front().GetBundleName(), additionalPaths, persistDatas);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get hap info failed ret=%{public}d", ret);
        RollbackAll(sessionId, SessionFinishSceneCode::GET_HAP_PATH, ret, 0);
        return ret;
    }

    ret = CheckType(additionalPaths, type);
    if (ret != RET_SUCCESS) {
        RollbackAll(sessionId, SessionFinishSceneCode::CHECK_TYPE, ret, 0);
        return ret;
    }

    if (type == InstallTypeEnum::TYPE_MERGE && !additionalPaths.empty()) {
        ret = RebuildHapPolicy(cache, additionalPaths, persistDatas);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Rebuild hap policy failed ret=%{public}d", ret);
            RollbackAll(sessionId, SessionFinishSceneCode::REBUILD_HAP_POLICY, ret, 0);
            return ret;
        }
    } else {
        ret = HapSignVerifyManager::GetInstance().BuildHapPolicy(cache.bundleInfos, cache.policy, cache.bundleParam);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "BuildHapPolicy failed ret=%{public}d", ret);
            RollbackAll(sessionId, SessionFinishSceneCode::BUILD_HAP_POLICY, ret, 0);
            return ERR_BUILD_POLICY_FAILED;
        }
    }
    
    ret = CheckPermissionList(cache, result);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Check permission failed ret=%{public}d", ret);
        RollbackAll(sessionId, SessionFinishSceneCode::CHECK_PERMISSION_LIST, ret, 0);
        return ret;
    }
    cache.isCheckPerm = true;
    return RET_SUCCESS;
}

int32_t InstallSessionManager::GetAppIdFromDb(const std::string& bundleName, std::string& appId)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    std::vector<GenericValues> hapTokenResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, conditionValue, hapTokenResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Query failed, ret: %{public}d", ret);
        return ERR_DATABASE_OPERATE_FAILED;
    }

    if (hapTokenResults.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Query empty");
        return ERR_PARAM_INVALID;
    }

    appId = hapTokenResults[0].GetString(TokenFiledConst::FIELD_APP_ID);
    return RET_SUCCESS;
}

int32_t InstallSessionManager::FillInstallPolicy(
    const std::string& bundleName, const BundlePolicy& bundlePolicy, InstallCache& cache)
{
    if (PermissionKernelUtils::IsKernelSupportSpm()) {
        int32_t ret = AccessTokenInfoManager::GetInstance().FillInstallPolicyWithoutHaps(
            bundleName, bundlePolicy, cache.bundleParam, cache.policy);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "FillInstallPolicyWithoutHaps failed ret=%{public}d", ret);
            return ERR_KERNEL_OPERATION_FAILED;
        }
        for (auto status : cache.policy.permStateList) {
            cache.policy.aclRequestedList.emplace_back(status.permissionName);
        }
        return GetAppIdFromDb(cache.bundleParam.bundleName, cache.bundleParam.appId);
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Kernel not supported, fallback to db verify");

    std::vector<TrustedBundleInfoInner> bundleInfos;
    int32_t ret = GetHapPathsFromDbAndVerify(bundleName, bundleInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetHapPathsFromDbAndVerify failed ret=%{public}d", ret);
        return ret;
    }
    if (bundleInfos.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "No hap found for bundle %{public}s", bundleName.c_str());
        return AccessTokenError::ERR_BUNDLE_NOT_EXIST;
    }

    ret = HapSignVerifyManager::GetInstance().BuildHapPolicy(bundleInfos, cache.policy, cache.bundleParam);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "BuildHapPolicy failed ret=%{public}d", ret);
        return ERR_BUILD_POLICY_FAILED;
    }

    return RET_SUCCESS;
}

int32_t InstallSessionManager::CreateInstallSession(const HapBaseInfo& info, const BundlePolicy& policy,
    const sptr<IRemoteObject>& cb, int32_t& sessionId)
{
    InstallCache cache;
    cache.baseInfo = info;
    int32_t ret = FillInstallPolicy(info.bundleName, policy, cache);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "FillInstallPolicy failed ret=%{public}d", ret);
        RollbackAll(sessionId, SessionFinishSceneCode::FILL_INSTALL_POLICY, ret, 0);
        return ret;
    }
    cache.isCheckPerm = true;

    int32_t callerPid = IPCSkeleton::GetCallingPid();
    cache.callerPid = callerPid;
    ProcessProxyDeathStub(cb);

    std::lock_guard<std::mutex> lock(cacheMutex_);
    sessionId = ++sessionCnt;
    sessionToInstallCache[sessionId] = cache;
    sessionToTimestamp[sessionId] = TimeUtil::GetCurrentTimestamp();
    return RET_SUCCESS;
}

int32_t InstallSessionManager::PrepareSessionIdentity(int32_t sessionId, const HapBaseInfo& info,
    const BundlePolicy& policy, Identity& identity)
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    if (sessionToInstallCache.find(sessionId) == sessionToInstallCache.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "sessionId not exist");
        return AccessTokenError::ERR_SESSION_NOT_EXIST;
    }
    InstallCache& cache = sessionToInstallCache[sessionId];
    if (cache.identity.tokenId != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Already prepare");
        RollbackAll(sessionId, SessionFinishSceneCode::PREPARE_IDENTITY, AccessTokenError::ERR_ALREADY_PREPARE, 0);
        return AccessTokenError::ERR_ALREADY_PREPARE;
    }
    if (!cache.isCheckPerm) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Not check permission!");
        RollbackAll(sessionId, SessionFinishSceneCode::PREPARE_IDENTITY, AccessTokenError::ERR_NOT_CHECK_PERMISSION, 0);
        return AccessTokenError::ERR_NOT_CHECK_PERMISSION;
    }
    if (!cache.bundleInfos.empty()) {
        auto bundleType = cache.bundleInfos.front().GetBundleType();
        if (bundleType != static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP) &&
            bundleType != static_cast<int32_t>(AppExecFwk::Spm::BundleType::ATOMIC_SERVICE) &&
            bundleType != static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP_SERVICE_FWK)) {
            LOGC(ATM_DOMAIN, ATM_TAG, "BundleType %{public}d not allow create tokenID",
                static_cast<int32_t>(bundleType));
            RollbackAll(sessionId, SessionFinishSceneCode::PREPARE_IDENTITY, AccessTokenError::ERR_PARAM_INVALID, 0);
            return AccessTokenError::ERR_PARAM_INVALID;
        }
    }
    cache.baseInfo = info;
    int32_t ret = GetTokenIdAndUid(cache, policy);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetTokenIdAndUid failed ret=%{public}d", ret);
        RollbackAll(sessionId, SessionFinishSceneCode::PREPARE_IDENTITY, ret, 0);
        return ret;
    }
    identity.tokenId = cache.identity.tokenId;
    identity.uid = cache.identity.uid;
    cache.bundlePolicy = policy;
    
    return RET_SUCCESS;
}

int32_t InstallSessionManager::PrepareHapIdentity(
    int32_t& sessionId, const HapBaseInfo& info, const BundlePolicy& policy,
    const sptr<IRemoteObject>& cb, Identity& identity)
{
    if (sessionId == 0) {
        int32_t ret = CreateInstallSession(info, policy, cb, sessionId);
        if (ret != RET_SUCCESS) {
            return ret;
        }
    }
    
    return PrepareSessionIdentity(sessionId, info, policy, identity);
}

int32_t InstallSessionManager::UpdateHapPolicy(int32_t sessionId, int32_t tokenId, const BundlePolicy& policy)
{
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        if (!migrationDone_.load()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Migration not completed");
            RollbackAll(sessionId,
                SessionFinishSceneCode::UPDATE_HAP_POLICY, AccessTokenError::ERR_MIGRATION_COMPLETED, tokenId);
            return AccessTokenError::ERR_MIGRATION_COMPLETED;
        }
        auto it = sessionToInstallCache.find(sessionId);
        if (it == sessionToInstallCache.end()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "sessionId not exist");
            return AccessTokenError::ERR_SESSION_NOT_EXIST;
        }
        if (!it->second.isCheckPerm) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Not check permission!");
            RollbackAll(sessionId,
                SessionFinishSceneCode::UPDATE_HAP_POLICY, AccessTokenError::ERR_NOT_CHECK_PERMISSION, tokenId);
            return AccessTokenError::ERR_NOT_CHECK_PERMISSION;
        }
        std::shared_ptr<HapTokenInfoInner> infoPtr =
            AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId, false);
        if (infoPtr == nullptr || infoPtr->GetBundleName() != it->second.bundleParam.bundleName) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid or not match bundleName.", tokenId);
            RollbackAll(sessionId,
                SessionFinishSceneCode::UPDATE_HAP_POLICY, AccessTokenError::ERR_PARAM_INVALID, tokenId);
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        it->second.tokenIDToBundlePolicy[static_cast<int32_t>(tokenId)] = policy;
    }
    return RET_SUCCESS;
}

int32_t InstallSessionManager::FillFinishContext(int32_t sessionId, const InstallCache& cache,
    FinishContext& context)
{
    if (cache.identity.tokenId != 0) {
        if (isInstallInfoHasCache(cache.baseInfo)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get cache by install info");
            return AccessTokenError::ERR_ALREADY_FINISH_INSTALL;
        }
        
        int32_t ret = AllocHapInfo(cache, context);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Alloc hap info failed");
            return ret;
        }
    }

    CreateUpdateHapInfo(cache, context);
    return RET_SUCCESS;
}

int32_t InstallSessionManager::ExecuteSpmKernelTasks(int32_t sessionId, const InstallCache& cache,
    const FinishContext& context, SpmTaskContext& spmContext)
{
    size_t startIndex = 0;
    if (cache.identity.tokenId != 0) {
        startIndex = 1;
        spmContext.addParams.emplace_back(SpmDataParam{context.hapInfos.front(), context.noCachedInfo,
            context.permBriefDataLists.front(), context.extendPermLists.front(), nullptr, true});
    }

    for (size_t i = startIndex; i < context.hapInfos.size(); ++i) {
        TokenIdStatus status;
        if (AccessTokenIDManager::GetInstance().GetTokenIdStatus(context.hapInfos[i].tokenID, status) == RET_SUCCESS &&
            status == TokenIdStatus::ACTIVE) {
            std::vector<BriefPermData>* oldPermPtr = (i < context.oldPermList.size()) ?
                context.oldPermList[i].get() : nullptr;
            spmContext.updateParams.emplace_back(SpmDataParam{context.hapInfos[i], context.noCachedInfo,
                context.permBriefDataLists[i], context.extendPermLists[i], oldPermPtr, true});
        } else {
            spmContext.addParams.emplace_back(SpmDataParam{context.hapInfos[i], context.noCachedInfo,
                context.permBriefDataLists[i], context.extendPermLists[i], nullptr, true});
        }
    }

    if (!spmContext.addParams.empty()) {
        spmContext.addTask = std::make_shared<AddSpmDataTask>(spmContext.addParams);
        uint32_t errIndex = 0;
        int32_t ret = spmContext.addTask->Add(errIndex);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Add cache failed, ret=%{public}d", ret);
            return ERR_KERNEL_OPERATION_FAILED;
        }
    }

    if (spmContext.updateParams.empty()) {
        return RET_SUCCESS;
    }
    
    spmContext.updateTask = std::make_shared<UpdateSpmDataTask>(spmContext.updateParams);
    uint32_t errIndex = 0;
    int32_t ret = spmContext.updateTask->Update(errIndex);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Update cache failed, ret=%{public}d", ret);
        if (spmContext.addTask) {
            spmContext.addTask->Rollback();
        }
        return ERR_KERNEL_OPERATION_FAILED;
    }

    return RET_SUCCESS;
}

int32_t InstallSessionManager::FinishInstallInner(int32_t sessionId, InstallCache& cache,
    const std::map<std::string, std::string>& modulePathMap)
{
    FinishContext context;
    AccessTokenInfoUtils::BuildBundleFullInfo(cache.bundleParam, cache.policy, context.innerInfo, context.noCachedInfo);

    int32_t ret = FillFinishContext(sessionId, cache, context);
    if (ret != RET_SUCCESS) {
        RollbackAll(sessionId, SessionFinishSceneCode::FILL_FINISH_CONTEXT, ret, 0);
        return ret;
    }

    SpmTaskContext spmContext;
    ret = ExecuteSpmKernelTasks(sessionId, cache, context, spmContext);
    if (ret != RET_SUCCESS) {
        RollbackAll(sessionId, SessionFinishSceneCode::EXECUTE_KERNEL_TASK, ret, 0);
        return ret;
    }

    ret = DeleteAndInsertValueToDb(cache, context, modulePathMap);
    if (ret != RET_SUCCESS) {
        if (spmContext.addTask) {
            spmContext.addTask->Rollback();
        }
        if (spmContext.updateTask) {
            spmContext.updateTask->Rollback();
        }
        RollbackAll(sessionId, SessionFinishSceneCode::FINISH_DB_OPRATION, ret, 0);
        return ret;
    }

    RefreshCache(sessionId, cache, context);
    int32_t callerPid = cache.callerPid;
    sessionToInstallCache.erase(sessionId);
    sessionToTimestamp.erase(sessionId);
    ReleaseDeathStub(callerPid);
    return RET_SUCCESS;
}

int32_t InstallSessionManager::FinishInstall(int32_t sessionId, bool isSuccess,
    const std::map<std::string, std::string>& modulePathMap)
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    if (!isSuccess) {
        RollbackAll(sessionId, SessionFinishSceneCode::FINISH_NOT_SUCCESS, 0, 0);
        return RET_SUCCESS;
    }

    auto it = sessionToInstallCache.find(sessionId);
    if (it == sessionToInstallCache.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "sessionId not exist");
        return AccessTokenError::ERR_SESSION_NOT_EXIST;
    }

    if (!it->second.isCheckPerm) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Not check permission!");
        RollbackAll(sessionId, SessionFinishSceneCode::FINISH_INSTALL, AccessTokenError::ERR_NOT_CHECK_PERMISSION, 0);
        return AccessTokenError::ERR_NOT_CHECK_PERMISSION;
    }

    if (!it->second.bundleInfos.empty()) {
        int32_t bundleType = it->second.bundleInfos.front().GetBundleType();
        if (bundleType == static_cast<int32_t>(AppExecFwk::Spm::BundleType::SHARED) ||
            bundleType == static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP_PLUGIN)) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Type %{public}d no need Finish", static_cast<int32_t>(bundleType));
            int32_t callerPid = it->second.callerPid;
            sessionToInstallCache.erase(sessionId);
            sessionToTimestamp.erase(sessionId);
            ReleaseDeathStub(callerPid);
            return RET_SUCCESS;
        }

        SupplementUpdateInfo(it->second);
    }

    if (!migrationDone_.load()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migration not completed");
        RollbackAll(sessionId, SessionFinishSceneCode::FINISH_INSTALL, AccessTokenError::ERR_MIGRATION_COMPLETED, 0);
        return AccessTokenError::ERR_MIGRATION_COMPLETED;
    }

    FilterPermissionByFeatures(it->second);

    return FinishInstallInner(sessionId, it->second, modulePathMap);
}

int32_t InstallSessionManager::GetCacheSignInfoBySessionId(
    int32_t sessionId, std::vector<TrustedBundleInfo>& bundleInfo)
{
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        auto it = sessionToInstallCache.find(sessionId);
        if (it == sessionToInstallCache.end()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "sessionId not exist");
            return AccessTokenError::ERR_SESSION_NOT_EXIST;
        }
        HapSignVerifyManager::GetInstance().ConvertTrustedBundleInfo(
            std::vector<TrustedBundleInfoInner>(it->second.bundleInfos.begin(),
            it->second.bundleInfos.begin() + it->second.list.hapPaths.size()), bundleInfo);
    }
    if (bundleInfo.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SessionId %{public}d bundleInfo is empty", sessionId);
        return ERR_PARAM_INVALID;
    }
    return RET_SUCCESS;
}

int32_t InstallSessionManager::FastVerify(const std::vector<std::string>& paths,
    std::vector<std::vector<uint8_t>>& persistDatas, std::vector<TrustedBundleInfoInner>& bundleInfos, int32_t userId)
{
    for (size_t i = 0; i < paths.size() && i < persistDatas.size(); ++i) {
        TrustedBundleInfoInner infoInner;
        infoInner.bootstrapInfo = std::make_shared<Security::Verify::BootstrapInfo>();
        infoInner.bootstrapInfo->Load(persistDatas[i].data(), persistDatas[i].size());
        bool isChanged = false;
        int32_t ret = HapSignVerifyManager::GetInstance().CheckHapsSignInfo(
            HapSignVerifyManager::MakeVerifyParams(paths[i], Security::Verify::VerifyType::Fast, userId),
            false, infoInner, isChanged);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "CheckHapsSignInfo failed ret=%{public}d", ret);
            return ERR_HAP_SIGN_VERIFY_FAILED;
        }
        bundleInfos.emplace_back(infoInner);
    }
    return RET_SUCCESS;
}

int32_t InstallSessionManager::GetHapPathsFromDbAndVerify(
    const std::string& bundleName, std::vector<TrustedBundleInfoInner>& bundleInfos)
{
    std::vector<std::string> hapPaths;
    std::vector<std::vector<uint8_t>> persistDatas;
    int32_t ret = GetHapPathFromDb(bundleName, hapPaths, persistDatas);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Find failed ret=%{public}d", ret);
        return ret;
    }
    if (hapPaths.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Bundle %{public}s not exist", bundleName.c_str());
        return ERR_BUNDLE_NOT_EXIST;
    }

    return FastVerify(hapPaths, persistDatas, bundleInfos);
}

int32_t InstallSessionManager::GetHapSignInfo(const std::string& bundleName, std::vector<TrustedBundleInfo>& bundleInfo)
{
    if (bundleName.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "bundleName is empty");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    std::vector<TrustedBundleInfoInner> bundleInfos;
    int32_t ret = GetHapPathsFromDbAndVerify(bundleName, bundleInfos);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    HapSignVerifyManager::GetInstance().ConvertTrustedBundleInfo(bundleInfos, bundleInfo);
    return RET_SUCCESS;
}

int32_t InstallSessionManager::GetCachePolicyBySessionId(int32_t sessionId, const std::string& bundleName,
    BundlePolicyInfo& bundlePolicyInfo)
{
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        auto it = sessionToInstallCache.find(sessionId);
        if (it == sessionToInstallCache.end()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "sessionId not exist");
            return AccessTokenError::ERR_SESSION_NOT_EXIST;
        }

        if (bundleName != it->second.bundleParam.bundleName) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Session bundle %{public}s not match",
                it->second.bundleInfos[0].GetBundleName().c_str());
            return AccessTokenError::ERR_PARAM_INVALID;
        }

        for (auto permState : it->second.policy.permStateList) {
            bundlePolicyInfo.reqPermissions.emplace_back(permState.permissionName);
        }
    }
    return RET_SUCCESS;
}

static void DumpPolicyEventInfo(const HapPolicy& policy, HapDfxInfo& dfxInfo)
{
    dfxInfo.permInfo = std::to_string(policy.permStateList.size()) + " : [";
    for (const auto& permState : policy.permStateList) {
        dfxInfo.permInfo.append(permState.permissionName + ", ");
    }
    dfxInfo.permInfo.append("]");

    dfxInfo.aclInfo = std::to_string(policy.aclRequestedList.size()) + " : [";
    for (const auto& perm : policy.aclRequestedList) {
        dfxInfo.aclInfo.append(perm + ", ");
    }
    dfxInfo.aclInfo.append("]");

    dfxInfo.extendInfo = std::to_string(policy.aclExtendedMap.size()) + " : {";
    for (const auto& aclExtend : policy.aclExtendedMap) {
        dfxInfo.extendInfo.append(aclExtend.first + ": " + aclExtend.second + ", ");
    }
    dfxInfo.extendInfo.append("}");
}

static void DumpPreAuthInfo(const std::vector<PreAuthorizationInfo>& preAuthorizationInfo, HapDfxInfo& dfxInfo)
{
    dfxInfo.preauthInfo = std::to_string(preAuthorizationInfo.size()) + " : [";
    for (const auto& preAuthInfo : preAuthorizationInfo) {
        dfxInfo.preauthInfo.append(preAuthInfo.permissionName + ", ");
    }
    dfxInfo.preauthInfo.append("]");
}

void InstallSessionManager::ReportAddHap(const InstallCache& cache, int32_t sceneCode,
    int32_t errorCode, const HapDfxInfo& dfxInfoRaw)
{
    HapDfxInfo dfxInfo = dfxInfoRaw;

    AccessTokenIDEx idEx;
    idEx.tokenIDEx = cache.identity.tokenId;

    dfxInfo.tokenId = idEx.tokenIdExStruct.tokenID;
    dfxInfo.tokenIdEx = idEx;
    dfxInfo.userID = cache.baseInfo.userID;
    dfxInfo.bundleName = cache.baseInfo.bundleName;
    dfxInfo.instIndex = cache.baseInfo.instIndex;

    dfxInfo.sceneCode = sceneCode;
    dfxInfo.dlpType = static_cast<HapDlpType>(cache.bundlePolicy.dlpType);
    dfxInfo.isRestore = (cache.reserved != 0);
    dfxInfo.oriTokenId = cache.oldTokenId;

    DumpPreAuthInfo(cache.bundlePolicy.preAuthorizationInfo, dfxInfo);
    ReportSysEventAddHap(errorCode, dfxInfo, true);
}

void InstallSessionManager::ReportUpdateHap(AccessTokenID tokenID, const BundlePolicy& bundlePolicy,
    int32_t sceneCode, int32_t errorCode, const HapDfxInfo& dfxInfoRaw)
{
    HapDfxInfo dfxInfo = dfxInfoRaw;
    dfxInfo.sceneCode = sceneCode;

    std::shared_ptr<HapTokenInfoInner> infoPtr =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", tokenID);
        return;
    }

    HapTokenInfo tokenInfo = infoPtr->GetHapInfoBasic();
    AccessTokenIDEx idEx;
    idEx.tokenIdExStruct.tokenID = tokenID;
    idEx.tokenIdExStruct.tokenAttr = tokenInfo.tokenAttr;

    dfxInfo.tokenId = tokenID;
    dfxInfo.tokenIdEx = idEx;
    dfxInfo.userID = tokenInfo.userID;
    dfxInfo.bundleName = tokenInfo.bundleName;
    dfxInfo.instIndex = tokenInfo.instIndex;

    DumpPreAuthInfo(bundlePolicy.preAuthorizationInfo, dfxInfo);
    ReportSysEventUpdateHap(errorCode, dfxInfo);
}

void InstallSessionManager::ReportSessionFinish(
    int32_t sessionId, const InstallCache& cache, int32_t sceneCode, int32_t errorCode)
{
    HapDfxInfo dfxInfoRaw;
    DumpPolicyEventInfo(cache.policy, dfxInfoRaw);
    dfxInfoRaw.duration = TimeUtil::GetCurrentTimestamp() - sessionToTimestamp[sessionId];

    if (cache.identity.tokenId != 0) {
        ReportAddHap(cache, sceneCode, errorCode, dfxInfoRaw);
    }
    
    for (auto it : cache.tokenIDToBundlePolicy) {
        ReportUpdateHap(it.first, it.second, sceneCode, errorCode, dfxInfoRaw);
    }

    if (cache.identity.tokenId == 0 && cache.tokenIDToBundlePolicy.empty()) {
        HapDfxInfo dfxInfo = dfxInfoRaw;
        dfxInfo.bundleName = cache.bundleParam.bundleName;
        dfxInfo.sceneCode = sceneCode;

        dfxInfo.tokenId = 0;
        dfxInfo.tokenIdEx.tokenIDEx = 0;
        dfxInfo.userID = 0;
        dfxInfo.instIndex = 0;
        dfxInfo.dlpType = HapDlpType::DLP_COMMON;
        dfxInfo.isRestore = false;
        dfxInfo.oriTokenId = 0;

        ReportSysEventAddHap(errorCode, dfxInfo, false);
    }
}

void InstallSessionManager::ReportSessionError(
    const InstallCache& cache, int32_t sceneCode, int32_t errorCode, AccessTokenID tokenId)
{
    HapDfxInfo dfxInfo;
    dfxInfo.bundleName = cache.bundleParam.bundleName;
    dfxInfo.sceneCode = sceneCode;
    dfxInfo.tokenId = tokenId;

    dfxInfo.tokenIdEx.tokenIDEx = 0;
    dfxInfo.userID = 0;
    dfxInfo.instIndex = 0;
    dfxInfo.dlpType = HapDlpType::DLP_COMMON;
    dfxInfo.isRestore = false;
    dfxInfo.oriTokenId = 0;
    ReportSysEventAddHap(errorCode, dfxInfo, true);
}

void InstallSessionManager::SetMigrationDone()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Migration done, flag set to true.");
    migrationDone_.store(true);
}

std::shared_ptr<ProxyDeathHandler> InstallSessionManager::GetProxyDeathHandler()
{
    std::lock_guard<std::mutex> lock(deathHandlerMutex_);
    if (proxyDeathHandler_ == nullptr) {
        proxyDeathHandler_ = std::make_shared<ProxyDeathHandler>();
    }
    return proxyDeathHandler_;
}

void InstallSessionManager::ProcessProxyDeathStub(const sptr<IRemoteObject>& anonyStub)
{
    if (anonyStub == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "anonyStub is nullptr");
        return;
    }
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    std::shared_ptr<ProxyDeathParam> param = std::make_shared<InstallSessionProxyDeathParam>(callerPid);
    if (param == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Create param failed");
        return;
    }
    auto handler = GetProxyDeathHandler();
    if (handler == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "handler is nullptr");
        return;
    }
    handler->AddProxyStub(anonyStub, param);
}

bool InstallSessionManager::HasCallerInSessionCache(int32_t callerPid)
{
    for (const auto& pair : sessionToInstallCache) {
        if (pair.second.callerPid == callerPid) {
            return true;
        }
    }
    return false;
}

void InstallSessionManager::ReleaseDeathStub(int32_t callerPid)
{
    if (HasCallerInSessionCache(callerPid)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Still has session for pid=%{public}d", callerPid);
        return;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Release death stub for pid=%{public}d", callerPid);
    std::shared_ptr<ProxyDeathParam> param = std::make_shared<InstallSessionProxyDeathParam>(callerPid);
    if (param == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Create param failed");
        return;
    }
    auto handler = GetProxyDeathHandler();
    if (handler == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "handler is nullptr");
        return;
    }
    handler->ReleaseProxyByParam(param);
}

void InstallSessionManager::ClearSessionByPid(int32_t pid)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "ClearSessionByPid pid=%{public}d", pid);
    std::lock_guard<std::mutex> lock(cacheMutex_);
    for (auto it = sessionToInstallCache.begin(); it != sessionToInstallCache.end();) {
        if (it->second.callerPid == pid) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Clear sessionId=%{public}d for pid=%{public}d", it->first, pid);
            RollbackAll(it->first, SessionFinishSceneCode::PROXY_DEATH, RET_FAILED, 0, false);
            sessionToTimestamp.erase(it->first);
            // death handler will release proxy
            it = sessionToInstallCache.erase(it);
        } else {
            ++it;
        }
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
