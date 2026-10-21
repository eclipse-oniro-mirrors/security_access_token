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

#include <algorithm>

#include "bundle_info_manager.h"
#include "install_session_manager.h"

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_utils.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_common_log.h"
#include "app_manager_access_client.h"
#include "access_token_db_operator.h"
#include "atm_data_type.h"
#include "callback_manager.h"
#include "constant_common.h"
#include "data_validator.h"
#ifdef SUPPORT_SANDBOX_APP
#include "dlp_permission_set_manager.h"
#endif
#include "hap_data_structure.h"
#include "hap_sign_verify_manager.h"
#include "hisysevent_adapter.h"
#include "iaccess_token_manager.h"
#include "install_db_repository.h"
#include "install_identity_manager.h"
#include "install_sysevent_reporter.h"
#include "ipc_skeleton.h"
#include "multiple_mode_utils.h"
#include "parameter.h"
#include "parameters.h"
#include "permission_constraint_check.h"
#include "permission_feature_manager.h"
#include "permission_manager.h"
#include "permission_map.h"
#include "permission_validator.h"
#include "perm_setproc.h"
#include "spm_data_kernel_common.h"
#include "time_util.h"
#include "tokenid_attributes.h"
#include "token_field_const.h"
#include "user_policy_manager.h"
#include "install_session_proxy_death_param.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_modify_notifier.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int64_t SESSION_TIMEOUT_MS = 3600000;
static const uint32_t DEBUG_APP_FLAG = 0x0008;
constexpr int32_t INVALID_UID = -1;
constexpr uint32_t ADMIN_CONTROLLED_FLAGS = PERMISSION_FIXED_BY_ADMIN_POLICY | PERMISSION_RESTRICTED_BY_ADMIN;

// Resolve the sticky state (migrated + permDialogCapState) of one token:
// session snapshot first, InfoManager chain as fallback. The caller-designated
// uid marks the token migrated on top of any prior state.
static void ResolveMigratedAndDialogCapState(const InstallCache& cache, AccessTokenID tokenId,
    InstallHapInfo& installInfo)
{
    std::shared_ptr<HapTokenInfoInner> infoPtr;
    auto innerIt = cache.untrustedTokenInfoMap.find(tokenId);
    if (innerIt != cache.untrustedTokenInfoMap.end()) {
        infoPtr = innerIt->second;
    } else {
        TokenIdStatus status = TokenIdStatus::ACTIVE;
        infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoAndStatus(tokenId, status);
    }
    // plain 32-bit id of the session's new identity (0 for pure update sessions)
    AccessTokenID installedToken = AccessTokenIDManager::ExtractTokenIdFromFull(cache.identity.tokenId);
    // this-session caller-designated uid: the installed identity takes the
    // session flag, each updated token takes its own resolution flag
    bool isUidFromCaller = false;
    if (tokenId == installedToken) {
        isUidFromCaller = cache.isUidFromCaller;
    } else {
        auto uidIt = cache.updatedUidStateMap.find(tokenId);
        isUidFromCaller = uidIt != cache.updatedUidStateMap.end() && uidIt->second.fromCaller;
    }

    if (infoPtr != nullptr && (tokenId != installedToken || cache.reserved == ReservedType::RESERVED_DATA)) {
        installInfo.permDialogCapState = infoPtr->IsPermDialogForbidden();
        installInfo.migrated = isUidFromCaller || infoPtr->IsMigrated();
    } else {
        installInfo.permDialogCapState = false;
        installInfo.migrated = isUidFromCaller;
    }
}

// Assemble the per-hap finish info (base info + sideload bit + sticky state).
static InstallHapInfo BuildInstallHapInfo(const InstallCache& cache, const HapTokenInfo& tokenInfo)
{
    InstallHapInfo installInfo;
    installInfo.baseInfo = tokenInfo;
    installInfo.isSideload = cache.bundleParam.isSideloadApp;
    ResolveMigratedAndDialogCapState(cache, tokenInfo.tokenID, installInfo);
    return installInfo;
}

// Map the finish info onto the hap cache commit item.
HapTokenInfoItem BuildHapTokenInfoItem(const InstallHapInfo& installInfo)
{
    HapTokenInfoItem item;
    item.tokenId = installInfo.baseInfo.tokenID;
    item.tokenAttr = installInfo.baseInfo.tokenAttr;
    item.userId = static_cast<uint32_t>(installInfo.baseInfo.userID);
    item.apiVersion = installInfo.baseInfo.apiVersion;
    item.instIndex = static_cast<uint32_t>(installInfo.baseInfo.instIndex);
    item.dlpType = static_cast<HapDlpType>(installInfo.baseInfo.dlpType);
    item.uid = installInfo.baseInfo.uid;
    item.bundleName = installInfo.baseInfo.bundleName;
    item.isSideload = installInfo.isSideload;
    item.migrated = installInfo.migrated;
    item.permDialogCapState = installInfo.permDialogCapState;
    return item;
}

// Only APP / ATOMIC_SERVICE / APP_SERVICE_FWK bundles may allocate a token id.
bool IsTokenAllocatableType(int32_t bundleType)
{
    return bundleType == static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP) ||
        bundleType == static_cast<int32_t>(AppExecFwk::Spm::BundleType::ATOMIC_SERVICE) ||
        bundleType == static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP_SERVICE_FWK);
}

// Only SHARED / APP_PLUGIN skip FinishInstall persistence.
// SKILL belongs to neither set: it persists sign data without a token.
bool IsNonPersistentBundleType(int32_t bundleType)
{
    return bundleType == static_cast<int32_t>(AppExecFwk::Spm::BundleType::SHARED) ||
        bundleType == static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP_PLUGIN);
}

bool HasModule(const std::vector<TrustedBundleInfoInner>& infos, const std::string& moduleName)
{
    return std::any_of(infos.begin(), infos.end(), [&moduleName](const TrustedBundleInfoInner& info) {
        return info.GetModuleName() == moduleName;
    });
}

// Pre-authorization info is bundle-level: take it from any policy BMS passed in
// via UpdateHapPolicy this round, falling back to PrepareHapIdentity's input.
std::vector<PreAuthorizationInfo> GetBundlePreAuthorization(const InstallCache& cache)
{
    if (!cache.updatedBundlePolicyMap.empty()) {
        return cache.updatedBundlePolicyMap.begin()->second.preAuthorizationInfo;
    }
    return cache.bundlePolicy.preAuthorizationInfo;
}

// Full-verify every hap in the list, then check cross-hap consistency.
int32_t VerifyHapList(const BundleHapList& list, std::vector<TrustedBundleInfoInner>& bundleInfos,
    HapVerifyResultInfo& resultInfo)
{
    for (size_t i = 0; i < list.hapPaths.size(); ++i) {
        TrustedBundleInfoInner infoInner;
        bool isChanged = false;
        int32_t ret = HapSignVerifyManager::GetInstance().CheckHapsSignInfo(
            HapSignVerifyManager::MakeVerifyParams(list.hapPaths[i], Security::Verify::VerifyType::All,
                list.userIdForEnterpriseSign),
            false, infoInner, isChanged);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Sign check ret=%{public}d, path=%{public}s",
                ret, list.hapPaths[i].c_str());
            resultInfo.index = i;
            resultInfo.errorCode = ret;
            return ERR_HAP_SIGN_VERIFY_FAILED;
        }
        bundleInfos.emplace_back(infoInner);
    }

    int32_t ret = HapSignVerifyManager::GetInstance().CheckMultipleHaps(bundleInfos);
    if (ret != RET_SUCCESS) {
        // failure details are logged inside CheckMultipleHaps
        return ERR_CHECK_MULTIPLE_HAP_FAILED;
    }
    return RET_SUCCESS;
}
}

InstallSessionManager* InstallSessionManager::implInstance_ = nullptr;
std::mutex InstallSessionManager::mutex_;
inline std::string GetPlaceholderModuleName(int32_t index)
{
    return "#" + std::to_string(index);
}

inline bool IsPlaceholderModuleName(const std::string& moduleName)
{
    size_t moduleNameMinSize = 2; // placeholder module name should be at least 2 characters, e.g. "#0"
    if (moduleName.size() < moduleNameMinSize || moduleName.front() != '#') {
        return false;
    }
    return std::all_of(moduleName.begin() + 1, moduleName.end(), [](unsigned char ch) {
        return std::isdigit(ch) != 0;
    });
}

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

void InstallSessionManager::InitPermissionList(const BundleParam& bundleParam, HapPolicy& policy,
    std::vector<GenericValues>* undefValues)
{
    std::vector<PermissionStatus> initializedList;
    HapInfoCheckResult result;
    std::vector<GenericValues> localUndefValues;
    (void)PermissionManager::GetInstance().InitPermissionList(
        bundleParam, policy, initializedList, result, localUndefValues);
    policy.permStateList = initializedList;
    if (undefValues != nullptr) {
        undefValues->insert(undefValues->end(), localUndefValues.begin(), localUndefValues.end());
    }
}

bool InstallSessionManager::ShouldSkipPermInheritance(
    const BundleParam& bundleParam, const HapPolicy& policy, AccessTokenAttr oldAttr)
{
    return (bundleParam.isDebug && policy.isDebugGrant) || (!bundleParam.isDebug && (oldAttr & DEBUG_APP_FLAG));
}

void InstallSessionManager::MergePermission(std::vector<BriefPermData>& newPerms,
    const std::vector<BriefPermData>& oldPerms, bool skipInheritance)
{
    for (auto& newPerm : newPerms) {
        auto iter = std::find_if(oldPerms.begin(), oldPerms.end(), [newPerm](const BriefPermData& oldPermData) {
            return newPerm.permCode == oldPermData.permCode;
        });
        if (iter != oldPerms.end()) {
            // PERMISSION_FIXED_BY_ADMIN_POLICY | PERMISSION_RESTRICTED_BY_ADMIN need inheritance.
            if (skipInheritance && (iter->flag & ADMIN_CONTROLLED_FLAGS) == 0) {
                continue;
            }
            PermissionDataBrief::GetInstance().UpdatePermStatus(*iter, newPerm);
        }
    }
}

int32_t InstallSessionManager::MergeBundleInfos(InstallCache& cache, std::vector<std::string>& paths,
    std::vector<std::vector<uint8_t>>& persistDatas)
{
    std::vector<TrustedBundleInfoInner> bundleInfos;
    int32_t ret = HapSignVerifyManager::FastVerify(paths, persistDatas, bundleInfos,
        cache.list.userIdForEnterpriseSign);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    // FastVerify's contract: on success paths, persistDatas and bundleInfos are
    // strictly equal in length (paired erase/emplace inside), so indexing both
    // vectors by the same i needs no extra bound check.
    for (size_t i = 0; i < paths.size(); i++) {
        if (!HasModule(cache.bundleInfos, bundleInfos[i].GetModuleName())) {
            cache.bundleInfos.emplace_back(bundleInfos[i]);
            cache.oldModulePaths.emplace_back(paths[i]);
        }
    }

    ret = HapSignVerifyManager::GetInstance().CheckMultipleHaps(cache.bundleInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "CheckMultipleHaps failed ret=%{public}d", ret);
        return ERR_CHECK_MULTIPLE_HAP_FAILED;
    }
    return RET_SUCCESS;
}

void InstallSessionManager::ClearTimeoutSession()
{
    std::vector<std::pair<InstallCache, int64_t>> timeoutSessions;
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        int64_t nowMs = TimeUtil::GetCurrentTimestamp();
        for (auto it = sessionToInstallCache.begin(); it != sessionToInstallCache.end();) {
            if (nowMs - it->second.createdMs < SESSION_TIMEOUT_MS) {
                ++it;
                continue;
            }
            LOGW(ATM_DOMAIN, ATM_TAG, "Install session %{public}d overtime", it->first);
            timeoutSessions.emplace_back(it->second, nowMs - it->second.createdMs);
            it = sessionToInstallCache.erase(it);
        }
    }
    // report and rollback outside cacheMutex_: HiSysEvent write and id release
    // must not run under the session lock
    for (auto& [cache, duration] : timeoutSessions) {
        // same id release as the proxy-death cleanup path, otherwise the ids
        // acquired by a timed-out session leak in the id manager sets
        InstallIdentityManager::RollbackIdentity(cache);
        InstallSysEventReporter::ReportSessionTimeout(cache, duration);
    }
}

bool InstallSessionManager::EnsureBundleTokenIdsLoaded(InstallCache& cache)
{
    if (cache.bundleTokenIdsLoaded) {
        return true;
    }
    std::vector<GenericValues> hapTokenResults;
    int32_t ret = InstallDbRepository::QueryBundleTokens(cache.bundleParam.bundleName, cache, hapTokenResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Query bundle tokens failed, ret=%{public}d", ret);
        return false;
    }
    return true;
}

// Bundle-level pre-authorization for this update round. Pre-authorization is
// identical for all tokens of one bundle, so take it from any policy BMS passed
void InstallSessionManager::SupplementUpdateInfo(InstallCache& cache)
{
    // The DB snapshot is only a candidate set; token validity is still filtered
    // in real time by the ACTIVE memory query below.
    if (!EnsureBundleTokenIdsLoaded(cache) || cache.bundleTokenIdList.empty()) {
        return;
    }
    std::vector<PreAuthorizationInfo> preAuth = GetBundlePreAuthorization(cache);
    for (auto tokenId : cache.bundleTokenIdList) {
        if (cache.updatedBundlePolicyMap.find(tokenId) == cache.updatedBundlePolicyMap.end()) {
            std::shared_ptr<HapTokenInfoInner> infoPtr =
                AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
            if (infoPtr == nullptr) {
                LOGW(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", tokenId);
                continue;
            }
            BundlePolicy bundlePolicy;
            // bundle-level pre-authorization of this update round (see above)
            bundlePolicy.preAuthorizationInfo = preAuth;
            // isDebugGrant may differ between tokens of one bundle, take a conservative false
            bundlePolicy.isDebugGrant = false;
            // DLP identity never changes during update, keep the token's old value
            // for DLP permission handling in CreateUpdateHapInfo
            bundlePolicy.dlpType = static_cast<DlpType>(infoPtr->GetDlpType());
            cache.updatedBundlePolicyMap[tokenId] = bundlePolicy;
            cache.updatedUidStateMap[tokenId] = {infoPtr->GetUid(), false};
        }
    }
}

int32_t InstallSessionManager::InitDlpPermission(const HapBaseInfo& baseInfo, MultipleMode mode,
    HapPolicy& policy)
{
    HapInfoParams params;
    params.userID = baseInfo.userID;
    params.bundleName = baseInfo.bundleName;
    std::vector<PermissionStatus> initializedList;
    std::vector<GenericValues> undefValues;
    if (!PermissionManager::GetInstance().InitDlpPermissionList(params, mode, initializedList,
        undefValues)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "InitDlpPermission failed");
        return ERR_PERM_REQUEST_CFG_FAILED;
    }
    policy.permStateList = initializedList;
    return RET_SUCCESS;
}

static void FillExtendedPerm(const HapPolicy& policy, std::vector<PermissionWithValue>& extPerms)
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

// Restore inherited permission states of the reserved token from db and merge them into
// the new permission list according to inheritance rules. Admin fixed permissions are
// kept even when debug/release switch skips inheritance.
int32_t InstallSessionManager::MergeReservedPermState(const InstallCache& cache, const HapPolicy& policy,
    std::vector<BriefPermData>& newPerms)
{
    bool skipPermInheritance = ShouldSkipPermInheritance(cache.bundleParam, policy, cache.oldAttr);
    std::vector<BriefPermData> oldPerms;
    int32_t ret = InstallDbRepository::BuildPermStateByTokenId(cache.oldTokenId, oldPerms);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "BuildPermStateByTokenId failed, ret=%{public}d", ret);
        return ret;
    }
    MergePermission(newPerms, oldPerms, skipPermInheritance);
    return RET_SUCCESS;
}

int32_t InstallSessionManager::AllocHapInfo(const InstallCache& cache, FinishContext& context)
{
    HapPolicy policy = cache.policy;
    policy.preAuthorizationInfo = cache.bundlePolicy.preAuthorizationInfo;
    policy.isDebugGrant = cache.bundlePolicy.isDebugGrant;
    policy.dlpType = cache.bundlePolicy.dlpType;

    if (policy.dlpType == DLP_COMMON) {
        InitPermissionList(cache.bundleParam, policy, &context.undefValues);
    } else {
        int32_t ret = InitDlpPermission(cache.baseInfo, cache.mode, policy);
        if (ret != RET_SUCCESS) {
            return ret;
        }
#ifdef SUPPORT_SANDBOX_APP
        DlpPermissionSetManager::GetInstance().FilterPermState(policy.dlpType, policy.permStateList);
#endif
    }

    std::vector<BriefPermData> newPerms;
    PermissionDataBrief::BuildPermissionBriefDataList(policy.permStateList, newPerms);

    std::vector<PermissionWithValue> newExtPerms;
    FillExtendedPerm(policy, newExtPerms);

    if (cache.reserved == ReservedType::RESERVED_DATA) {
        int32_t ret = MergeReservedPermState(cache, policy, newPerms);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "MergeReservedPermState failed, ret=%{public}d", ret);
            return ret;
        }
    }

    HapTokenInfo tokenInfo;
    AccessTokenInfoUtils::BuildHapTokenInfo(cache.identity, cache.bundleParam, tokenInfo);
    tokenInfo.dlpType = policy.dlpType;
    tokenInfo.instIndex = cache.baseInfo.instIndex;

    context.hapInfos.emplace_back(BuildInstallHapInfo(cache, tokenInfo));
    context.permBriefDataLists.emplace_back(std::move(newPerms));
    context.extendPermLists.emplace_back(newExtPerms);
    context.oldPermList.emplace_back(nullptr);

    return RET_SUCCESS;
}

// Build the final permission list for one updated token. Order matters: grant states are
// initialized from the new package policy first (pre-authorization / system grant), then
// grants not available to a DLP app are filtered, and finally old grant states are
// inherited per the update rules.
std::vector<BriefPermData> InstallSessionManager::BuildUpdatedPermList(
    const BundleParam& bundleParam, const BundlePolicy& bundlePolicy, AccessTokenAttr oldAttr,
    HapPolicy& newPolicy, const std::vector<BriefPermData>& oldPermList,
    std::vector<GenericValues>* undefValues)
{
    InitPermissionList(bundleParam, newPolicy, undefValues);
#ifdef SUPPORT_SANDBOX_APP
    // DLP app: filter out granted permissions not available to this dlpType
    if (bundlePolicy.dlpType != DLP_COMMON) {
        DlpPermissionSetManager::GetInstance().FilterPermState(bundlePolicy.dlpType, newPolicy.permStateList);
    }
#endif
    std::vector<BriefPermData> newPerms;
    PermissionDataBrief::BuildPermissionBriefDataList(newPolicy.permStateList, newPerms);

    bool skipInheritance = ShouldSkipPermInheritance(bundleParam, newPolicy, oldAttr);
    MergePermission(newPerms, oldPermList, skipInheritance);

    return newPerms;
}

// Session-level token resolution (single entry of the update chain):
// - ACTIVE: return the live object from the InfoManager active cache; it never
//   enters the session cache.
// - UNTRUSTED / RESERVED: load a DB snapshot and store it in the session cache
//   on first load for reuse.
// - Unknown token (INVALID / dirty row): return nullptr without touching the DB.
std::shared_ptr<HapTokenInfoInner> InstallSessionManager::GetHapTokenInfoForInstall(
    InstallCache& cache, AccessTokenID tokenId)
{
    auto it = cache.untrustedTokenInfoMap.find(tokenId);
    if (it != cache.untrustedTokenInfoMap.end()) {
        return it->second;
    }
    TokenIdStatus status = TokenIdStatus::ACTIVE;
    std::shared_ptr<HapTokenInfoInner> inner =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoAndStatus(tokenId, status);
    if (inner == nullptr || status == TokenIdStatus::ACTIVE) {
        return inner;
    }
    cache.untrustedTokenInfoMap[tokenId] = inner;
    return inner;
}

int32_t InstallSessionManager::CreateUpdateHapInfo(InstallCache& cache, FinishContext& context)
{
    for (const auto& [tokenId, bundlePolicy] : cache.updatedBundlePolicyMap) {
        std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoForInstall(cache, tokenId);
        if (infoPtr == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is invalid.", tokenId);
            continue;
        }

        // bundlePolicy here has two sources:
        // 1. Tokens updated explicitly by BMS via UpdateHapPolicy: the policy BMS passed in.
        // 2. Tokens supplemented by SupplementUpdateInfo.
        // cache.policy comes from profile without preAuth/isDebugGrant.
        HapPolicy newPolicy = cache.policy;
        newPolicy.preAuthorizationInfo = bundlePolicy.preAuthorizationInfo;
        newPolicy.isDebugGrant = bundlePolicy.isDebugGrant;

        // Old permission states: the brief cache first; DB-snapshot tokens
        // loaded by GetHapTokenInfoForInstall are not registered in the brief
        // cache, so backfill from db (same as the reserved-data path) to keep
        // their granted states across the update instead of resetting them.
        std::vector<BriefPermData> oldPermList;
        if (PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(tokenId, oldPermList) != RET_SUCCESS) {
            int32_t ret = InstallDbRepository::BuildPermStateByTokenId(tokenId, oldPermList);
            if (ret != RET_SUCCESS) {
                LOGE(ATM_DOMAIN, ATM_TAG, "BuildPermStateByTokenId failed, tokenId=%{public}u, ret=%{public}d",
                    tokenId, ret);
                return ret;
            }
        }

        std::vector<BriefPermData> permBriefDataList = BuildUpdatedPermList(
            cache.bundleParam, bundlePolicy, infoPtr->GetAttr(), newPolicy, oldPermList,
            &context.undefValues);

        HapTokenInfo tokenInfo = infoPtr->GetHapInfoBasic();
        tokenInfo.tokenAttr = InstallIdentityManager::BuildTokenAttr(cache.bundleParam);
        tokenInfo.apiVersion = HapTokenInfoInner::GetApiVersion(cache.bundleParam.apiVersion);
        auto it = cache.updatedUidStateMap.find(tokenId);
        if (it != cache.updatedUidStateMap.end()) {
            tokenInfo.uid = it->second.uid;
        }
        
        std::vector<PermissionWithValue> extPerms;
        FillExtendedPerm(newPolicy, extPerms);

        context.hapInfos.emplace_back(BuildInstallHapInfo(cache, tokenInfo));
        context.permBriefDataLists.emplace_back(std::move(permBriefDataList));
        context.extendPermLists.emplace_back(std::move(extPerms));
        context.oldPermList.emplace_back(std::make_shared<std::vector<BriefPermData>>(std::move(oldPermList)));
    }
    return RET_SUCCESS;
}

static bool HasInstalled(const HapBaseInfo& baseInfo)
{
    AccessTokenIDEx idEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(
        baseInfo.userID, baseInfo.bundleName, baseInfo.instIndex);
    return idEx.tokenIDEx != 0;
}

void InstallSessionManager::RefreshCache(const InstallCache& cache, const FinishContext& context)
{
    size_t index = 0;
    if (cache.HasNewIdentity()) {
        HapTokenInfoItem hapInfoItem = BuildHapTokenInfoItem(context.hapInfos[index]);
        AccessTokenInfoManager::GetInstance().CommitCreateHapCache(
            hapInfoItem, context.permBriefDataLists[index], context.extendPermLists[index]);
        index++;
    }

    for (size_t i = index; i < context.hapInfos.size(); ++i) {
        // the sticky flags were resolved once at FillFinishContext and already
        // cover the "uid adopted from caller" and "prior migrated state" cases
        HapTokenInfoItem hapInfoItem = BuildHapTokenInfoItem(context.hapInfos[i]);
        AccessTokenInfoManager::GetInstance().CommitUpdateHapCache(
            hapInfoItem, context.permBriefDataLists[i], context.extendPermLists[i]);
    }
    InstallIdentityManager::CommitIdentity(cache, context);
}

void InstallSessionManager::RollbackAll(int32_t sessionId, int32_t sceneCode, int32_t errorCode, AccessTokenID tokenId,
    bool eraseCache)
{
    auto it = sessionToInstallCache.find(sessionId);
    if (it == sessionToInstallCache.end()) {
        return;
    }
    if (errorCode != RET_SUCCESS) {
        InstallSysEventReporter::ReportSessionError(it->second, sceneCode, errorCode, tokenId);
    }
    InstallIdentityManager::RollbackIdentity(it->second);
    if (eraseCache) {
        int32_t callerPid = it->second.callerPid;
        sessionToInstallCache.erase(sessionId);
        ReleaseDeathStub(callerPid);
    }
}

void InstallSessionManager::CreateSessionEntry(InstallCache& cache, const sptr<IRemoteObject>& cb,
    const std::string& bundleName, int32_t& sessionId)
{
    ProcessProxyDeathStub(cb);

    std::lock_guard<std::mutex> lock(cacheMutex_);
    sessionId = ++sessionCnt;
    cache.callerPid = IPCSkeleton::GetCallingPid();
    cache.ipcCode = IPC_CHECK_HAP_SIGN_INFO;
    cache.createdMs = TimeUtil::GetCurrentTimestamp();
    sessionToInstallCache[sessionId] = cache;
    LOGI(ATM_DOMAIN, ATM_TAG, "sessionId=%{public}d, bundle=%{public}s", sessionId, bundleName.c_str());
}

int32_t InstallSessionManager::CheckHapSignInfo(const BundleHapList& list, const sptr<IRemoteObject>& cb,
    int32_t& sessionId, std::vector<TrustedBundleInfo>& bundleInfo, HapVerifyResultInfo& resultInfo,
    uint32_t flag)
{
    ClearTimeoutSession();

    if (list.hapPaths.empty() || !DataValidator::IsSignInfoQueryFlagValid(flag)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Paths size=%{public}zu, flag=%{public}u.", list.hapPaths.size(), flag);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    InstallCache cache;

    int32_t ret = VerifyHapList(list, cache.bundleInfos, resultInfo);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    HapSignVerifyManager::GetInstance().ConvertTrustedBundleInfo(cache.bundleInfos, bundleInfo, flag);

    cache.list = list;
    CreateSessionEntry(cache, cb, cache.bundleInfos.front().GetBundleName(), sessionId);
    return RET_SUCCESS;
}

int32_t InstallSessionManager::CheckInstallType(std::vector<std::string>& installedPaths, InstallTypeEnum type)
{
    if (!installedPaths.empty() && type == InstallTypeEnum::TYPE_INSTALL) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Already has data, type:0");
        return ERR_BUNDLE_ALREADY_EXIST;
    }

    if (installedPaths.empty() &&
        (type == InstallTypeEnum::TYPE_MERGE || type == InstallTypeEnum::TYPE_REPLACE)) {
        LOGW(ATM_DOMAIN, ATM_TAG, "No data, type:%{public}d", static_cast<int32_t>(type));
    }

    return RET_SUCCESS;
}

int32_t InstallSessionManager::PrepareInstalledBundleInfo(int32_t sessionId, InstallCache& cache, InstallTypeEnum type)
{
    std::vector<std::string> installedPaths;
    std::vector<std::vector<uint8_t>> persistDatas;
    int32_t ret = InstallDbRepository::GetInstalledBundleInfo(
        cache.bundleInfos.front().GetBundleName(), cache.mode, installedPaths, persistDatas);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get hap info failed ret=%{public}d", ret);
        RollbackAll(sessionId, InstallHapSceneCode::GET_HAP_PATH, ret, 0);
        return ret;
    }

    ret = CheckInstallType(installedPaths, type);
    if (ret != RET_SUCCESS) {
        // keep the session alive for a same-session retry with a corrected type;
        // nothing is allocated at this stage so the identity rollback is a no-op
        RollbackAll(sessionId, InstallHapSceneCode::CHECK_TYPE, ret, 0, false);
        return ret;
    }

    if (type == InstallTypeEnum::TYPE_MERGE && !installedPaths.empty()) {
        ret = MergeBundleInfos(cache, installedPaths, persistDatas);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Merge bundle infos failed ret=%{public}d", ret);
            RollbackAll(sessionId, InstallHapSceneCode::REBUILD_HAP_POLICY, ret, 0);
            return ret;
        }
    }
    return RET_SUCCESS;
}

int32_t InstallSessionManager::CheckHapPermissionInfo(
    int32_t sessionId, InstallTypeEnum type, MultipleMode mode, HapInfoCheckResult& result)
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    if (sessionToInstallCache.find(sessionId) == sessionToInstallCache.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "sessionId %{public}d not exist", sessionId);
        return AccessTokenError::ERR_SESSION_NOT_EXIST;
    }
    // install mode must be within the same mode domain ({0,1}); CURRENT_MODE
    // is a query-only sentinel; DataValidator logs the invalid value
    if (!DataValidator::IsInstallModeValid(mode)) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    InstallCache& cache = sessionToInstallCache[sessionId];
    cache.type = type;
    cache.mode = mode;
    cache.ipcCode = IPC_CHECK_HAP_PERMISSION_INFO;

    if (cache.bundleInfos.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "bundleInfos is empty");
        return ERR_PARAM_INVALID;
    }

    int32_t ret = PrepareInstalledBundleInfo(sessionId, cache, type);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    ret = HapSignVerifyManager::GetInstance().BuildHapPolicy(cache.bundleInfos, cache.policy, cache.bundleParam);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "BuildHapPolicy failed ret=%{public}d", ret);
        RollbackAll(sessionId, InstallHapSceneCode::BUILD_HAP_POLICY, ret, 0);
        return AccessTokenError::ERR_BUILD_POLICY_FAILED;
    }
    
    if (!PermissionConstraintCheck::CheckAclAndEdm(cache.bundleParam, cache.policy, result)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "CheckAclAndEdm failed.");
        RollbackAll(sessionId, InstallHapSceneCode::CHECK_PERMISSION_LIST,
            AccessTokenError::ERR_CHECK_ACL_OR_EDM_FAILED, 0);
        return AccessTokenError::ERR_CHECK_ACL_OR_EDM_FAILED;
    }
    cache.hasPermChecked = true;
    return RET_SUCCESS;
}

static bool TryKernelPolicyRestore(const std::string& bundleName, const BundlePolicy& bundlePolicy,
    InstallCache& cache)
{
    if (!PermissionKernelUtils::IsKernelSupportSpm()) {
        return false;
    }
    int32_t ret = AccessTokenInfoManager::GetInstance().RestoreInstallPolicyFromKernel(
        bundleName, cache.mode, bundlePolicy, cache.bundleParam, cache.policy);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get policy from spm failed ret=%{public}d", ret);
        return false;
    }
    ret = InstallDbRepository::GetAppIdFromDb(
        cache.bundleParam.bundleName, cache.mode, cache.bundleParam.appId);
    if (ret != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Backfill appId failed ret=%{public}d, fallback to db verify.", ret);
        return false;
    }
    return true;
}

int32_t InstallSessionManager::FillInstallPolicy(
    const std::string& bundleName, const BundlePolicy& bundlePolicy, InstallCache& cache)
{
    if (TryKernelPolicyRestore(bundleName, bundlePolicy, cache)) {
        return RET_SUCCESS;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Kernel not supported or load failed, fallback to db verify");

    std::vector<std::string> hapPaths;
    std::vector<std::vector<uint8_t>> persistDatas;
    int32_t ret = InstallDbRepository::GetInstalledBundleInfo(bundleName, cache.mode, hapPaths, persistDatas);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get installed bundle info failed ret=%{public}d", ret);
        return ret;
    }
    if (hapPaths.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Bundle %{public}s not exist", bundleName.c_str());
        return ERR_BUNDLE_NOT_EXIST;
    }

    std::vector<TrustedBundleInfoInner> bundleInfos;
    ret = HapSignVerifyManager::FastVerify(hapPaths, persistDatas, bundleInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "FastVerify failed ret=%{public}d", ret);
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
    const sptr<IRemoteObject>& cb, int32_t& sessionId, const Identity& desired)
{
    InstallCache cache;
    cache.baseInfo = info;
    cache.mode = MultipleModeUtils::GetTokenMode(info.instIndex);

    if (desired.tokenId != 0 && desired.uid != INVALID_UID) {
        if (AccessTokenIDManager::ExtractUserId(desired.uid) != info.userID) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Desired uid %{public}d user segment mismatch with user %{public}d.",
                desired.uid, info.userID);
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        cache.repairedIdentity = desired;
    }
    int32_t ret = FillInstallPolicy(info.bundleName, policy, cache);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    cache.hasPermChecked = true;

    CreateSessionEntry(cache, cb, info.bundleName, sessionId);
    return RET_SUCCESS;
}

int32_t InstallSessionManager::ValidatePreExistingSession(const InstallCache& cache, const HapBaseInfo& info)
{
    if (cache.HasNewIdentity()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Already prepare");
        return AccessTokenError::ERR_ALREADY_PREPARE;
    }
    if (!cache.hasPermChecked) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Not check permission!");
        return AccessTokenError::ERR_NOT_CHECK_PERMISSION;
    }
    // the prepare target must be consistent with the sign-verified bundle:
    // token-allocatable bundle type and matching bundleName. Merge-appended
    // sessions keep the verified entry at the front.
    if (cache.bundleInfos.empty()) {
        return RET_SUCCESS;
    }
    const TrustedBundleInfoInner& verified = cache.bundleInfos.front();
    if (!IsTokenAllocatableType(verified.GetBundleType())) {
        LOGC(ATM_DOMAIN, ATM_TAG, "BundleType %{public}d doesn`t need tokenID",
            static_cast<int32_t>(verified.GetBundleType()));
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (info.bundleName != verified.GetBundleName()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "BundleName %{public}s mismatch with verified bundle %{public}s.",
            info.bundleName.c_str(), verified.GetBundleName().c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return RET_SUCCESS;
}

int32_t InstallSessionManager::PrepareSessionIdentity(int32_t sessionId, const HapBaseInfo& info,
    const BundlePolicy& policy, Identity& identity, bool sessionCreatedInPrepare)
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    auto it = sessionToInstallCache.find(sessionId);
    if (it == sessionToInstallCache.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "sessionId %{public}d not exist", sessionId);
        return AccessTokenError::ERR_SESSION_NOT_EXIST;
    }
    InstallCache& cache = it->second;
    if (!sessionCreatedInPrepare) {
        int32_t ret = ValidatePreExistingSession(cache, info);
        if (ret != RET_SUCCESS) {
            RollbackAll(sessionId, InstallHapSceneCode::PREPARE_IDENTITY, ret, 0);
            return ret;
        }
    }
    cache.baseInfo = info;
    // the prepare target must be within the session's mode domain (mode is
    // bound at CheckHapSignInfo, or derived from instIndex in the repair path)
    if (!MultipleModeUtils::IsModeInstIndexMatch(static_cast<int32_t>(cache.mode), info.instIndex)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Session mode %{public}d mismatch with instIndex %{public}d.",
            static_cast<int32_t>(cache.mode), info.instIndex);
        RollbackAll(sessionId, InstallHapSceneCode::PREPARE_IDENTITY, AccessTokenError::ERR_PARAM_INVALID, 0);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    int32_t ret = InstallIdentityManager::GetTokenIdAndUid(cache, policy);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetTokenIdAndUid failed ret=%{public}d", ret);
        RollbackAll(sessionId, InstallHapSceneCode::PREPARE_IDENTITY, ret, 0);
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
        int32_t ret = CreateInstallSession(info, policy, cb, sessionId, identity);
        if (ret != RET_SUCCESS) {
            return ret;
        }
        // The session was created in this prepare call, the pre-existing-session validations are skipped.
        return PrepareSessionIdentity(sessionId, info, policy, identity, true);
    }

    return PrepareSessionIdentity(sessionId, info, policy, identity, false);
}

int32_t CheckUpdateTargetMatch(const InstallCache& cache, AccessTokenID tokenId,
    const std::shared_ptr<HapTokenInfoInner>& infoPtr, int32_t uid)
{
    if (infoPtr->GetBundleName() != cache.bundleParam.bundleName) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Token %{public}u is not match bundleName.", tokenId);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (uid != INVALID_UID && AccessTokenIDManager::ExtractUserId(uid) != infoPtr->GetUserID()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Uid %{public}d doesn't match token user %{public}d.", uid, infoPtr->GetUserID());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return RET_SUCCESS;
}

int32_t InstallSessionManager::UpdateHapPolicy(
    int32_t sessionId, AccessTokenIDEx& tokenIdEx, const BundlePolicy& policy, int32_t& uid)
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    // low 32 bits carry the plain token id: the update target (unchanged logic)
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    if (!migrationDone_.load()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Migration not completed");
        RollbackAll(sessionId,
            InstallHapSceneCode::UPDATE_HAP_POLICY, AccessTokenError::ERR_MIGRATION_COMPLETED, tokenId);
        return AccessTokenError::ERR_MIGRATION_COMPLETED;
    }
    auto it = sessionToInstallCache.find(sessionId);
    if (it == sessionToInstallCache.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "sessionId %{public}d not exist", sessionId);
        return AccessTokenError::ERR_SESSION_NOT_EXIST;
    }
    if (!it->second.hasPermChecked) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Not check permission!");
        RollbackAll(sessionId,
            InstallHapSceneCode::UPDATE_HAP_POLICY, AccessTokenError::ERR_NOT_CHECK_PERMISSION, tokenId);
        return AccessTokenError::ERR_NOT_CHECK_PERMISSION;
    }
    if (AccessTokenIDManager::GetInstance().IsReservedTokenId(tokenId)) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Token %{public}u in reserved list", tokenId);
        RollbackAll(sessionId, InstallHapSceneCode::UPDATE_HAP_POLICY, AccessTokenError::ERR_PARAM_INVALID, tokenId);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    std::shared_ptr<HapTokenInfoInner> infoPtr = GetHapTokenInfoForInstall(it->second, tokenId);
    if (infoPtr == nullptr) {
        // caller re-create the missing token via a repair PrepareHapIdentity session
        LOGW(ATM_DOMAIN, ATM_TAG, "Token %{public}u not exist in ATM, skip update, sessionId=%{public}d, "
            "bundle=%{public}s.", tokenId, sessionId, it->second.bundleParam.bundleName.c_str());
        // report-only, no RollbackAll: the session keeps.
        InstallSysEventReporter::ReportSessionError(it->second, InstallHapSceneCode::UPDATE_HAP_POLICY,
            AccessTokenError::ERR_TOKENID_NOT_EXIST, tokenId);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    int32_t ret = CheckUpdateTargetMatch(it->second, tokenId, infoPtr, uid);
    if (ret != RET_SUCCESS) {
        RollbackAll(sessionId, InstallHapSceneCode::UPDATE_HAP_POLICY, ret, tokenId);
        return ret;
    }

    bool isNewBundleId = false;
    bool fromCaller = false;
    ret = InstallIdentityManager::ResolveUpdateUid(uid, infoPtr, isNewBundleId, fromCaller);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Check uid failed, ret=%{public}d", ret);
        RollbackAll(sessionId, InstallHapSceneCode::UPDATE_HAP_POLICY, AccessTokenError::ERR_INVALID_UID, tokenId);
        return ret;
    }

    it->second.updatedBundlePolicyMap[tokenId] = policy;
    it->second.updatedUidStateMap[tokenId] = {uid, isNewBundleId, fromCaller};
    // refresh the high 32 bits (token attr) with the value this upgrade applies
    // at FinishInstall; the plain token id itself never changes in the update flow
    tokenIdEx.tokenIdExStruct.tokenAttr = InstallIdentityManager::BuildTokenAttr(it->second.bundleParam);
    return RET_SUCCESS;
}

int32_t InstallSessionManager::FillFinishContext(InstallCache& cache, FinishContext& context)
{
    if (cache.HasNewIdentity()) {
        if (HasInstalled(cache.baseInfo)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Get cache by install info");
            return AccessTokenError::ERR_ALREADY_FINISH_INSTALL;
        }

        int32_t ret = AllocHapInfo(cache, context);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Alloc hap info failed, ret=%{public}d", ret);
            return ret;
        }
    }

    return CreateUpdateHapInfo(cache, context);
}

void InstallSessionManager::BuildSpmKernelParams(const InstallCache& cache, const FinishContext& ctx,
    std::vector<SpmDataParam>& addParams, std::vector<SpmDataParam>& updateParams)
{
    size_t startIndex = 0;
    if (cache.HasNewIdentity()) {
        startIndex = 1;
        addParams.emplace_back(SpmDataParam{ctx.hapInfos.front().baseInfo, ctx.noCachedInfo,
            ctx.permBriefDataLists.front(), ctx.extendPermLists.front(), nullptr, true});
    }

    for (size_t i = startIndex; i < ctx.hapInfos.size(); ++i) {
        if (KernelDetail::IsSpmDataExists(ctx.hapInfos[i].baseInfo.tokenID)) {
            std::vector<BriefPermData>* oldPermPtr = (i < ctx.oldPermList.size()) && (ctx.oldPermList[i] != nullptr) ?
                ctx.oldPermList[i].get() : nullptr;
            updateParams.emplace_back(SpmDataParam{ctx.hapInfos[i].baseInfo, ctx.noCachedInfo,
                ctx.permBriefDataLists[i], ctx.extendPermLists[i], oldPermPtr, true});
        } else if (ctx.hapInfos[i].baseInfo.uid != INVALID_UID) { // uid -1 don't add
            addParams.emplace_back(SpmDataParam{ctx.hapInfos[i].baseInfo, ctx.noCachedInfo,
                ctx.permBriefDataLists[i], ctx.extendPermLists[i], nullptr, true});
        }
    }
}

int32_t InstallSessionManager::StageSpmKernelTasks(const InstallCache& cache, const FinishContext& ctx,
    KernelAndDBWriteTransaction& txn)
{
    std::vector<SpmDataParam> addParams;
    std::vector<SpmDataParam> updateParams;
    BuildSpmKernelParams(cache, ctx, addParams, updateParams);

    if (!addParams.empty()) {
        int32_t ret = txn.StageKernelAdd(addParams);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Stage kernel add failed, ret=%{public}d", ret);
            return ERR_KERNEL_OPERATION_FAILED;
        }
    }
    if (!updateParams.empty()) {
        int32_t ret = txn.StageKernelUpdate(updateParams);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Stage kernel update failed, ret=%{public}d", ret);
            return ERR_KERNEL_OPERATION_FAILED;
        }
    }
    return RET_SUCCESS;
}

int32_t InstallSessionManager::FinishInstallInner(InstallCache& cache,
    const std::map<std::string, std::string>& modulePathMap)
{
    FinishContext context;
    AccessTokenInfoUtils::BuildBundleFullInfo(cache.bundleParam, cache.policy, context.innerInfo, context.noCachedInfo);

    int32_t ret = FillFinishContext(cache, context);
    if (ret != RET_SUCCESS) {
        RollbackFinishedSession(cache, InstallHapSceneCode::FILL_FINISH_CONTEXT, ret, 0);
        return ret;
    }

    KernelAndDBWriteTransaction txn;
    ret = StageSpmKernelTasks(cache, context, txn);
    if (ret != RET_SUCCESS) {
        RollbackFinishedSession(cache, InstallHapSceneCode::EXECUTE_KERNEL_TASK, ret, 0);
        return ret; // transaction destructor rolls the executed kernel ops back
    }

    std::vector<AddInfo> addInfoVec;
    std::vector<DelInfo> delInfoVec;
    ret = InstallDbRepository::BuildDbOpsVec(cache, context, modulePathMap, addInfoVec, delInfoVec);
    if (ret != RET_SUCCESS) {
        RollbackFinishedSession(cache, InstallHapSceneCode::FINISH_DB_OPERATION, ret, 0);
        return ret;
    }
    ret = txn.CommitDb(delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        RollbackFinishedSession(cache, InstallHapSceneCode::FINISH_DB_OPERATION, ret, 0);
        return ret;
    }

    RefreshCache(cache, context);
    txn.Commit();
    // ---- outside the transaction: cross-module notifications and DFX reporting ----
#ifdef TOKEN_SYNC_ENABLE
    size_t notifyStart = cache.HasNewIdentity() ? 1 : 0;
    for (size_t i = notifyStart; i < context.hapInfos.size(); ++i) {
        TokenModifyNotifier::GetInstance().NotifyTokenModify(context.hapInfos[i].baseInfo.tokenID);
    }
#endif
    int64_t duration = TimeUtil::GetCurrentTimestamp() - cache.createdMs;
    InstallSysEventReporter::ReportSessionFinish(cache, duration, InstallHapSceneCode::SESSION_FINISH, 0);
    return RET_SUCCESS;
}

void InstallSessionManager::RollbackFinishedSession(InstallCache& cache, int32_t sceneCode, int32_t errorCode,
    AccessTokenID tokenId)
{
    InstallIdentityManager::RollbackIdentity(cache);
    if (errorCode != RET_SUCCESS) {
        InstallSysEventReporter::ReportSessionError(cache, sceneCode, errorCode, tokenId);
    }
}

int32_t InstallSessionManager::FinishInstall(int32_t sessionId, bool isPersistent,
    const std::map<std::string, std::string>& modulePathMap)
{
    InstallCache cache;
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);

        if (!migrationDone_.load()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Migration not completed");
            RollbackAll(sessionId, InstallHapSceneCode::FINISH_INSTALL, AccessTokenError::ERR_MIGRATION_COMPLETED, 0);
            return AccessTokenError::ERR_MIGRATION_COMPLETED;
        }

        auto it = sessionToInstallCache.find(sessionId);
        if (it == sessionToInstallCache.end()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "sessionId %{public}d not exist.", sessionId);
            return AccessTokenError::ERR_SESSION_NOT_EXIST;
        }
        InstallCache& sessionCache = it->second;
        sessionCache.ipcCode = IPC_FINISH_INSTALL;

        if (!isPersistent) {
            LOGI(ATM_DOMAIN, ATM_TAG, "No need persistent.");
            RollbackAll(sessionId, InstallHapSceneCode::FINISH_NOT_PERSISTENT, 0, 0);
            return RET_SUCCESS;
        }

        const bool hasCheckSign = !sessionCache.bundleInfos.empty();
        std::string bundleName = hasCheckSign ? sessionCache.bundleInfos.front().GetBundleName() :
            sessionCache.baseInfo.bundleName;
        LOGI(ATM_DOMAIN, ATM_TAG, "Start finish, sessionId=%{public}d, bundle=%{public}s",
            sessionId, bundleName.c_str());

        if (hasCheckSign && IsNonPersistentBundleType(sessionCache.bundleInfos.front().GetBundleType())) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Type %{public}d no need persistent.",
                sessionCache.bundleInfos.front().GetBundleType());
            RollbackAll(sessionId, InstallHapSceneCode::FINISH_NOT_PERSISTENT, 0, 0);
            return RET_SUCCESS;
        }

        if (!sessionCache.hasPermChecked) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Not check permission!");
            RollbackAll(sessionId, InstallHapSceneCode::FINISH_INSTALL, AccessTokenError::ERR_NOT_CHECK_PERMISSION, 0);
            return AccessTokenError::ERR_NOT_CHECK_PERMISSION;
        }

        if (hasCheckSign) {
            SupplementUpdateInfo(sessionCache);
        }

        // Take over the session: the kernel+db transaction below must run
        // outside cacheMutex_ (outermost-lock constraint of the transaction).
        cache = std::move(sessionCache);
        sessionToInstallCache.erase(sessionId);
        ReleaseDeathStub(cache.callerPid);
    }

    return FinishInstallInner(cache, modulePathMap);
}

int32_t InstallSessionManager::GetCacheSignInfoBySessionId(
    int32_t sessionId, std::vector<TrustedBundleInfo>& bundleInfo, uint32_t flag)
{
    if (!DataValidator::IsSignInfoQueryFlagValid(flag)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Query flag is invalid.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    std::lock_guard<std::mutex> lock(cacheMutex_);
    auto it = sessionToInstallCache.find(sessionId);
    if (it == sessionToInstallCache.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "sessionId %{public}d not exist", sessionId);
        return AccessTokenError::ERR_SESSION_NOT_EXIST;
    }

    // Contract: bundleInfos.size() >= list.hapPaths.size() (equal after
    // CheckHapSignInfo; MergeBundleInfos only appends afterwards), so the
    // first hapPaths.size() entries are the originally verified ones. Truncate
    // to the min anyway so a broken invariant degrades instead of UB.
    size_t signCount = std::min(it->second.bundleInfos.size(), it->second.list.hapPaths.size());
    HapSignVerifyManager::GetInstance().ConvertTrustedBundleInfo(
        std::vector<TrustedBundleInfoInner>(it->second.bundleInfos.begin(),
        it->second.bundleInfos.begin() + signCount), bundleInfo, flag);

    if (bundleInfo.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SessionId %{public}d bundleInfo is empty", sessionId);
        return ERR_PARAM_INVALID;
    }
    return RET_SUCCESS;
}

int32_t InstallSessionManager::GetCachePolicyBySessionId(int32_t sessionId, const std::string& bundleName,
    BundlePolicyInfo& bundlePolicyInfo)
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    auto it = sessionToInstallCache.find(sessionId);
    if (it == sessionToInstallCache.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "sessionId %{public}d not exist", sessionId);
        return AccessTokenError::ERR_SESSION_NOT_EXIST;
    }

    if (bundleName != it->second.bundleParam.bundleName) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Bundle %{public}s not match session bundle %{public}s",
            bundleName.c_str(), it->second.bundleParam.bundleName.c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    for (auto permState : it->second.policy.permStateList) {
        bundlePolicyInfo.reqPermissions.emplace_back(permState.permissionName);
    }
    return RET_SUCCESS;
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
            LOGI(ATM_DOMAIN, ATM_TAG, "Clear sessionId=%{public}d for pid=%{public}d, "
                "tokenId=%{public}u, uid=%{public}d", it->first, pid,
                static_cast<AccessTokenID>(it->second.identity.tokenId), it->second.identity.uid);
            RollbackAll(it->first, InstallHapSceneCode::PROXY_DEATH, RET_FAILED, 0, false);
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
