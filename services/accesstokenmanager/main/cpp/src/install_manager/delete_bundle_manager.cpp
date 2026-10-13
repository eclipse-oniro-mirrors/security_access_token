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

#include "delete_bundle_manager.h"

#include <set>

#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_dfx_define.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_info_utils.h"
#include "callback_manager.h"
#include "hisysevent_adapter.h"
#include "kernel_and_db_transaction.h"
#include "permission_change_notifier.h"
#include "permission_data_brief.h"
#include "token_field_const.h"
#include "tokenid_attributes.h"
#include "token_modify_notifier.h"
#include "user_policy_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
#ifdef SPM_DATA_ENABLE
namespace {
constexpr int32_t UNAVAILABLE_UID = -1;
const uint32_t TOKEN_RESERVED_FLAG = 0x0004;
} // namespace

DeleteBundleManager::DeleteBundleManager() = default;

DeleteBundleManager::~DeleteBundleManager() = default;

DeleteBundleManager& DeleteBundleManager::GetInstance()
{
    static DeleteBundleManager instance;
    return instance;
}

void DeleteBundleManager::GenerateHapTokenDelInfoVec(AccessTokenID tokenID,
    const std::string& bundleName, std::vector<DelInfo>& delInfoVec, bool includePermissionState)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));

    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, delInfoVec);

    if (includePermissionState) {
        AccessTokenInfoUtils::GenerateDelInfoToVec(
            AtmDataType::ACCESSTOKEN_PERMISSION_STATE, condition, delInfoVec);
    }

    AccessTokenInfoUtils::GenerateDelInfoToVec(
        AtmDataType::ACCESSTOKEN_PERMISSION_EXTEND_VALUE, condition, delInfoVec);
    AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_HAP_UNDEFINE_INFO, condition, delInfoVec);

    if (AccessTokenInfoUtils::IsSystemResource(bundleName)) {
        AccessTokenInfoUtils::GenerateDelInfoToVec(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, condition, delInfoVec);
    }
}

void DeleteBundleManager::BuildTokenRemoveDbOps(const std::shared_ptr<HapTokenInfoInner>& info, ReservedType type,
    std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec)
{
    AccessTokenID tokenID = info->GetTokenID();
    bool includePermissionState = (type != ReservedType::RESERVED_DATA);
    GenerateHapTokenDelInfoVec(tokenID, info->GetBundleName(), delInfoVec, includePermissionState);

    if (type == ReservedType::NONE) {
        return; // plain uninstall: the row is deleted, nothing is re-inserted
    }
    // Re-insert with the reserved flag; empty only for remote tokens, which
    // DeleteActiveAndUntrustedToken already rejects - defensive tail.
    std::vector<GenericValues> addValues;
    info->GenerateHapInfoValues("", APL_INVALID, addValues);
    if (addValues.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u generates no insert values.", tokenID);
        return;
    }
    addValues[0].Remove(TokenFiledConst::FIELD_TOKEN_ATTR);
    addValues[0].Put(TokenFiledConst::FIELD_TOKEN_ATTR,
        static_cast<int32_t>(info->GetAttr() | TOKEN_RESERVED_FLAG));
    addValues[0].Remove(TokenFiledConst::FIELD_RESERVED);
    addValues[0].Put(TokenFiledConst::FIELD_RESERVED, static_cast<int32_t>(type));
    if (type == ReservedType::RESERVED_IDENTITY) {
        // The uid is released back to the pool; the row keeps an unavailable one.
        addValues[0].Remove(TokenFiledConst::FIELD_UID);
        addValues[0].Put(TokenFiledConst::FIELD_UID, static_cast<int32_t>(UNAVAILABLE_UID));
    }
    AccessTokenInfoUtils::GenerateAddInfoToVec(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, addValues, addInfoVec);
}

void DeleteBundleManager::JudgeBundleCleanFromRows(const std::vector<GenericValues>& tokenResults,
    AccessTokenID targetTokenId, int32_t targetUid, ReservedType delType, BundleCleanPlan& plan)
{
    // Spec: the current token's post-transaction state is governed by delType
    // alone; a RESERVED_IDENTITY row stores uid=-1 (bundleId already released
    // at reserve time).
    bool needCleanBundleInfo = true;
    bool needCleanBundleId = (delType != ReservedType::RESERVED_DATA) && (targetUid != UNAVAILABLE_UID);
    int32_t bundleId = UNAVAILABLE_UID;
    (void)AccessTokenIDManager::GetInstance().ExtractBundleId(targetUid, bundleId);

    for (const auto& result : tokenResults) {
        if (static_cast<AccessTokenID>(result.GetInt(TokenFiledConst::FIELD_TOKEN_ID)) == targetTokenId) {
            continue;
        }
        if (AccessTokenInfoUtils::GetReservedTokenTypeDBValue(result) == ReservedType::NONE) {
            needCleanBundleInfo = false;
        }
        if (!needCleanBundleId) {
            continue;
        }
        int32_t curBundleId = 0;
        if (AccessTokenIDManager::GetInstance().ExtractBundleId(
            result.GetInt(TokenFiledConst::FIELD_UID), curBundleId) && (bundleId == curBundleId)) {
            needCleanBundleId = false;
        }
    }

    plan.cleanBundleInfo = needCleanBundleInfo;
    plan.cleanBundleId = needCleanBundleId;
}

int32_t DeleteBundleManager::JudgeBundleClean(AccessTokenID currentTokenId, const std::string& bundleName,
    int32_t currentUid, ReservedType delType, BundleCleanPlan& plan)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    std::vector<GenericValues> tokenResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, tokenResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to query tokens for bundle %{public}s.", bundleName.c_str());
        return ret;
    }
    JudgeBundleCleanFromRows(tokenResults, currentTokenId, currentUid, delType, plan);
    return RET_SUCCESS;
}

int32_t DeleteBundleManager::BuildBundleCleanDbOps(const std::shared_ptr<HapTokenInfoInner>& info,
    ReservedType delType, std::vector<DelInfo>& delInfoVec, BundleCleanPlan& plan)
{
    int32_t ret = JudgeBundleClean(info->GetTokenID(), info->GetBundleName(), info->GetUid(), delType, plan);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    if (!plan.cleanBundleInfo) {
        return RET_SUCCESS;
    }
    GenericValues packageCondition;
    packageCondition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, info->GetBundleName());
    AccessTokenInfoUtils::GenerateDelInfoToVec(
        AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, packageCondition, delInfoVec);
    return RET_SUCCESS;
}

int32_t DeleteBundleManager::BuildBundleDelDbOps(const std::string& bundleName,
    std::vector<AccessTokenID>& activeTokens, std::vector<AccessTokenID>& reservedTokens,
    std::vector<int32_t>& uids, std::vector<DelInfo>& delInfoVec)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    std::vector<GenericValues> tokenResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, tokenResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to query tokens for bundle %{public}s, err %{public}d.",
            bundleName.c_str(), ret);
        return ret;
    }

    activeTokens.clear();
    reservedTokens.clear();
    std::set<int32_t> uidSet;
    for (const auto& result : tokenResults) {
        AccessTokenID tokenID = static_cast<AccessTokenID>(result.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
        if (AccessTokenInfoUtils::GetReservedTokenTypeDBValue(result) == ReservedType::NONE) {
            activeTokens.emplace_back(tokenID);
        } else {
            reservedTokens.emplace_back(tokenID);
        }
        // Distinct valid uids (one per user) for the bundleId release.
        int32_t uid = result.GetInt(TokenFiledConst::FIELD_UID);
        if (uid >= 0) {
            uidSet.insert(uid);
        }
        // Complete (NONE-mode) deletion: includePermissionState follows the
        // deletion mode, never the stored type (see header spec).
        GenerateHapTokenDelInfoVec(tokenID, bundleName, delInfoVec, true);
    }
    uids.assign(uidSet.begin(), uidSet.end());
    LOGI(ATM_DOMAIN, ATM_TAG, "Bundle %{public}s, active size=%{public}zu, reserved size=%{public}zu.",
        bundleName.c_str(), activeTokens.size(), reservedTokens.size());

    GenericValues packageCondition;
    packageCondition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    AccessTokenInfoUtils::GenerateDelInfoToVec(
        AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, packageCondition, delInfoVec);
    return RET_SUCCESS;
}

int32_t DeleteBundleManager::DeleteIdentityWithDfx(AccessTokenID tokenID, const std::string& bundleName,
    ReservedType reservedType, DeleteDfxInfo& dfxInfo)
{
    // Case 1: tokenID 0 deletes every token of the bundle plus its package info.
    if (tokenID == INVALID_TOKENID) {
        dfxInfo.sceneCode = static_cast<int32_t>(AT_DELETE_ALL_BUNDLE);
        if (reservedType != ReservedType::NONE) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Invalid param: reservedType must be NONE when tokenID is invalid.");
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        return DeleteWholeBundle(bundleName);
    }

    if (TokenIDAttributes::GetTokenIdTypeEnum(tokenID) != TOKEN_HAP) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is not a HAP token.", tokenID);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    // Case 2.1: reserved tokens own no kernel objects; the TOKEN_HAP check
    // lives in DeleteActiveAndUntrustedToken (single validation point).
    if (AccessTokenIDManager::GetInstance().IsReservedTokenId(tokenID)) {
        dfxInfo.sceneCode = static_cast<int32_t>(AT_DELETE_RESERVED_TOKEN);
        if (reservedType != ReservedType::NONE) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Invalid param: reservedType must be NONE for reserved tokenID.");
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        return DeleteReservedToken(tokenID, bundleName, dfxInfo);
    }

    if (reservedType == ReservedType::RESERVED_IDENTITY) {
        dfxInfo.sceneCode = static_cast<int32_t>(AT_DELETE_KEEP_TOKEN_FINISH);
    } else if (reservedType == ReservedType::RESERVED_DATA) {
        dfxInfo.sceneCode = static_cast<int32_t>(AT_DELETE_KEEP_DATA);
    } else {
        dfxInfo.sceneCode = static_cast<int32_t>(AT_DELETE_NORMAL);
    }
    // Case 2.2: active or untrusted token, transactional delete.
    return DeleteActiveAndUntrustedToken(tokenID, bundleName, reservedType, dfxInfo);
}

int32_t DeleteBundleManager::DeleteActiveAndUntrustedToken(AccessTokenID id,
    const std::string& bundleName, ReservedType type, DeleteDfxInfo& dfxInfo)
{
    TokenIdStatus status = TokenIdStatus::ACTIVE;
    std::shared_ptr<HapTokenInfoInner> info =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoAndStatus(id, status);
    if (info == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is not exist.", id);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    if (status == TokenIdStatus::RESERVED) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is reserved.", id);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    dfxInfo.userId = info->GetUserID();
    dfxInfo.instIndex = info->GetInstIndex();
    if (info->IsRemote()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Remote hap token %{public}u can not delete.", id);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (info->GetBundleName() != bundleName) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Token %{public}u does not belong to bundle %{public}s.",
            id, bundleName.c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return DeleteActiveTokenInner(info, type);
}

int32_t DeleteBundleManager::DeleteActiveTokenInner(std::shared_ptr<HapTokenInfoInner> info, ReservedType delType)
{
    AccessTokenID id = info->GetTokenID();
    // Both declared BEFORE the txn: the brief must outlive the rollback
    // (reverse destruction order).
    std::vector<BriefPermData> oldPermBriefDataList;
    std::vector<std::string> permissionList;
    {
        KernelAndDBWriteTransaction txn;
        // Rollback source captured under the lock; a missing brief degrades
        // the rollback to the spm-entry restore only (restart reconciliation
        // is the fallback, failure reported above).
        int32_t briefRet = PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(id, oldPermBriefDataList);
        if (briefRet != RET_SUCCESS) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Get brief failed, token=%{public}u may be untrusted, ret=%{public}d.",
                id, briefRet);
            ReportSysCommonEventError(DELETE_BRIEF_MISSING, ERR_TOKENID_NOT_EXIST);
        }
        // Notify data captured while the briefs are alive.
        HapTokenInfoInner::GetGrantedPermList(id, permissionList);
        RemoveSpmDataParam removeParam = { id, &oldPermBriefDataList };
        int32_t ret = txn.StageKernelRemove({ removeParam });
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "StageKernelRemove failed, id %{public}u, ret %{public}d.", id, ret);
            return ret;
        }
        std::vector<DelInfo> delInfoVec;
        std::vector<AddInfo> addInfoVec;
        BundleCleanPlan cleanPlan;
        ret = BuildDeleteDbAllOps(info, delType, delInfoVec, addInfoVec, cleanPlan);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "BuildDeleteDbAllOps failed, id %{public}u, ret %{public}d.", id, ret);
            return ret;
        }
        ret = txn.CommitDb(delInfoVec, addInfoVec);
        if (ret != RET_SUCCESS) {
            // Surface the failure; the destructor restores the kernel.
            LOGE(ATM_DOMAIN, ATM_TAG, "CommitDb failed, id %{public}u, ret %{public}d.", id, ret);
            return ret;
        }
        PublishActiveTokenDeletion(info, delType, cleanPlan);
        txn.Commit();
    } // L0 lock released; the notification tail below runs lock-free.
    LOGI(ATM_DOMAIN, ATM_TAG, "Remove hap token %{public}u ok!", id);
    NotifyTokenDeleted(id, permissionList);
    return RET_SUCCESS;
}

int32_t DeleteBundleManager::BuildDeleteDbAllOps(const std::shared_ptr<HapTokenInfoInner>& info,
    ReservedType delType, std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec,
    BundleCleanPlan& cleanPlan)
{
    BuildTokenRemoveDbOps(info, delType, delInfoVec, addInfoVec);
    int32_t ret = BuildBundleCleanDbOps(info, delType, delInfoVec, cleanPlan);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    if (delType != ReservedType::RESERVED_DATA) {
        // Non-RESERVED_DATA deletes drop the policy whitelist entry.
        // RESERVED_DATA keeps the whitelist with the data.
        (void)UserPolicyManager::GetInstance().BuildRemoveTokensFromPolicyWhiteListOps(
            { info->GetTokenID() }, delInfoVec, addInfoVec);
    }
    return RET_SUCCESS;
}

void DeleteBundleManager::PublishActiveTokenDeletion(const std::shared_ptr<HapTokenInfoInner>& info,
    ReservedType delType, const BundleCleanPlan& cleanPlan)
{
    AccessTokenID id = info->GetTokenID();
    if (cleanPlan.cleanBundleId) {
        // Memory-only bundleId release
        (void)AccessTokenIDManager::GetInstance().RemoveBundleId(info->GetUid());
    }
    AccessTokenInfoManager::GetInstance().CommitDeleteHapCache(id, info->GetBundleName());
    if (delType != ReservedType::NONE) {
        (void)AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(id, TokenIdStatus::RESERVED);
    } else {
        // Set-agnostic force release: the complete delete frees the id from
        // whichever set holds it (active or untrusted).
        AccessTokenIDManager::GetInstance().ReleaseTokenIdForce(id);
    }
    if (delType != ReservedType::RESERVED_DATA) {
        // Ordering convention: in-memory commits stay inside the L0 scope;
        // callbacks fire only after the lock is released.
        UserPolicyManager::GetInstance().CommitPolicyWhiteListRemoval({ id });
    }
}

namespace {
/**
 * Assemble the kernel-removal params for a whole-bundle delete, capturing
 * each active token's permission bitmap. oldBriefs must be declared before
 * the transaction by the caller: the params reference its elements and must
 * stay alive until the rollback-capable transaction is gone.
 */
void BuildWholeBundleRemoveParams(const std::vector<AccessTokenID>& activeTokens,
    std::vector<std::vector<BriefPermData>>& oldBriefs, std::vector<RemoveSpmDataParam>& removeParams)
{
    // Stage every active token's kernel removal (reserved tokens hold no
    // kernel objects). Capped by MAX_ENTRY_NUM (255); exceeding fails the
    // whole delete (no batching).
    oldBriefs.resize(activeTokens.size());
    removeParams.reserve(activeTokens.size());
    uint32_t briefMissingCount = 0;
    for (size_t i = 0; i < activeTokens.size(); ++i) {
        // Missing brief: bitmap not restorable, spm entry still restored;
        // keep the frequency observable.
        if (PermissionDataBrief::GetInstance().GetBriefPermDataByTokenId(
            activeTokens[i], oldBriefs[i]) != RET_SUCCESS) {
            briefMissingCount++;
        }
        RemoveSpmDataParam param = { activeTokens[i], &oldBriefs[i] };
        removeParams.emplace_back(param);
    }
    if (briefMissingCount > 0) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Get brief failed, %{public}u tokens are not compensable.", briefMissingCount);
        ReportSysCommonEventError(DELETE_BRIEF_MISSING, ERR_TOKENID_NOT_EXIST);
    }
}

/**
 * Publish the in-memory half of a committed whole-bundle delete: every token
 * of the bundle (active, untrusted or reserved - the release is set-agnostic)
 * drops its cache entry and leaves whichever id set holds it; the bundleIds
 * the bundle occupied return to the pool; the policy whitelist entries go.
 */
void ReleaseBundleResources(const std::string& bundleName,
    const std::vector<AccessTokenID>& allTokens, const std::vector<int32_t>& uids)
{
    for (const auto& tokenId : allTokens) {
        // Route through the cache commit (active caches no-op for reserved).
        AccessTokenInfoManager::GetInstance().CommitDeleteHapCache(tokenId, bundleName);
        // Force release: the whole bundle is gone, the id leaves whichever
        // set holds it - no active/reserved partition needed here.
        AccessTokenIDManager::GetInstance().ReleaseTokenIdForce(tokenId);
    }
    // Every bundleId (one per user) returns to the pool; idempotent.
    for (const auto& uid : uids) {
        (void)AccessTokenIDManager::GetInstance().RemoveBundleId(uid);
    }
    UserPolicyManager::GetInstance().CommitPolicyWhiteListRemoval(allTokens);
}
} // namespace

int32_t DeleteBundleManager::DeleteWholeBundle(const std::string& bundleName)
{
    // Declared before the transaction so reverse destruction order keeps the
    // briefs alive until the rollback-capable transaction is destroyed.
    std::vector<std::vector<BriefPermData>> oldBriefs;
    std::vector<std::vector<std::string>> grantedPermLists;
    std::vector<AccessTokenID> activeTokens;
    std::vector<AccessTokenID> reservedTokens;
    std::vector<int32_t> uids;
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    {
        KernelAndDBWriteTransaction txn;
        int32_t ret = BuildBundleDelDbOps(bundleName, activeTokens, reservedTokens, uids, delInfoVec);
        if (ret != RET_SUCCESS) {
            return ret;
        }
        std::vector<RemoveSpmDataParam> removeParams;
        BuildWholeBundleRemoveParams(activeTokens, oldBriefs, removeParams);
        ret = txn.StageKernelRemove(removeParams);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "StageKernelRemove failed for bundle %{public}s, ret %{public}d.",
                bundleName.c_str(), ret);
            return ret;
        }
        // The whole bundle is wiped, so every token drops its policy whitelist
        // entry inside the same transaction: freed ids must not leak policy
        // privileges to their next owner. The combined list also feeds the
        // set-agnostic release below.
        std::vector<AccessTokenID> allBundleTokens = activeTokens;
        allBundleTokens.insert(allBundleTokens.end(), reservedTokens.begin(), reservedTokens.end());
        (void)UserPolicyManager::GetInstance().BuildRemoveTokensFromPolicyWhiteListOps(
            allBundleTokens, delInfoVec, addInfoVec);
        ret = txn.CommitDb(delInfoVec, addInfoVec);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "CommitDb failed for bundle %{public}s, ret %{public}d.",
                bundleName.c_str(), ret);
            return ret;
        }
        // Capture the granted lists while the briefs are still alive.
        grantedPermLists.resize(activeTokens.size());
        for (size_t i = 0; i < activeTokens.size(); ++i) {
            (void)HapTokenInfoInner::GetGrantedPermList(activeTokens[i], grantedPermLists[i]);
        }
        ReleaseBundleResources(bundleName, allBundleTokens, uids);
        txn.Commit();
    } // L0 lock released; cross-module notifications run lock-free below.
    NotifyBundleTokensDeleted(activeTokens, grantedPermLists);
    return RET_SUCCESS;
}

void DeleteBundleManager::NotifyTokenDeleted(AccessTokenID tokenId,
    const std::vector<std::string>& grantedPerms)
{
    // Legacy parity: the parameter bump carries the first granted permission only.
    if (!grantedPerms.empty()) {
        PermissionChangeNotifier::GetInstance().ParamUpdate(grantedPerms[0], 0, true);
    }
    for (const auto& perm : grantedPerms) {
        CallbackManager::GetInstance().ExecuteCallbackAsync(tokenId, perm, STATE_CHANGE_REVOKED);
    }
#ifdef TOKEN_SYNC_ENABLE
    TokenModifyNotifier::GetInstance().NotifyTokenDelete(tokenId);
#endif
}

void DeleteBundleManager::NotifyBundleTokensDeleted(const std::vector<AccessTokenID>& activeTokens,
    const std::vector<std::vector<std::string>>& grantedPermLists)
{
    if (grantedPermLists.size() != activeTokens.size()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "grantedPermLists size %{public}zu != activeTokens size %{public}zu.",
            grantedPermLists.size(), activeTokens.size());
        return;
    }
    for (size_t i = 0; i < activeTokens.size(); ++i) {
        NotifyTokenDeleted(activeTokens[i], grantedPermLists[i]);
    }
}

int32_t DeleteBundleManager::HandleReservedRowNotFound(AccessTokenID tokenID, const std::string& bundleName)
{
    // Ownership mismatch must reject the call.
    GenericValues idCondition;
    idCondition.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenID));
    std::vector<GenericValues> idResults;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, idCondition, idResults);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to query token %{public}u from db, err %{public}d.", tokenID, ret);
        return ret;
    }
    if (!idResults.empty()) {
        std::string actualBundleName = idResults[0].GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
        LOGE(ATM_DOMAIN, ATM_TAG,
            "BundleName mismatch: tokenID=%{public}u, expected bundleName=%{public}s, actual bundleName=%{public}s",
            tokenID, bundleName.c_str(), actualBundleName.c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    // Idempotent: audit-trace which bundle asked for the release.
    LOGW(ATM_DOMAIN, ATM_TAG,
        "Reserved token %{public}u db row missing, release for bundle %{public}s proceeds.",
        tokenID, bundleName.c_str());
    return RET_SUCCESS;
}

int32_t DeleteBundleManager::PrepareReservedTokenDelete(AccessTokenID tokenID, const std::string& bundleName,
    DeleteDfxInfo& dfxInfo, int32_t& rowUid, BundleCleanPlan& cleanPlan)
{
    rowUid = UNAVAILABLE_UID;
    // One bundle-name query feeds both the row lookup and the clean judgment.
    GenericValues bundleCondition;
    bundleCondition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    std::vector<GenericValues> bundleRows;
    int32_t ret = AccessTokenDbOperator::Find(
        AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, bundleCondition, bundleRows);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to query tokens for bundle %{public}s, err %{public}d.",
            bundleName.c_str(), ret);
        return ret;
    }
    size_t rowIndex = bundleRows.size();
    for (size_t i = 0; i < bundleRows.size(); ++i) {
        if (static_cast<AccessTokenID>(bundleRows[i].GetInt(TokenFiledConst::FIELD_TOKEN_ID)) == tokenID) {
            rowIndex = i;
            break;
        }
    }
    if (rowIndex == bundleRows.size()) {
        ret = HandleReservedRowNotFound(tokenID, bundleName);
        if (ret != RET_SUCCESS) {
            return ret;
        }
    }
    if (rowIndex != bundleRows.size()) {
        const GenericValues& row = bundleRows[rowIndex];
        dfxInfo.userId = row.GetInt(TokenFiledConst::FIELD_USER_ID);
        dfxInfo.instIndex = row.GetInt(TokenFiledConst::FIELD_INST_INDEX);
        rowUid = row.GetInt(TokenFiledConst::FIELD_UID);
    }

    // Complete delete (NONE mode); uid=-1 rows are skipped by the judgment.
    JudgeBundleCleanFromRows(bundleRows, tokenID, rowUid, ReservedType::NONE, cleanPlan);
    return RET_SUCCESS;
}

int32_t DeleteBundleManager::DeleteReservedToken(AccessTokenID tokenID, const std::string& bundleName,
    DeleteDfxInfo& dfxInfo)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteReservedToken: tokenID=%{public}u, bundleName=%{public}s.",
        tokenID, bundleName.c_str());
    KernelAndDBWriteTransaction txn;
    int32_t rowUid = 0;
    BundleCleanPlan cleanPlan;
    int32_t ret = PrepareReservedTokenDelete(tokenID, bundleName, dfxInfo, rowUid, cleanPlan);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    std::vector<DelInfo> delInfoVec;
    // The deletion mode here is a complete delete (NONE), independent of the
    // token's own stored type: the permission state always goes.
    GenerateHapTokenDelInfoVec(tokenID, bundleName, delInfoVec, true);
    if (cleanPlan.cleanBundleInfo) {
        GenericValues packageCondition;
        packageCondition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
        AccessTokenInfoUtils::GenerateDelInfoToVec(
            AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO, packageCondition, delInfoVec);
    }
    ret = txn.CommitDb(delInfoVec, {});
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to delete reserved token %{public}u from db, err %{public}d.",
            tokenID, ret);
        return ret;
    }
    // Route through the cache commit (active caches no-op for reserved).
    AccessTokenInfoManager::GetInstance().CommitDeleteHapCache(tokenID, bundleName);
    if (cleanPlan.cleanBundleId) {
        (void)AccessTokenIDManager::GetInstance().RemoveBundleId(rowUid);
    }
    AccessTokenIDManager::GetInstance().RemoveReservedTokenId(tokenID);
    txn.Commit();
    return RET_SUCCESS;
}
#endif // SPM_DATA_ENABLE
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
