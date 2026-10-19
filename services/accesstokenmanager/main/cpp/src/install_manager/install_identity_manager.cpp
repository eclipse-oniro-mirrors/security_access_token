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

#include "install_identity_manager.h"

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_id_manager.h"
#include "generic_values.h"
#include "install_db_repository.h"
#include "multiple_mode_utils.h"
#include "token_field_const.h"
#include "tokenid_attributes.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const uint32_t SYSTEM_APP_FLAG = 0x0001;
static const uint32_t ATOMIC_SERVICE_FLAG = 0x0002;
static const uint32_t DEBUG_APP_FLAG = 0x0008;
constexpr int32_t INVALID_UID = -1;
}

namespace {
// Resolve the plain 32-bit token id: in repair mode adopt the desired id if it
// registers cleanly (version/type bits valid, not in any id set), and fall back
// to a fresh allocation on any failure; the actual id reaches BMS via the out param.
AccessTokenID ResolveTokenId(const InstallCache& cache, bool isDlpApp, bool isCloneApp)
{
    AccessTokenID desired = AccessTokenIDManager::ParseTokenId(cache.repairedIdentity.tokenId);
    if (desired != 0) {
        // The adopted id must carry the same identity flags a fresh allocation
        // would set: a dlp/clone token whose desired id lacks (or wrongly
        // carries) the dlp/clone bit would leak a mismatched public bit layout
        // to TokenIDAttributes::GetTokenIdDlpFlag/GetTokenIdCloneFlag callers.
        bool flagMatch = TokenIDAttributes::GetTokenIdDlpFlag(desired) == (isDlpApp ? 1 : 0)
            && TokenIDAttributes::GetTokenIdCloneFlag(desired) == (isCloneApp ? 1 : 0);
        int32_t ret = AccessTokenIDManager::GetInstance().RegisterTokenId(desired, TOKEN_HAP);
        if (flagMatch && ret == RET_SUCCESS) {
            return desired;
        }
        LOGW(ATM_DOMAIN, ATM_TAG, "Adopt tokenId %{public}u rejected (flagMatch=%{public}d, ret=%{public}d), "
            "allocate new one.", desired, static_cast<int32_t>(flagMatch), ret);
    }
    return AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(TOKEN_HAP, isDlpApp, isCloneApp, 0);
}

// Resolve the uid: a same-bundle sibling uid first, then the desired uid from the
// BMS input if reusable (uid != INVALID_UID means BMS expressed an expectation),
// otherwise a fresh allocation.
int32_t ResolveUid(InstallCache& cache, int32_t bundleRefUid, int32_t& uid)
{
    if (bundleRefUid != INVALID_UID) {
        return AccessTokenIDManager::GetInstance().TranslateUid(bundleRefUid, cache.baseInfo.userID, uid);
    }

    int32_t desiredUid = cache.repairedIdentity.uid;
    // uid 0 (struct default) and -1 both mean no expectation: skip the adoption
    // path so a fresh uid is allocated (validated, not adopted, flow unaffected)
    if (desiredUid != INVALID_UID && desiredUid != 0) {
        // The desired uid must belong to the target user
        if (AccessTokenIDManager::ExtractUserId(desiredUid) != cache.baseInfo.userID) {
            LOGC(ATM_DOMAIN, ATM_TAG,
                "Uid %{public}d doesn't belong to user %{public}d.", desiredUid, cache.baseInfo.userID);
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        bool reusable = false;
        if (AccessTokenIDManager::GetInstance().IsUidReusable(desiredUid, reusable) == RET_SUCCESS && reusable) {
            AccessTokenIDManager::GetInstance().InitSingleBundleIdCache(desiredUid);
            uid = desiredUid;
            cache.uidFromCaller = true;
            return RET_SUCCESS;
        }
        LOGW(ATM_DOMAIN, ATM_TAG, "Adopt uid %{public}d failed, allocate new one.", desiredUid);
    }
    return AccessTokenIDManager::GetInstance().AllocUid(cache.baseInfo.userID, uid);
}
}

AccessTokenAttr InstallIdentityManager::BuildTokenAttr(const BundleParam& param)
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

int32_t InstallIdentityManager::CreateTokenIdAndUid(
    InstallCache& cache, const BundlePolicy& bundlePolicy, int32_t bundleRefUid)
{
    bool isDlpApp = bundlePolicy.dlpType > DLP_COMMON;
    bool isCloneApp = !isDlpApp && (!MultipleModeUtils::IsMainAppIndex(cache.baseInfo.instIndex));

    AccessTokenID tokenId = ResolveTokenId(cache, isDlpApp, isCloneApp);
    if (tokenId == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token Id create failed");
        return ERR_TOKENID_CREATE_FAILED;
    }
    cache.identity.tokenId = AccessTokenIDManager::BuildFullTokenId(tokenId, BuildTokenAttr(cache.bundleParam));

    int32_t ret = ResolveUid(cache, bundleRefUid, cache.identity.uid);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Uid create failed, ret=%{public}d", ret);
        AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
        return ERR_UID_CREATE_FAILED;
    }
    return RET_SUCCESS;
}

void InstallIdentityManager::RestoreIdentityFromReservedData(
    InstallCache& cache, AccessTokenID tokenId, int32_t uid, int32_t oldAttr)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Reserved data token, tokenId=%{public}u, uid=%{public}d", tokenId, uid);
    cache.identity.tokenId = AccessTokenIDManager::BuildFullTokenId(tokenId, BuildTokenAttr(cache.bundleParam));
    cache.identity.uid = uid;
    cache.isNewBundleId = false;
    cache.reserved = ReservedType::RESERVED_DATA;
    cache.oldTokenId = tokenId;
    cache.oldAttr = oldAttr;
}

int32_t InstallIdentityManager::ResolveExistingTokenReuse(InstallCache& cache, const GenericValues& tokenValue)
{
    AccessTokenID tokenId = static_cast<AccessTokenID>(tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
    ReservedType reserved = static_cast<ReservedType>(tokenValue.GetInt(TokenFiledConst::FIELD_RESERVED));
    int32_t uid = tokenValue.GetInt(TokenFiledConst::FIELD_UID);
    int32_t oldAttr = tokenValue.GetInt(TokenFiledConst::FIELD_TOKEN_ATTR);

    if (reserved == ReservedType::RESERVED_DATA) {
        RestoreIdentityFromReservedData(cache, tokenId, uid, oldAttr);
        return RET_SUCCESS;
    }
    if (reserved == ReservedType::RESERVED_IDENTITY) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Reserved identity token");
        cache.reserved = ReservedType::RESERVED_IDENTITY;
        cache.oldTokenId = tokenId;
        return RET_SUCCESS;
    }
    // reserved == ReservedType::NONE
    // DB has a record without reservation. If the tokenId is already registered in id manager,
    // a live token occupies it and install must fail. Otherwise the db record is dirty data
    // (e.g. boot recovery residue), remove it and continue with fresh allocation.
    TokenIdStatus status;
    if (AccessTokenIDManager::GetInstance().GetTokenIdStatus(tokenId, status) == RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "No reservation, tokenId already registered");
        return AccessTokenError::ERR_TOKENID_HAS_EXISTED;
    }
    return InstallDbRepository::DeleteFromDbByTokenId(tokenId);
}

int32_t InstallIdentityManager::GetTokenIdAndUid(InstallCache& cache, const BundlePolicy& bundlePolicy)
{
    std::vector<GenericValues> hapTokenResults;
    int32_t ret = InstallDbRepository::QueryBundleTokens(cache.baseInfo.bundleName, cache, hapTokenResults);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    int32_t bundleRefUid = INVALID_UID;
    for (const auto& tokenValue : hapTokenResults) {
        if (tokenValue.GetInt(TokenFiledConst::FIELD_INST_INDEX) != cache.baseInfo.instIndex) {
            continue;
        }
        int32_t userId = tokenValue.GetInt(TokenFiledConst::FIELD_USER_ID);
        if (userId == cache.baseInfo.userID) {
            ret = ResolveExistingTokenReuse(cache, tokenValue);
            if (ret != RET_SUCCESS) {
                return ret;
            }
            // RESERVED_DATA: identity fully resolved (token/uid reused from the
            // reserved row), skip remaining rows and fresh allocation
            if (cache.reserved == ReservedType::RESERVED_DATA) {
                return RET_SUCCESS;
            }
        } else {
            int32_t uid = tokenValue.GetInt(TokenFiledConst::FIELD_UID);
            if (uid != INVALID_UID) {
                bundleRefUid = uid;
                cache.isNewBundleId = false;
            }
        }
    }

    return CreateTokenIdAndUid(cache, bundlePolicy, bundleRefUid);
}

int32_t InstallIdentityManager::ResolveUpdateUid(
    int32_t& uid, const std::shared_ptr<HapTokenInfoInner>& infoPtr, bool& isNewBundleId, bool& fromCaller)
{
    // public static entry: direct callers (tests, future code) may pass nullptr
    if (infoPtr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "HapTokenInfoInner is null");
        return ERR_PARAM_INVALID;
    }

    // level 1: AT memory uid
    int32_t rawUid = infoPtr->GetUid();
    if (rawUid != INVALID_UID) {
        uid = rawUid;
        return RET_SUCCESS;
    }

    // level 2: cross-user bundleId reuse
    std::vector<GenericValues> hapTokenResults;
    int32_t ret = InstallDbRepository::QueryBundleTokenbyIndex(
        infoPtr->GetBundleName(), infoPtr->GetInstIndex(), hapTokenResults);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    int32_t bundleRefUid = INVALID_UID;
    for (const auto& tokenValue : hapTokenResults) {
        int32_t queryUid = tokenValue.GetInt(TokenFiledConst::FIELD_UID);
        if (queryUid != INVALID_UID) {
            bundleRefUid = queryUid;
            break;
        }
    }
    if (bundleRefUid != INVALID_UID) {
        return AccessTokenIDManager::GetInstance().TranslateUid(bundleRefUid, infoPtr->GetUserID(), uid);
    }

    // level 3: BMS desired uid if reusable, otherwise fresh allocation
    bool reusable = false;
    if (uid != INVALID_UID &&
        AccessTokenIDManager::GetInstance().IsUidReusable(uid, reusable) == RET_SUCCESS && reusable) {
        AccessTokenIDManager::GetInstance().InitSingleBundleIdCache(uid);
        isNewBundleId = true;
        fromCaller = true;
    } else {
        int32_t ret = AccessTokenIDManager::GetInstance().AllocUid(infoPtr->GetUserID(), uid);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Uid create failed, ret=%{public}d", ret);
            return ERR_UID_CREATE_FAILED;
        }
        isNewBundleId = true;
    }
    return RET_SUCCESS;
}
// Session success path: settle id states. Updated tokens (loaded inactive during
// the session) become ACTIVE; reserved transitions retire or reactivate the old
// token. Pairs with RollbackIdentity.
void InstallIdentityManager::CommitIdentity(const InstallCache& cache, const FinishContext& context)
{
    if (cache.HasNewIdentity()) {
        AccessTokenIDManager::GetInstance().RemoveBundleIdFromReservedSet(cache.identity.uid);
    }

    size_t index = cache.HasNewIdentity() ? 1 : 0; // the new token is registered ACTIVE on allocation
    for (size_t i = index; i < context.hapInfos.size(); ++i) {
        AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(context.hapInfos[i].tokenID, TokenIdStatus::ACTIVE);
        AccessTokenIDManager::GetInstance().RemoveBundleIdFromReservedSet(context.hapInfos[i].uid);
    }
    if (cache.reserved == ReservedType::RESERVED_IDENTITY) {
        // identity kept across reinstall: old token is replaced, drop it from
        // the reserved id set (its session snapshot dies with the session cache)
        AccessTokenIDManager::GetInstance().RemoveReservedTokenId(cache.oldTokenId);
        return;
    }
    if (cache.reserved == ReservedType::RESERVED_DATA) {
        // identity and data kept: the reused token becomes active again
        (void)AccessTokenIDManager::GetInstance().ChangeTokenIdStatus(cache.identity.tokenId, TokenIdStatus::ACTIVE);
    }
}

// Session failure path: release every id acquired by this session. Pairs with
// CommitIdentity and with the allocation in CreateTokenIdAndUid.
void InstallIdentityManager::RollbackIdentity(const InstallCache& cache)
{
    if (cache.HasNewIdentity()) {
        // token allocated in CreateTokenIdAndUid; RESERVED_DATA reuses a reserved
        // token that never left the reserved set, so there is nothing to release
        if (cache.reserved != ReservedType::RESERVED_DATA) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(
                static_cast<AccessTokenID>(cache.identity.tokenId));
        }
        if (cache.isNewBundleId) {
            AccessTokenIDManager::GetInstance().RemoveBundleId(cache.identity.uid);
        }
    }
    for (const auto& iter : cache.uidStateMap) {
        if (iter.second.isNewBundleId) {
            AccessTokenIDManager::GetInstance().RemoveBundleId(iter.second.uid);
        }
    }
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
