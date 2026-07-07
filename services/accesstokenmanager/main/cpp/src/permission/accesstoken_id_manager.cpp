/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "accesstoken_id_manager.h"
#include <atomic>
#include <cinttypes>
#include <cstdlib>
#include <mutex>
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "data_validator.h"
#include "parameter.h"
#include "random.h"
#include "spm_setproc.h"
#include "tokenid_attributes.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
constexpr int32_t BUNDLE_ID_MIN = 10000;
constexpr int32_t BUNDLE_ID_MAX = 65535;
constexpr int32_t UID_TRANSFORM_DIVISOR = 200000;
static std::atomic<int32_t> g_bundleIdMin = -1;
}

int32_t AccessTokenIDManager::GetBundleIdMin()
{
    int32_t expectedValue = g_bundleIdMin.load();
    if (expectedValue != -1) {
        return expectedValue;
    }

    constexpr int32_t VALUE_MAX_LEN = 32;
    char value[VALUE_MAX_LEN] = {0};
    int32_t ret = GetParameter("const.product.baseappid", "", value, VALUE_MAX_LEN - 1);
    if (ret <= 0) {
        g_bundleIdMin = BUNDLE_ID_MIN;
        return g_bundleIdMin.load();
    }

    int32_t bundleIdMin = static_cast<int32_t>(std::atoll(value));
    if (bundleIdMin < BUNDLE_ID_MIN || bundleIdMin >= BUNDLE_ID_MAX) {
        g_bundleIdMin = BUNDLE_ID_MIN;
    } else {
        g_bundleIdMin = bundleIdMin;
    }
    return g_bundleIdMin.load();
}

ATokenTypeEnum AccessTokenIDManager::GetTokenIdType(AccessTokenID id)
{
    {
        std::shared_lock<std::shared_mutex> idGuard(this->tokenIdLock_);
        if (tokenIdSet_.count(id) == 0) {
            return TOKEN_INVALID;
        }
    }
    return TokenIDAttributes::GetTokenIdTypeEnum(id);
}

int AccessTokenIDManager::RegisterTokenId(AccessTokenID id, ATokenTypeEnum type)
{
    AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&id);
    if (idInner->version != DEFAULT_TOKEN_VERSION || idInner->type != type || idInner->type_ext != 0) {
        return ERR_PARAM_INVALID;
    }
    std::unique_lock<std::shared_mutex> idGuard(this->tokenIdLock_);
    TokenIdStatus status;
    if (GetTokenIdStatusLocked(id, status) == RET_SUCCESS) {
        return ERR_TOKENID_HAS_EXISTED;
    }

    tokenIdSet_.insert(id);
    return RET_SUCCESS;
}

AccessTokenID AccessTokenIDManager::CreateTokenId(ATokenTypeEnum type, int32_t dlpFlag, int32_t cloneFlag,
    int32_t toolFlag) const
{
    uint32_t rand = GetRandomUint32FromUrandom();
    if (rand == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get random failed");
        return 0;
    }

    AccessTokenIDInner innerId = {0};
    innerId.version = DEFAULT_TOKEN_VERSION;
    innerId.type = type;
    innerId.type_ext = 0;
    innerId.res = 0;
    innerId.toolFlag = static_cast<uint32_t>(toolFlag);
    innerId.cloneFlag = static_cast<uint32_t>(cloneFlag);
    innerId.renderFlag = 0;
    innerId.dlpFlag = static_cast<uint32_t>(dlpFlag);
    innerId.tokenUniqueID = rand & TOKEN_RANDOM_MASK;
    AccessTokenID tokenId = *reinterpret_cast<AccessTokenID *>(&innerId);
    return tokenId;
}

AccessTokenID AccessTokenIDManager::CreateAndRegisterTokenId(ATokenTypeEnum type, int32_t dlpFlag, int32_t cloneFlag,
    int32_t toolFlag)
{
    AccessTokenID tokenId = 0;
    // random maybe repeat, retry twice.
    for (int i = 0; i < MAX_CREATE_TOKEN_ID_RETRY; i++) {
        tokenId = CreateTokenId(type, dlpFlag, cloneFlag, toolFlag);
        if (tokenId == INVALID_TOKENID) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Create tokenId failed");
            return INVALID_TOKENID;
        }

        int ret = RegisterTokenId(tokenId, type);
        if (ret == RET_SUCCESS) {
            break;
        } else if (i < MAX_CREATE_TOKEN_ID_RETRY - 1) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Register tokenId failed(error=%{public}d), maybe repeat, retry.", ret);
        } else {
            LOGE(ATM_DOMAIN, ATM_TAG, "Register tokenId finally failed(error=%{public}d).", ret);
            tokenId = INVALID_TOKENID;
        }
    }
    return tokenId;
}

void AccessTokenIDManager::ReleaseTokenId(AccessTokenID id)
{
    std::unique_lock<std::shared_mutex> idGuard(this->tokenIdLock_);
    if (tokenIdSet_.count(id) == 0) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Id %{public}x is not exist", id);
        return;
    }
    tokenIdSet_.erase(id);
}

bool AccessTokenIDManager::IsReservedTokenId(AccessTokenID id)
{
    std::shared_lock<std::shared_mutex> idGuard(this->tokenIdLock_);
    return reservedTokenIdSet_.count(id) > 0;
}

void AccessTokenIDManager::AddReservedTokenId(AccessTokenID id)
{
    std::unique_lock<std::shared_mutex> idGuard(this->tokenIdLock_);
    TokenIdStatus status;
    if (GetTokenIdStatusLocked(id, status) == RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Id %{public}u already exist as %{public}d", id, static_cast<int32_t>(status));
        return;
    }
    reservedTokenIdSet_.insert(id);
}

void AccessTokenIDManager::RemoveReservedTokenId(AccessTokenID id)
{
    std::unique_lock<std::shared_mutex> idGuard(this->tokenIdLock_);
    reservedTokenIdSet_.erase(id);
}

int32_t AccessTokenIDManager::GetTokenIdStatus(AccessTokenID id, TokenIdStatus& status)
{
    std::shared_lock<std::shared_mutex> idGuard(this->tokenIdLock_);
    return GetTokenIdStatusLocked(id, status);
}

int32_t AccessTokenIDManager::GetTokenIdStatusLocked(AccessTokenID id, TokenIdStatus& status) const
{
    bool inActive = (tokenIdSet_.count(id) > 0);
    bool inReserved = (reservedTokenIdSet_.count(id) > 0);
    bool inUntrusted = (untrustedTokenIdSet_.count(id) > 0);

    if (inActive) {
        status = TokenIdStatus::ACTIVE;
        return RET_SUCCESS;
    } else if (inReserved) {
        status = TokenIdStatus::RESERVED;
        return RET_SUCCESS;
    } else if (inUntrusted) {
        status = TokenIdStatus::UNTRUSTED;
        return RET_SUCCESS;
    } else {
        // avoid log too much when device is rebooting, only log in debug level
        LOGD(ATM_DOMAIN, ATM_TAG, "TokenId %{public}u not found in any set.", id);
        return ERR_TOKENID_NOT_EXIST;
    }
}

int32_t AccessTokenIDManager::ChangeTokenIdStatus(AccessTokenID id, TokenIdStatus targetStatus)
{
    std::unique_lock<std::shared_mutex> idGuard(this->tokenIdLock_);

    TokenIdStatus currentStatus;
    int32_t result = GetTokenIdStatusLocked(id, currentStatus);
    if (result != RET_SUCCESS) {
        return result;
    }

    // If already in target status, return success
    if (currentStatus == targetStatus) {
        LOGD(ATM_DOMAIN, ATM_TAG, "TokenId %{public}u already in target status %{public}u.", id,
            static_cast<uint32_t>(targetStatus));
        return RET_SUCCESS;
    }

    // Remove from current set
    switch (currentStatus) {
        case TokenIdStatus::ACTIVE:
            tokenIdSet_.erase(id);
            break;
        case TokenIdStatus::RESERVED:
            reservedTokenIdSet_.erase(id);
            break;
        case TokenIdStatus::UNTRUSTED:
            untrustedTokenIdSet_.erase(id);
            break;
        default:
            return ERR_PARAM_INVALID;
    }
    // Add to target set
    switch (targetStatus) {
        case TokenIdStatus::ACTIVE:
            tokenIdSet_.insert(id);
            break;
        case TokenIdStatus::RESERVED:
            reservedTokenIdSet_.insert(id);
            break;
        case TokenIdStatus::UNTRUSTED:
            untrustedTokenIdSet_.insert(id);
            break;
        default:
            return ERR_PARAM_INVALID;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "TokenId %{public}u status changed from %{public}u to %{public}u.", id,
        static_cast<uint32_t>(currentStatus), static_cast<uint32_t>(targetStatus));
    return RET_SUCCESS;
}

AccessTokenIDManager& AccessTokenIDManager::GetInstance()
{
    static AccessTokenIDManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            AccessTokenIDManager* tmp = new AccessTokenIDManager();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

bool AccessTokenIDManager::ExtractBundleId(int32_t uid, int32_t& bundleId) const
{
    if (uid < 0) {
        return false;
    }
    int32_t extracted = uid % UID_TRANSFORM_DIVISOR;

    // Don't use GetBundleIdMin() here because GetBundleIdMin() value may be changed by system parameter,
    // which is invalid for exsisted bundleId.
    if (extracted < BUNDLE_ID_MIN || extracted > BUNDLE_ID_MAX) {
        return false;
    }
    bundleId = extracted;
    return true;
}

bool AccessTokenIDManager::IsBundleIdInUse(int32_t bundleId)
{
    std::unique_lock<std::mutex> lock(bundleIdLock_);
    return bundleIdSet_.count(bundleId) > 0;
}

void AccessTokenIDManager::InitSingleBundleIdCache(int32_t uid)
{
    int32_t bundleId = 0;
    if (!ExtractBundleId(uid, bundleId)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid uid=%{public}d.", uid);
        return;
    }
    std::unique_lock<std::mutex> lock(bundleIdLock_);
    bundleIdSet_.insert(bundleId);
}

int32_t AccessTokenIDManager::AllocUid(int32_t localId, int32_t& outUid)
{
#ifdef SPM_DATA_ENABLE
    {
        std::unique_lock<std::mutex> lock(migrationLock_);
        if (!migrationDone_) {
            LOGE(ATM_DOMAIN, ATM_TAG, "AllocUid failed, migration not completed.");
            return AccessTokenError::ERR_PARAM_INVALID;
        }
    }
#endif
    std::unique_lock<std::mutex> lock(bundleIdLock_);
    int32_t startId = bundleIdSet_.empty() ? GetBundleIdMin() : (*bundleIdSet_.rbegin() + 1);
    if (startId > BUNDLE_ID_MAX) {
        startId = GetBundleIdMin();
    }

    // Two-pass scan: [startId, BUNDLE_ID_MAX] then wrap [BUNDLE_ID_MIN, startId-1]
    int32_t ranges[2][2] = {{startId, BUNDLE_ID_MAX}, {GetBundleIdMin(), startId - 1}};
    int rangeSize = 2; // size of ranges
    for (int p = 0; p < rangeSize; p++) {
        for (int32_t candidate = ranges[p][0]; candidate <= ranges[p][1]; ++candidate) {
            if (bundleIdSet_.count(candidate) > 0) {
                continue;
            }
            int32_t uid = localId * UID_TRANSFORM_DIVISOR + candidate % UID_TRANSFORM_DIVISOR;
            uint64_t refcnt = 0;
            int32_t ret = SpmGetUidRefCnt(static_cast<uint32_t>(uid), &refcnt);
            if (ret != RET_SUCCESS && ret != ENOTSUP) {
                LOGE(ATM_DOMAIN, ATM_TAG, "SpmGetUidRefCnt failed, bundleId=%{public}d, ret=%{public}d.", candidate,
                    ret);
                return RET_FAILED;
            }
            if (ret == RET_SUCCESS && refcnt != 0) {
                LOGW(ATM_DOMAIN, ATM_TAG, "BundleId=%{public}d has active refcnt %{public}" PRIu64 ", skip.", candidate,
                    refcnt);
                continue;
            }
            bundleIdSet_.insert(candidate);
            outUid = uid;
            return RET_SUCCESS;
        }
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "AllocUid: all bundleIds exhausted.");
    return ERR_OVERSIZE;
}

int32_t AccessTokenIDManager::RemoveBundleId(int32_t uid)
{
    int32_t bundleId = 0;
    if (!ExtractBundleId(uid, bundleId)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid uid=%{public}d.", uid);
        return ERR_PARAM_INVALID;
    }
    std::unique_lock<std::mutex> lock(bundleIdLock_);
    if (bundleIdSet_.count(bundleId) == 0) {
        LOGW(ATM_DOMAIN, ATM_TAG, "BundleId=%{public}d not in cache.", bundleId);
        return RET_SUCCESS;
    }
    bundleIdSet_.erase(bundleId);
    return RET_SUCCESS;
}

int32_t AccessTokenIDManager::TranslateUid(int32_t srcUid, int32_t dstLocalId, int32_t& outUid)
{
    int32_t bundleId = 0;
    if (!ExtractBundleId(srcUid, bundleId)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid srcUid=%{public}d.", srcUid);
        return ERR_PARAM_INVALID;
    }
    outUid = dstLocalId * UID_TRANSFORM_DIVISOR + bundleId % UID_TRANSFORM_DIVISOR;
    return RET_SUCCESS;
}

void AccessTokenIDManager::SetMigrationDone()
{
    std::unique_lock<std::mutex> lock(migrationLock_);
    migrationDone_ = true;
    LOGI(ATM_DOMAIN, ATM_TAG, "Migration done flag set to true.");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
