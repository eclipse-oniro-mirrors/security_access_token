/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_TOKEN_ID_MANAGER_H
#define ACCESSTOKEN_TOKEN_ID_MANAGER_H

#include <mutex>
#include <set>
#include <shared_mutex>
#include <vector>

#include "access_token.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static constexpr unsigned int TOKEN_RANDOM_MASK = (1 << 20) - 1;
static const int MAX_CREATE_TOKEN_ID_RETRY = 1000;

enum class TokenIdStatus : uint32_t {
    ACTIVE = 0,      // tokenId in tokenIdSet_
    RESERVED = 1,    // tokenId in reservedTokenIdSet_
    UNTRUSTED = 2    // tokenId in untrustedTokenIdSet_
};

class AccessTokenIDManager final {
public:
    static AccessTokenIDManager& GetInstance();
    virtual ~AccessTokenIDManager() = default;

    int AddTokenId(AccessTokenID id, ATokenTypeEnum type);
    AccessTokenID CreateAndRegisterTokenId(ATokenTypeEnum type, int32_t dlpFlag, int32_t cloneFlag,
        int32_t toolFlag);
    int RegisterTokenId(AccessTokenID id, ATokenTypeEnum type);
    void ReleaseTokenId(AccessTokenID id);
    void AddReservedTokenId(AccessTokenID id);
    void RemoveReservedTokenId(AccessTokenID id);
    bool IsReservedTokenId(AccessTokenID id);
    ATokenTypeEnum GetTokenIdType(AccessTokenID id);
    int32_t ChangeTokenIdStatus(AccessTokenID id, TokenIdStatus targetStatus);

    // Identity bundleId management
    // Note: Callers are responsible for determining whether to add or remove bundleId based on their own logic.
    // This class only provides the underlying management capabilities.
    void InitSingleBundleIdCache(int32_t uid);
    int32_t ImportInitialUids(const std::vector<int32_t>& uids);
    int32_t AllocUid(int32_t localId, int32_t& outUid);
    int32_t RemoveBundleId(int32_t uid);
    int32_t TranslateUid(int32_t srcUid, int32_t dstLocalId, int32_t& outUid);

    // Migration control
    void SetMigrationDone();
    bool ExtractBundleId(int32_t uid, int32_t &bundleId) const;
    int32_t GetTokenIdStatus(AccessTokenID id, TokenIdStatus& status);
private:
    AccessTokenIDManager() = default;
    DISALLOW_COPY_AND_MOVE(AccessTokenIDManager);
    AccessTokenID CreateTokenId(ATokenTypeEnum type, int32_t dlpFlag, int32_t cloneFlag, int32_t toolFlag) const;
    int32_t GetTokenIdStatusLocked(AccessTokenID id, TokenIdStatus& status) const;

    std::shared_mutex tokenIdLock_;
    std::set<AccessTokenID> tokenIdSet_;
    std::set<AccessTokenID> reservedTokenIdSet_;
    std::set<AccessTokenID> untrustedTokenIdSet_;
    std::mutex bundleIdLock_;
    std::set<int32_t> bundleIdSet_;
    std::mutex migrationLock_;
    bool migrationDone_ = false;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_TOKEN_ID_MANAGER_H
