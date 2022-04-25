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

#include <set>
#include <vector>

#include "access_token.h"
#include "nocopyable.h"
#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static constexpr unsigned int TOKEN_RANDOM_MASK = (1 << 20) - 1;
static const int MAX_CREATE_TOKEN_ID_RETRY = 1000;

class AccessTokenIDManager final {
public:
    static AccessTokenIDManager& GetInstance();
    virtual ~AccessTokenIDManager() = default;

    int AddTokenId(AccessTokenID id, ATokenTypeEnum type);
    AccessTokenID CreateAndRegisterTokenId(ATokenTypeEnum type, int dlpType);
    int RegisterTokenId(AccessTokenID id, ATokenTypeEnum type);
    void ReleaseTokenId(AccessTokenID id);
    ATokenTypeEnum GetTokenIdType(AccessTokenID id);
    int GetTokenIdDlpFlag(AccessTokenID id);
    static ATokenTypeEnum GetTokenIdTypeEnum(AccessTokenID id);

private:
    AccessTokenIDManager() = default;
    DISALLOW_COPY_AND_MOVE(AccessTokenIDManager);
    AccessTokenID CreateTokenId(ATokenTypeEnum type, int dlpType) const;

    OHOS::Utils::RWLock tokenIdLock_;
    std::set<AccessTokenID> tokenIdSet_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_TOKEN_ID_MANAGER_H
