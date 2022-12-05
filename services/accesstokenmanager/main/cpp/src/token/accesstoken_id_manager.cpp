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

#include "accesstoken_id_manager.h"
#include "accesstoken_log.h"
#include "data_validator.h"
#include "random.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenIDManager"};
}

ATokenTypeEnum AccessTokenIDManager::GetTokenIdTypeEnum(AccessTokenID id)
{
    AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&id);
    return (ATokenTypeEnum)idInner->type;
}

int AccessTokenIDManager::GetTokenIdDlpFlag(AccessTokenID id)
{
    AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&id);
    return idInner->dlpFlag;
}

ATokenTypeEnum AccessTokenIDManager::GetTokenIdType(AccessTokenID id)
{
    {
        Utils::UniqueReadGuard<Utils::RWLock> idGuard(this->tokenIdLock_);
        if (tokenIdSet_.count(id) == 0) {
            return TOKEN_INVALID;
        }
    }
    return GetTokenIdTypeEnum(id);
}

int AccessTokenIDManager::RegisterTokenId(AccessTokenID id, ATokenTypeEnum type)
{
    AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&id);
    if (idInner->version != DEFAULT_TOKEN_VERSION || idInner->type != type) {
        return RET_FAILED;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> idGuard(this->tokenIdLock_);

    for (std::set<AccessTokenID>::iterator it = tokenIdSet_.begin(); it != tokenIdSet_.end(); ++it) {
        AccessTokenID tokenId = *it;
        AccessTokenIDInner *idInnerExist = reinterpret_cast<AccessTokenIDInner *>(&tokenId);
        if (idInnerExist->tokenUniqueID == idInner->tokenUniqueID) {
            return RET_FAILED;
        }
    }
    tokenIdSet_.insert(id);
    return RET_SUCCESS;
}

AccessTokenID AccessTokenIDManager::CreateTokenId(ATokenTypeEnum type, int dlpType) const
{
    unsigned int rand = GetRandomUint32();
    if (rand == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "get random failed");
        return 0;
    }

    AccessTokenIDInner innerId = {0};
    innerId.version = DEFAULT_TOKEN_VERSION;
    innerId.type = type;
    innerId.res = 0;
    innerId.dlpFlag = (dlpType == 0) ? 0 : 1;
    innerId.tokenUniqueID = rand & TOKEN_RANDOM_MASK;
    AccessTokenID tokenId = *(AccessTokenID *)&innerId;
    return tokenId;
}

AccessTokenID AccessTokenIDManager::CreateAndRegisterTokenId(ATokenTypeEnum type, int dlpType)
{
    AccessTokenID tokenId = 0;
    // random maybe repeat, retry twice.
    for (int i = 0; i < MAX_CREATE_TOKEN_ID_RETRY; i++) {
        tokenId = CreateTokenId(type, dlpType);
        if (tokenId == INVALID_TOKENID) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "create tokenId failed");
            return INVALID_TOKENID;
        }

        int ret = RegisterTokenId(tokenId, type);
        if (ret == RET_SUCCESS) {
            break;
        } else if (i < MAX_CREATE_TOKEN_ID_RETRY - 1) {
            ACCESSTOKEN_LOG_WARN(LABEL, "reigster tokenId failed, maybe repeat, retry");
        } else {
            ACCESSTOKEN_LOG_ERROR(LABEL, "reigster tokenId finally failed");
            tokenId = INVALID_TOKENID;
        }
    }
    return tokenId;
}

void AccessTokenIDManager::ReleaseTokenId(AccessTokenID id)
{
    Utils::UniqueWriteGuard<Utils::RWLock> idGuard(this->tokenIdLock_);
    if (tokenIdSet_.count(id) == 0) {
        ACCESSTOKEN_LOG_INFO(LABEL, "id %{public}x is not exist", id);
        return;
    }
    tokenIdSet_.erase(id);
}

AccessTokenIDManager& AccessTokenIDManager::GetInstance()
{
    static AccessTokenIDManager instance;
    return instance;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
