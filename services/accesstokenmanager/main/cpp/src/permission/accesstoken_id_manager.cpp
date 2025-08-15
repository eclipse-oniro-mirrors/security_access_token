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
#include <mutex>
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "data_validator.h"
#include "random.h"
#include "tokenid_attributes.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
}

ATokenTypeEnum AccessTokenIDManager::GetTokenIdType(AccessTokenID id)
{
    {
        Utils::UniqueReadGuard<Utils::RWLock> idGuard(this->tokenIdLock_);
        if (tokenIdSet_.count(id) == 0) {
            return TOKEN_INVALID;
        }
    }
    return TokenIDAttributes::GetTokenIdTypeEnum(id);
}

int AccessTokenIDManager::RegisterTokenId(AccessTokenID id, ATokenTypeEnum type)
{
    AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&id);
    if (idInner->version != DEFAULT_TOKEN_VERSION || idInner->type != type) {
        return ERR_PARAM_INVALID;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> idGuard(this->tokenIdLock_);

    for (std::set<AccessTokenID>::iterator it = tokenIdSet_.begin(); it != tokenIdSet_.end(); ++it) {
        AccessTokenID tokenId = *it;
        AccessTokenIDInner *idInnerExist = reinterpret_cast<AccessTokenIDInner *>(&tokenId);
        if ((type == idInnerExist->type) && (idInnerExist->tokenUniqueID == idInner->tokenUniqueID)) {
            return ERR_TOKENID_HAS_EXISTED;
        }
    }
    tokenIdSet_.insert(id);
    return RET_SUCCESS;
}

AccessTokenID AccessTokenIDManager::CreateTokenId(ATokenTypeEnum type, int32_t dlpFlag, int32_t cloneFlag) const
{
    uint32_t rand = GetRandomUint32FromUrandom();
    if (rand == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get random failed");
        return 0;
    }

    AccessTokenIDInner innerId = {0};
    innerId.version = DEFAULT_TOKEN_VERSION;
    innerId.type = type;
    innerId.res = 0;
    innerId.cloneFlag = static_cast<uint32_t>(cloneFlag);
    innerId.renderFlag = 0;
    innerId.dlpFlag = static_cast<uint32_t>(dlpFlag);
    innerId.tokenUniqueID = rand & TOKEN_RANDOM_MASK;
    AccessTokenID tokenId = *reinterpret_cast<AccessTokenID *>(&innerId);
    return tokenId;
}

AccessTokenID AccessTokenIDManager::CreateAndRegisterTokenId(ATokenTypeEnum type, int32_t dlpFlag, int32_t cloneFlag)
{
    AccessTokenID tokenId = 0;
    // random maybe repeat, retry twice.
    for (int i = 0; i < MAX_CREATE_TOKEN_ID_RETRY; i++) {
        tokenId = CreateTokenId(type, dlpFlag, cloneFlag);
        if (tokenId == INVALID_TOKENID) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Create tokenId failed");
            return INVALID_TOKENID;
        }

        int ret = RegisterTokenId(tokenId, type);
        if (ret == RET_SUCCESS) {
            break;
        } else if (i < MAX_CREATE_TOKEN_ID_RETRY - 1) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Reigster tokenId failed(error=%{public}d), maybe repeat, retry.", ret);
        } else {
            LOGE(ATM_DOMAIN, ATM_TAG, "Reigster tokenId finally failed(error=%{public}d).", ret);
            tokenId = INVALID_TOKENID;
        }
    }
    return tokenId;
}

void AccessTokenIDManager::ReleaseTokenId(AccessTokenID id)
{
    Utils::UniqueWriteGuard<Utils::RWLock> idGuard(this->tokenIdLock_);
    if (tokenIdSet_.count(id) == 0) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Id %{public}x is not exist", id);
        return;
    }
    tokenIdSet_.erase(id);
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
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
