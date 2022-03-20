/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "token_modify_notifier.h"

#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "token_sync_kit.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenModifyNotifier"};
}

TokenModifyNotifier::TokenModifyNotifier() : hasInited_(false) {}

TokenModifyNotifier::~TokenModifyNotifier() {}

void TokenModifyNotifier::AddHapTokenObservation(AccessTokenID tokenID)
{
    if (AccessTokenIDManager::GetInstance().GetTokenIdType(tokenID) != TOKEN_HAP) {
        ACCESSTOKEN_LOG_INFO(LABEL, "Observation token is not hap token");
        return;
    }
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->Notifylock_);
    if (observationSet_.count(tokenID) <= 0) {
        observationSet_.insert(tokenID);
    }
}

void TokenModifyNotifier::NotifyTokenDelete(AccessTokenID tokenID)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->Notifylock_);
    if (observationSet_.count(tokenID) <= 0) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "hap token is not observed");
        return;
    }
    observationSet_.erase(tokenID);
    deleteTokenList_.emplace_back(tokenID);
    NotifyTokenChangedIfNeed();
}

void TokenModifyNotifier::NotifyTokenModify(AccessTokenID tokenID)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->Notifylock_);
    if (observationSet_.count(tokenID) <= 0) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "hap token is not observed");
        return;
    }
    modifiedTokenList_.emplace_back(tokenID);
    NotifyTokenChangedIfNeed();
}

TokenModifyNotifier& TokenModifyNotifier::GetInstance()
{
    static TokenModifyNotifier instance;

    if (!instance.hasInited_) {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(instance.initLock_);
        if (!instance.hasInited_) {
            instance.notifyTokenWorker_.Start(1);
            instance.hasInited_ = true;
        }
    }

    return instance;
}

void TokenModifyNotifier::NotifyTokenSyncTask()
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->Notifylock_);
    for (AccessTokenID deleteToken : deleteTokenList_) {
        TokenSyncKit::DeleteRemoteHapTokenInfo(deleteToken);
    }

    for (AccessTokenID modifyToken : modifiedTokenList_) {
        HapTokenInfoForSync hapSync;
        int ret = AccessTokenInfoManager::GetInstance().GetHapTokenSync(modifyToken, hapSync);
        if (ret != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "the hap token 0x%{public}x need to sync is not found!", modifyToken);
            continue;
        }
        TokenSyncKit::UpdateRemoteHapTokenInfo(hapSync);
    }
    deleteTokenList_.clear();
    modifiedTokenList_.clear();
}
void TokenModifyNotifier::NotifyTokenChangedIfNeed()
{
    if (notifyTokenWorker_.GetCurTaskNum() > 1) {
        ACCESSTOKEN_LOG_INFO(LABEL, " has notify task!");
        return;
    }

    notifyTokenWorker_.AddTask([]() {
        TokenModifyNotifier::GetInstance().NotifyTokenSyncTask();
    });
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
