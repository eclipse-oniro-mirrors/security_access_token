/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "accesstoken_callback_proxys.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "libraryloader.h"
#include "token_sync_kit_loader.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
}

TokenModifyNotifier::TokenModifyNotifier() : hasInited_(false), notifyTokenWorker_("TokenModify") {}

TokenModifyNotifier::~TokenModifyNotifier()
{
    if (!hasInited_) {
        return;
    }
    this->notifyTokenWorker_.Stop();
    this->hasInited_ = false;
}

void TokenModifyNotifier::AddHapTokenObservation(AccessTokenID tokenID)
{
    if (AccessTokenIDManager::GetInstance().GetTokenIdType(tokenID) != TOKEN_HAP) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Observation token is not hap token");
        return;
    }
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->listLock_);
    if (observationSet_.count(tokenID) <= 0) {
        observationSet_.insert(tokenID);
    }
}

void TokenModifyNotifier::NotifyTokenDelete(AccessTokenID tokenID)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->listLock_);
    if (observationSet_.count(tokenID) <= 0) {
        LOGD(ATM_DOMAIN, ATM_TAG, "Hap token is not observed");
        return;
    }
    observationSet_.erase(tokenID);
    deleteTokenList_.emplace_back(tokenID);
    NotifyTokenChangedIfNeed();
}

void TokenModifyNotifier::NotifyTokenModify(AccessTokenID tokenID)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->listLock_);
    if (observationSet_.count(tokenID) <= 0) {
        LOGD(ATM_DOMAIN, ATM_TAG, "Hap token is not observed");
        return;
    }
    modifiedTokenList_.emplace_back(tokenID);
    NotifyTokenChangedIfNeed();
}

TokenModifyNotifier& TokenModifyNotifier::GetInstance()
{
    static TokenModifyNotifier* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            TokenModifyNotifier* tmp = new TokenModifyNotifier();
            instance = std::move(tmp);
        }
    }

    if (!instance->hasInited_) {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(instance->initLock_);
        if (!instance->hasInited_) {
            instance->notifyTokenWorker_.Start(1);
            instance->hasInited_ = true;
        }
    }

    return *instance;
}

void TokenModifyNotifier::NotifyTokenSyncTask()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Called!");

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->notifyLock_);
    LOGI(ATM_DOMAIN, ATM_TAG, "Start execution!");
    LibraryLoader loader(TOKEN_SYNC_LIBPATH);
    TokenSyncKitInterface* tokenSyncKit = loader.GetObject<TokenSyncKitInterface>();
    if (tokenSyncKit == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Dlopen libtokensync_sdk failed.");
        return;
    }

    std::vector<AccessTokenID> deleteList;
    std::vector<AccessTokenID> modifiedList;
    {
        Utils::UniqueWriteGuard<Utils::RWLock> listGuard(this->listLock_);
        deleteList = deleteTokenList_;
        modifiedList = modifiedTokenList_;
        deleteTokenList_.clear();
        modifiedTokenList_.clear();
    }

    for (AccessTokenID deleteToken : deleteList) {
        int ret = TOKEN_SYNC_SUCCESS;
        if (tokenSyncCallbackObject_ != nullptr) {
            ret = tokenSyncCallbackObject_->DeleteRemoteHapTokenInfo(deleteToken);
        }
        ret = tokenSyncKit->DeleteRemoteHapTokenInfo(deleteToken);
        if (ret != TOKEN_SYNC_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Fail to delete remote haptoken info, ret is %{public}d", ret);
        }
    }

    for (AccessTokenID modifyToken : modifiedList) {
        HapTokenInfoForSync hapSync;
        int ret = AccessTokenInfoManager::GetInstance().GetHapTokenSync(modifyToken, hapSync);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "The hap token 0x%{public}x need to sync is not found!", modifyToken);
            continue;
        }
        if (tokenSyncCallbackObject_ != nullptr) {
            ret = tokenSyncCallbackObject_->UpdateRemoteHapTokenInfo(hapSync);
        }
        ret = tokenSyncKit->UpdateRemoteHapTokenInfo(hapSync);
        if (ret != TOKEN_SYNC_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Fail to update remote haptoken info, ret is %{public}d", ret);
        }
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Over!");
}

int32_t TokenModifyNotifier::GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID)
{
    if (tokenSyncCallbackObject_ != nullptr) {
        Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->notifyLock_);
        int32_t ret = tokenSyncCallbackObject_->GetRemoteHapTokenInfo(deviceID, tokenID);
        if (ret != TOKEN_SYNC_OPENSOURCE_DEVICE) {
            return ret;
        }
    }

    LibraryLoader loader(TOKEN_SYNC_LIBPATH);
    TokenSyncKitInterface* tokenSyncKit = loader.GetObject<TokenSyncKitInterface>();
    if (tokenSyncKit == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Dlopen libtokensync_sdk failed.");
        return ERR_LOAD_SO_FAILED;
    }
    return tokenSyncKit->GetRemoteHapTokenInfo(deviceID, tokenID);
}

int32_t TokenModifyNotifier::RegisterTokenSyncCallback(const sptr<IRemoteObject>& callback)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->notifyLock_);
    tokenSyncCallbackObject_ = new TokenSyncCallbackProxy(callback);
    tokenSyncCallbackDeathRecipient_ = sptr<TokenSyncCallbackDeathRecipient>::MakeSptr();
    callback->AddDeathRecipient(tokenSyncCallbackDeathRecipient_);
    LOGI(ATM_DOMAIN, ATM_TAG, "Register token sync callback successful.");
    return ERR_OK;
}

int32_t TokenModifyNotifier::UnRegisterTokenSyncCallback()
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->notifyLock_);
    if (tokenSyncCallbackObject_ != nullptr && tokenSyncCallbackDeathRecipient_ != nullptr) {
        tokenSyncCallbackObject_->AsObject()->RemoveDeathRecipient(tokenSyncCallbackDeathRecipient_);
    }
    tokenSyncCallbackObject_ = nullptr;
    tokenSyncCallbackDeathRecipient_ = nullptr;
    LOGI(ATM_DOMAIN, ATM_TAG, "Unregister token sync callback successful.");
    return ERR_OK;
}

void TokenModifyNotifier::NotifyTokenChangedIfNeed()
{
    if (notifyTokenWorker_.GetCurTaskNum() > 1) {
        LOGI(ATM_DOMAIN, ATM_TAG, " has notify task! taskNum is %{public}zu.", notifyTokenWorker_.GetCurTaskNum());
        return;
    }

    notifyTokenWorker_.AddTask([]() {
        TokenModifyNotifier::GetInstance().NotifyTokenSyncTask();
    });
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
