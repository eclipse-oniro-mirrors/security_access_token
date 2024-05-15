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
#include "accesstoken_log.h"
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
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "TokenModifyNotifier"};
}

#ifdef RESOURCESCHEDULE_FFRT_ENABLE
TokenModifyNotifier::TokenModifyNotifier() : hasInited_(false), curTaskNum_(0) {}
#else
TokenModifyNotifier::TokenModifyNotifier() : hasInited_(false), notifyTokenWorker_("TokenModify") {}
#endif

TokenModifyNotifier::~TokenModifyNotifier()
{
    if (!hasInited_) {
        return;
    }
#ifndef RESOURCESCHEDULE_FFRT_ENABLE
    this->notifyTokenWorker_.Stop();
#endif
    this->hasInited_ = false;
}

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
    static TokenModifyNotifier* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new TokenModifyNotifier();
        }
    }

    if (!instance->hasInited_) {
        Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(instance->initLock_);
        if (!instance->hasInited_) {
#ifndef RESOURCESCHEDULE_FFRT_ENABLE
            instance->notifyTokenWorker_.Start(1);
#endif
            instance->hasInited_ = true;
        }
    }

    return *instance;
}

void TokenModifyNotifier::NotifyTokenSyncTask()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called!");

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->Notifylock_);
    LibraryLoader loader(TOKEN_SYNC_LIBPATH);
    TokenSyncKitInterface* tokenSyncKit = loader.GetObject<TokenSyncKitInterface>();
    if (tokenSyncKit == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Dlopen libtokensync_sdk failed.");
        return;
    }
    for (AccessTokenID deleteToken : deleteTokenList_) {
        if (tokenSyncCallbackObject_ != nullptr) {
            tokenSyncCallbackObject_->DeleteRemoteHapTokenInfo(deleteToken);
        }
        tokenSyncKit->DeleteRemoteHapTokenInfo(deleteToken);
    }

    for (AccessTokenID modifyToken : modifiedTokenList_) {
        HapTokenInfoForSync hapSync;
        int ret = AccessTokenInfoManager::GetInstance().GetHapTokenSync(modifyToken, hapSync);
        if (ret != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "the hap token 0x%{public}x need to sync is not found!", modifyToken);
            continue;
        }
        if (tokenSyncCallbackObject_ != nullptr) {
            tokenSyncCallbackObject_->UpdateRemoteHapTokenInfo(hapSync);
        }
        tokenSyncKit->UpdateRemoteHapTokenInfo(hapSync);
    }
    deleteTokenList_.clear();
    modifiedTokenList_.clear();

    ACCESSTOKEN_LOG_INFO(LABEL, "over!");
}

int32_t TokenModifyNotifier::GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID)
{
    if (tokenSyncCallbackObject_ != nullptr) {
        Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->Notifylock_);
        int32_t ret = tokenSyncCallbackObject_->GetRemoteHapTokenInfo(deviceID, tokenID);
        if (ret != TOKEN_SYNC_OPENSOURCE_DEVICE) {
            return ret;
        }
    }

    LibraryLoader loader(TOKEN_SYNC_LIBPATH);
    TokenSyncKitInterface* tokenSyncKit = loader.GetObject<TokenSyncKitInterface>();
    if (tokenSyncKit == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Dlopen libtokensync_sdk failed.");
        return ERR_LOAD_SO_FAILED;
    }
    return tokenSyncKit->GetRemoteHapTokenInfo(deviceID, tokenID);
}

int32_t TokenModifyNotifier::RegisterTokenSyncCallback(const sptr<IRemoteObject>& callback)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->Notifylock_);
    tokenSyncCallbackObject_ = iface_cast<ITokenSyncCallback>(callback);
    tokenSyncCallbackDeathRecipient_ = sptr<TokenSyncCallbackDeathRecipient>(new TokenSyncCallbackDeathRecipient);
    callback->AddDeathRecipient(tokenSyncCallbackDeathRecipient_);
    ACCESSTOKEN_LOG_INFO(LABEL, "Register token sync callback successful.");
    return ERR_OK;
}

int32_t TokenModifyNotifier::UnRegisterTokenSyncCallback()
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->Notifylock_);
    tokenSyncCallbackObject_ = nullptr;
    tokenSyncCallbackDeathRecipient_ = nullptr;
    ACCESSTOKEN_LOG_INFO(LABEL, "Unregister token sync callback successful.");
    return ERR_OK;
}

#ifdef RESOURCESCHEDULE_FFRT_ENABLE
int32_t TokenModifyNotifier::GetCurTaskNum()
{
    return curTaskNum_.load();
}

void TokenModifyNotifier::AddCurTaskNum()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Add task!");
    curTaskNum_++;
}

void TokenModifyNotifier::ReduceCurTaskNum()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Reduce task!");
    curTaskNum_--;
}
#endif

void TokenModifyNotifier::NotifyTokenChangedIfNeed()
{
#ifdef RESOURCESCHEDULE_FFRT_ENABLE
    if (GetCurTaskNum() > 1) {
        ACCESSTOKEN_LOG_INFO(LABEL, "has notify task! taskNum is %{public}d.", GetCurTaskNum());
        return;
    }

    std::string taskName = "TokenModify";
    auto tokenModify = []() {
        TokenModifyNotifier::GetInstance().NotifyTokenSyncTask();
        TokenModifyNotifier::GetInstance().ReduceCurTaskNum();
    };
    ffrt::submit(tokenModify, {}, {}, ffrt::task_attr().qos(ffrt::qos_default).name(taskName.c_str()));
    AddCurTaskNum();
#else
    if (notifyTokenWorker_.GetCurTaskNum() > 1) {
        ACCESSTOKEN_LOG_INFO(LABEL, " has notify task! taskNum is %{public}zu.", notifyTokenWorker_.GetCurTaskNum());
        return;
    }

    notifyTokenWorker_.AddTask([]() {
        TokenModifyNotifier::GetInstance().NotifyTokenSyncTask();
    });
#endif
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
