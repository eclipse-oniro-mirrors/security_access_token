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

#include "callback_manager.h"

#include <future>
#include <thread>
#include <datetime_ex.h>

#include "access_token.h"
#include "access_token_error.h"
#include "perm_state_callback_death_recipient.h"


namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "CallbackManager"};
static const time_t MAX_TIMEOUT_SEC = 30;
static const uint32_t MAX_CALLBACK_SIZE = 1024;
}

CallbackManager& CallbackManager::GetInstance()
{
    static CallbackManager instance;
    return instance;
}

CallbackManager::CallbackManager() : callbackDeathRecipient_(sptr<IRemoteObject::DeathRecipient>(
    new (std::nothrow) PermStateCallbackDeathRecipient()))
{
}

CallbackManager::~CallbackManager()
{
}

int32_t CallbackManager::AddCallback(
    const std::shared_ptr<PermStateChangeScope>& callbackScopePtr, const sptr<IRemoteObject>& callback)
{
    if ((callbackScopePtr == nullptr) || (callback == nullptr)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "input is nullptr");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (callbackInfoList_.size() >= MAX_CALLBACK_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback size has reached limitation");
        return AccessTokenError::ERR_EXCEEDED_MAXNUM_REGISTRATION_LIMIT;
    }
    callback->AddDeathRecipient(callbackDeathRecipient_);

    CallbackRecord recordInstance;
    recordInstance.callbackObject_ = callback;
    recordInstance.scopePtr_ = callbackScopePtr;

    callbackInfoList_.emplace_back(recordInstance);

    ACCESSTOKEN_LOG_INFO(LABEL, "recordInstance is added");
    return RET_SUCCESS;
}

int32_t CallbackManager::RemoveCallback(const sptr<IRemoteObject>& callback)
{
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback is nullptr");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    for (auto it = callbackInfoList_.begin(); it != callbackInfoList_.end(); ++it) {
        if (callback == (*it).callbackObject_) {
            ACCESSTOKEN_LOG_INFO(LABEL, "find callback");
            if (callbackDeathRecipient_ != nullptr) {
                callback->RemoveDeathRecipient(callbackDeathRecipient_);
            }
            (*it).callbackObject_ = nullptr;
            callbackInfoList_.erase(it);
            break;
        }
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "callbackInfoList_ %{public}u", (uint32_t)callbackInfoList_.size());
    return RET_SUCCESS;
}

bool CallbackManager::CalledAccordingToTokenIdLlist(
    const std::vector<AccessTokenID>& tokenIDList, AccessTokenID tokenID)
{
    if (tokenIDList.empty()) {
        return true;
    }
    return std::any_of(tokenIDList.begin(), tokenIDList.end(),
        [tokenID](AccessTokenID id) { return id == tokenID; });
}

bool CallbackManager::CalledAccordingToPermLlist(const std::vector<std::string>& permList, const std::string& permName)
{
    if (permList.empty()) {
        return true;
    }
    return std::any_of(permList.begin(), permList.end(),
        [permName](const std::string& perm) { return perm == permName; });
}

void CallbackManager::ExecuteCallbackAsync(AccessTokenID tokenID, const std::string& permName, int32_t changeType)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "entry");
    auto callbackStart = [&]() {
        ACCESSTOKEN_LOG_INFO(LABEL, "callbackStart");
        std::vector<sptr<IRemoteObject>> list;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = callbackInfoList_.begin(); it != callbackInfoList_.end(); ++it) {
                std::shared_ptr<PermStateChangeScope> scopePtr_ = (*it).scopePtr_;
                if (scopePtr_ == nullptr) {
                    ACCESSTOKEN_LOG_ERROR(LABEL, "scopePtr_ is nullptr");
                    continue;
                }
                if (!CalledAccordingToTokenIdLlist(scopePtr_->tokenIDs, tokenID) ||
                    !CalledAccordingToPermLlist(scopePtr_->permList, permName)) {
                        ACCESSTOKEN_LOG_INFO(LABEL,
                            "tokenID is %{public}u, permName is  %{public}s", tokenID, permName.c_str());
                        continue;
                }
                list.emplace_back((*it).callbackObject_);
            }
        }
        for (auto it = list.begin(); it != list.end(); ++it) {
            auto callback = iface_cast<IPermissionStateCallback>(*it);
            if (callback != nullptr) {
                ACCESSTOKEN_LOG_INFO(LABEL, "callback excute");
                PermStateChangeInfo resInfo;
                resInfo.PermStateChangeType = changeType;
                resInfo.permissionName = permName;
                resInfo.tokenID = tokenID;
                callback->PermStateChangeCallback(resInfo);
            }
        }
    };

    std::packaged_task<void()> callbackTask(callbackStart);
    std::future<void> fut = callbackTask.get_future();
    std::make_unique<std::thread>(std::move(callbackTask))->detach();

    ACCESSTOKEN_LOG_DEBUG(LABEL, "Waiting for the callback execution complete...");
    std::future_status status = fut.wait_for(std::chrono::seconds(MAX_TIMEOUT_SEC));
    if (status == std::future_status::timeout) {
        ACCESSTOKEN_LOG_WARN(LABEL, "callbackTask callback execution timeout");
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "The callback execution is complete");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
