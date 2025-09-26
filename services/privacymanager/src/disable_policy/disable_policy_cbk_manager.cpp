/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "disable_policy_cbk_manager.h"

#include <future>
#include <thread>
#include <datetime_ex.h>
#include <pthread.h>

#include "accesstoken_common_log.h"
#include "ipc_skeleton.h"
#include "privacy_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
#ifndef MAX_COUNT_TEST
static const uint32_t MAX_CALLBACK_SIZE = 1024;
#else
static const uint32_t MAX_CALLBACK_SIZE = 20;
#endif
}

DisablePolicyCbkManager::DisablePolicyCbkManager()
    : callbackDeathRecipient_(sptr<IRemoteObject::DeathRecipient>(
        new (std::nothrow) PermDisablePolicyCbkDeathRecipient()))
{}

DisablePolicyCbkManager::~DisablePolicyCbkManager()
{}

#ifdef EVENTHANDLER_ENABLE
void DisablePolicyCbkManager::InitEventHandler(const std::shared_ptr<AccessEventHandler>& eventHandler)
{
    eventHandler_ = eventHandler;
}
#endif

uint32_t DisablePolicyCbkManager::GetCurCallbackSize()
{
    std::shared_lock<std::shared_mutex> lock(callbackMutex_);
    return callbackDataList_.size();
}

void DisablePolicyCbkManager::AddToCallbackList(AccessTokenID registerTokenId, const std::vector<std::string>& permList,
    const sptr<IRemoteObject>& callback)
{
    DisableCallbackData data(registerTokenId, permList, callback);

    std::unique_lock<std::shared_mutex> lock(callbackMutex_);
    callbackDataList_.emplace_back(data);

    LOGI(PRI_DOMAIN, PRI_TAG, "Callback has added!");
}

void DisablePolicyCbkManager::RemoveFromCallbackList(const sptr<IRemoteObject>& callback)
{
    std::unique_lock<std::shared_mutex> lock(callbackMutex_);
    for (auto it = callbackDataList_.begin(); it != callbackDataList_.end(); ++it) {
        if (callback == it->callbackObject) {
            LOGI(PRI_DOMAIN, PRI_TAG, "Find callback");

            if (callbackDeathRecipient_ != nullptr) {
                callback->RemoveDeathRecipient(callbackDeathRecipient_);
            }

            it->callbackObject = nullptr;
            callbackDataList_.erase(it);
            break;
        }
    }
}

int32_t DisablePolicyCbkManager::AddCallback(AccessTokenID registerTokenId, const std::vector<std::string>& permList,
    const sptr<IRemoteObject>& callback)
{
    if (callback == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Callback is nullptr!");
        return PrivacyError::ERR_PARAM_INVALID;
    }

    if (GetCurCallbackSize() >= MAX_CALLBACK_SIZE) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Callback list size has reach the max value.");
        return PrivacyError::ERR_CALLBACKS_EXCEED_LIMITATION;
    }

    if (callback->IsProxyObject() &&
        ((callbackDeathRecipient_ == nullptr) || !callback->AddDeathRecipient(callbackDeathRecipient_))) {
        LOGE(PRI_DOMAIN, PRI_TAG, "add death recipient failed.");
        return PrivacyError::ERR_ADD_DEATH_RECIPIENT_FAILED;
    }

    AddToCallbackList(registerTokenId, permList, callback);
    return RET_SUCCESS;
}

int32_t DisablePolicyCbkManager::RemoveCallback(const sptr<IRemoteObject>& callback)
{
    if (callback == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Callback is nullptr!");
        return PrivacyError::ERR_PARAM_INVALID;
    }

    RemoveFromCallbackList(callback);
    return RET_SUCCESS;
}

bool DisablePolicyCbkManager::NeedCalled(const std::vector<std::string>& permList, const std::string& permName)
{
    if (permList.empty()) {
        return true;
    }
    return std::any_of(permList.begin(), permList.end(),
        [permName](const std::string& perm) { return perm == permName; });
}

void DisablePolicyCbkManager::GetCallbackFromList(const std::string& permissionName,
    std::vector<sptr<IRemoteObject>>& list)
{
    std::vector<std::string> permList;
    std::shared_lock<std::shared_mutex> lock(callbackMutex_);
    for (auto it = callbackDataList_.begin(); it != callbackDataList_.end(); ++it) {
        permList = it->permList;
        if (!NeedCalled(permList, permissionName)) {
            continue;
        }

        LOGI(PRI_DOMAIN, PRI_TAG, "TokenId %{public}u, perm %{public}s need callback!", it->registerTokenId,
            permissionName.c_str());
        list.emplace_back(it->callbackObject);
    }
}

void DisablePolicyCbkManager::PermDisablePolicyCallback(const PermDisablePolicyInfo& info)
{
    std::vector<sptr<IRemoteObject>> list;
    GetCallbackFromList(info.permissionName, list);
    
    for (auto it = list.begin(); it != list.end(); ++it) {
        sptr<IPermDisablePolicyCallback> callback = new (std::nothrow) PermDisablePolicyCbkProxy(*it);
        if (callback == nullptr) {
            continue;
        }

        callback->PermDisablePolicyCallback(info);
    }

    LOGI(PRI_DOMAIN, PRI_TAG, "Callback send end!");
}

void DisablePolicyCbkManager::ExecuteCallbackAsync(const PermDisablePolicyInfo& info)
{
#ifdef EVENTHANDLER_ENABLE
    if (eventHandler_ == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Fail to get EventHandler!");
        return;
    }

    AccessTokenID callerTokenID = IPCSkeleton::GetCallingTokenID();
    std::string taskName = std::to_string(callerTokenID) + info.permissionName + (info.isDisable ? "true" : "false");
    LOGI(PRI_DOMAIN, PRI_TAG, "Add permission task name %{public}s", taskName.c_str());
    std::function<void()> task = ([info]() {
        DisablePolicyCbkManager::GetInstance()->PermDisablePolicyCallback(info);
    });
    eventHandler_->ProxyPostTask(task, taskName);
    LOGI(PRI_DOMAIN, PRI_TAG, "The callback execution is complete");
    return;
#else
    LOGI(PRI_DOMAIN, PRI_TAG, "Event handler is unenabled");
    return;
#endif
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
