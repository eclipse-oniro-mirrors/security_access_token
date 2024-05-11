/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "active_status_callback_manager.h"

#include <future>
#include <thread>
#include <datetime_ex.h>
#include <pthread.h>

#include "accesstoken_dfx_define.h"
#include "accesstoken_log.h"
#include "privacy_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "ActiveStatusCallbackManager"
};
static const uint32_t MAX_CALLBACK_SIZE = 1024;
std::recursive_mutex g_instanceMutex;
}

ActiveStatusCallbackManager& ActiveStatusCallbackManager::GetInstance()
{
    static ActiveStatusCallbackManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new ActiveStatusCallbackManager();
        }
    }
    return *instance;
}

ActiveStatusCallbackManager::ActiveStatusCallbackManager()
    : callbackDeathRecipient_(sptr<IRemoteObject::DeathRecipient>(
        new (std::nothrow) PermActiveStatusCallbackDeathRecipient()))
{
}

ActiveStatusCallbackManager::~ActiveStatusCallbackManager()
{
}

#ifdef EVENTHANDLER_ENABLE
void ActiveStatusCallbackManager::InitEventHandler(const std::shared_ptr<AccessEventHandler>& eventHandler)
{
    eventHandler_ = eventHandler;
}
#endif

int32_t ActiveStatusCallbackManager::AddCallback(
    const std::vector<std::string>& permList, const sptr<IRemoteObject>& callback)
{
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "input is nullptr");
        return PrivacyError::ERR_PARAM_INVALID;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (callbackDataList_.size() >= MAX_CALLBACK_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "list size has reached max value");
        return PrivacyError::ERR_CALLBACKS_EXCEED_LIMITATION;
    }
    callback->AddDeathRecipient(callbackDeathRecipient_);

    CallbackData recordInstance;
    recordInstance.callbackObject_ = callback;
    recordInstance.permList_ = permList;

    callbackDataList_.emplace_back(recordInstance);

    ACCESSTOKEN_LOG_INFO(LABEL, "recordInstance is added");
    return RET_SUCCESS;
}

int32_t ActiveStatusCallbackManager::RemoveCallback(const sptr<IRemoteObject>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called");
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Callback is nullptr.");
        return PrivacyError::ERR_PARAM_INVALID;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    for (auto it = callbackDataList_.begin(); it != callbackDataList_.end(); ++it) {
        if (callback == (*it).callbackObject_) {
            ACCESSTOKEN_LOG_INFO(LABEL, "find callback");
            if (callbackDeathRecipient_ != nullptr) {
                callback->RemoveDeathRecipient(callbackDeathRecipient_);
            }
            (*it).callbackObject_ = nullptr;
            callbackDataList_.erase(it);
            break;
        }
    }
    return RET_SUCCESS;
}

bool ActiveStatusCallbackManager::NeedCalled(const std::vector<std::string>& permList, const std::string& permName)
{
    if (permList.empty()) {
        return true;
    }
    return std::any_of(permList.begin(), permList.end(),
        [permName](const std::string& perm) { return perm == permName; });
}


void ActiveStatusCallbackManager::ActiveStatusChange(
    AccessTokenID tokenId, const std::string& permName, const std::string& deviceId, ActiveChangeType changeType)
{
    std::vector<sptr<IRemoteObject>> list;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = callbackDataList_.begin(); it != callbackDataList_.end(); ++it) {
            std::vector<std::string> permList = (*it).permList_;
            if (!NeedCalled(permList, permName)) {
                ACCESSTOKEN_LOG_INFO(LABEL, "tokenId %{public}u, permName %{public}s", tokenId, permName.c_str());
                continue;
            }
            list.emplace_back((*it).callbackObject_);
        }
    }
    for (auto it = list.begin(); it != list.end(); ++it) {
        auto callback = iface_cast<IPermActiveStatusCallback>(*it);
        if (callback != nullptr) {
            ActiveChangeResponse resInfo;
            resInfo.type = changeType;
            resInfo.permissionName = permName;
            resInfo.tokenID = tokenId;
            resInfo.deviceId = deviceId;
            ACCESSTOKEN_LOG_INFO(LABEL,
                "callback execute tokenId %{public}u, permision %{public}s changeType %{public}d",
                tokenId, permName.c_str(), changeType);
            callback->ActiveStatusChangeCallback(resInfo);
        }
    }
}

void ActiveStatusCallbackManager::ExecuteCallbackAsync(
    AccessTokenID tokenId, const std::string& permName, const std::string& deviceId, ActiveChangeType changeType)
{
    if (changeType == PERM_ACTIVE_IN_BACKGROUND) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK_EVENT",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "CODE", BACKGROUND_CALL_EVENT,
            "CALLER_TOKENID", tokenId, "PERMISSION_NAME", permName, "REASON", "background call");
    }

#ifdef EVENTHANDLER_ENABLE
    if (eventHandler_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "fail to get EventHandler");
        return;
    }
    std::string taskName = permName + std::to_string(tokenId);
    ACCESSTOKEN_LOG_INFO(LABEL, "add permission task name:%{public}s", taskName.c_str());
    std::function<void()> task = ([tokenId, permName, deviceId, changeType]() {
        ActiveStatusCallbackManager::GetInstance().ActiveStatusChange(tokenId, permName, deviceId, changeType);
        ACCESSTOKEN_LOG_INFO(LABEL, "token: %{public}d, ActiveStatusChange end", tokenId);
    });
    eventHandler_->ProxyPostTask(task, taskName);
    ACCESSTOKEN_LOG_INFO(LABEL, "The callback execution is complete");
    return;
#else
    ACCESSTOKEN_LOG_INFO(LABEL, "event handler is unenabled");
    return;
#endif
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
