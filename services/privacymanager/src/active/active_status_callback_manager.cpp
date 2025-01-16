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
#include "ipc_skeleton.h"
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
            ActiveStatusCallbackManager* tmp = new ActiveStatusCallbackManager();
            instance = std::move(tmp);
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
    AccessTokenID regiterTokenId, const std::vector<std::string>& permList, const sptr<IRemoteObject>& callback)
{
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Input is nullptr");
        return PrivacyError::ERR_PARAM_INVALID;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (callbackDataList_.size() >= MAX_CALLBACK_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "List size has reached max value");
        return PrivacyError::ERR_CALLBACKS_EXCEED_LIMITATION;
    }
    if (!callback->AddDeathRecipient(callbackDeathRecipient_)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "add death recipient failed");
        return PrivacyError::ERR_ADD_DEATH_RECIPIENT_FAILED;
    }

    CallbackData recordInstance;
    recordInstance.registerTokenId = regiterTokenId;
    recordInstance.callbackObject_ = callback;
    recordInstance.permList_ = permList;

    callbackDataList_.emplace_back(recordInstance);

    ACCESSTOKEN_LOG_INFO(LABEL, "RecordInstance is added");
    return RET_SUCCESS;
}

int32_t ActiveStatusCallbackManager::RemoveCallback(const sptr<IRemoteObject>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Called");
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Callback is nullptr.");
        return PrivacyError::ERR_PARAM_INVALID;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    for (auto it = callbackDataList_.begin(); it != callbackDataList_.end(); ++it) {
        if (callback == (*it).callbackObject_) {
            ACCESSTOKEN_LOG_INFO(LABEL, "Find callback");
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


void ActiveStatusCallbackManager::ActiveStatusChange(ActiveChangeResponse& info)
{
    std::vector<sptr<IRemoteObject>> list;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = callbackDataList_.begin(); it != callbackDataList_.end(); ++it) {
            std::vector<std::string> permList = (*it).permList_;
            if (!NeedCalled(permList, info.permissionName)) {
                ACCESSTOKEN_LOG_INFO(LABEL, "TokenId %{public}u, perm %{public}s", info.tokenID,
                    info.permissionName.c_str());
                continue;
            }
            list.emplace_back((*it).callbackObject_);
        }
    }
    for (auto it = list.begin(); it != list.end(); ++it) {
        sptr<IPermActiveStatusCallback> callback = new PermActiveStatusChangeCallbackProxy(*it);
        if (callback != nullptr) {
            ACCESSTOKEN_LOG_INFO(LABEL, "callback execute callingTokenId %{public}u, tokenId %{public}u, "
                "permision %{public}s, changeType %{public}d, usedType %{public}d, pid %{public}d", info.callingTokenID,
                info.tokenID, info.permissionName.c_str(), info.type, info.usedType, info.pid);
            callback->ActiveStatusChangeCallback(info);
        }
    }
}

void ActiveStatusCallbackManager::ExecuteCallbackAsync(ActiveChangeResponse& info)
{
    if (info.type == PERM_ACTIVE_IN_BACKGROUND) {
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK_EVENT",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "CODE", BACKGROUND_CALL_EVENT,
            "CALLER_TOKENID", info.tokenID, "PERMISSION_NAME", info.permissionName, "REASON", "background call");
    }

#ifdef EVENTHANDLER_ENABLE
    if (eventHandler_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to get EventHandler");
        return;
    }
    std::string taskName = info.permissionName + std::to_string(info.tokenID);
    ACCESSTOKEN_LOG_INFO(LABEL, "Add permission task name:%{public}s", taskName.c_str());
    std::function<void()> task = ([info]() mutable {
        ActiveStatusCallbackManager::GetInstance().ActiveStatusChange(info);
        ACCESSTOKEN_LOG_INFO(LABEL,
            "Token: %{public}u, permName:  %{public}s, changeType: %{public}d, ActiveStatusChange end",
            info.tokenID, info.permissionName.c_str(), info.type);
    });
    eventHandler_->ProxyPostTask(task, taskName);
    ACCESSTOKEN_LOG_INFO(LABEL, "The callback execution is complete");
    return;
#else
    ACCESSTOKEN_LOG_INFO(LABEL, "Event handler is unenabled");
    return;
#endif
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
