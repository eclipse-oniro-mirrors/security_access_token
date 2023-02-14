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

#include "active_status_callback_manager.h"

#include <future>
#include <thread>
#include <datetime_ex.h>

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
static const time_t MAX_TIMEOUT_SEC = 30;
static const uint32_t MAX_CALLBACK_SIZE = 1024;
}

ActiveStatusCallbackManager& ActiveStatusCallbackManager::GetInstance()
{
    static ActiveStatusCallbackManager instance;
    return instance;
}

ActiveStatusCallbackManager::ActiveStatusCallbackManager()
    : callbackDeathRecipient_(sptr<IRemoteObject::DeathRecipient>(
        new (std::nothrow) PermActiveStatusCallbackDeathRecipient()))
{
}

ActiveStatusCallbackManager::~ActiveStatusCallbackManager()
{
}

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
        ACCESSTOKEN_LOG_ERROR(LABEL, "callback is nullptr");
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

void ActiveStatusCallbackManager::ExecuteCallbackAsync(
    AccessTokenID tokenId, const std::string& permName, const std::string& deviceId, ActiveChangeType changeType)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "entry");
    if (changeType == PERM_ACTIVE_IN_BACKGROUND) {
        HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK_EVENT",
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "CODE", BACKGROUND_CALL_EVENT,
            "CALLER_TOKENID", tokenId, "PERMISSION_NAME", permName, "REASON", "background call");
    }
    auto callbackFunc = [&]() {
        ACCESSTOKEN_LOG_INFO(LABEL, "callbackStart");
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
                ACCESSTOKEN_LOG_INFO(LABEL, "callback excute changeType %{public}d", changeType);
                callback->ActiveStatusChangeCallback(resInfo);
            }
        }
    };

    std::packaged_task<void()> callbackTask(callbackFunc);
    std::future<void> fut = callbackTask.get_future();
    std::make_unique<std::thread>(std::move(callbackTask))->detach();

    ACCESSTOKEN_LOG_INFO(LABEL, "Waiting for the callback execution complete...");
    std::future_status status = fut.wait_for(std::chrono::seconds(MAX_TIMEOUT_SEC));
    if (status == std::future_status::timeout) {
        ACCESSTOKEN_LOG_WARN(LABEL, "callbackTask callback execution timeout");
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "The callback execution is complete");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
