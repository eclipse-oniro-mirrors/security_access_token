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
#include "privacy_manager_client.h"

#include <algorithm>
#include "accesstoken_log.h"
#include "iservice_registry.h"
#include "privacy_error.h"
#include "privacy_manager_proxy.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyManagerClient"
};
} // namespace

const static int32_t MAX_CALLBACK_SIZE = 200;
const static int32_t MAX_PERM_LIST_SIZE = 1024;

PrivacyManagerClient& PrivacyManagerClient::GetInstance()
{
    static PrivacyManagerClient instance;
    return instance;
}

PrivacyManagerClient::PrivacyManagerClient()
{}

PrivacyManagerClient::~PrivacyManagerClient()
{}

int32_t PrivacyManagerClient::AddPermissionUsedRecord(
    AccessTokenID tokenID, const std::string& permissionName, int32_t successCount, int32_t failCount)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->AddPermissionUsedRecord(tokenID, permissionName, successCount, failCount);
}

int32_t PrivacyManagerClient::StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->StartUsingPermission(tokenID, permissionName);
}

int32_t PrivacyManagerClient::CreateStateChangeCbk(
    const std::shared_ptr<StateCustomizedCbk>& callback, sptr<StateChangeCallback>& callbackWrap)
{
    std::lock_guard<std::mutex> lock(stateCbkMutex_);

    if (stateChangeCallback_ != nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, " callback has been used");
        return PrivacyError::ERR_CALLBACK_ALREADY_EXIST;
    } else {
        callbackWrap = new (std::nothrow) StateChangeCallback(callback);
        if (callbackWrap == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "memory allocation for callbackWrap failed!");
            return PrivacyError::ERR_SERVICE_ABNORMAL;
        }
    }
    return RET_SUCCESS;
}

int32_t PrivacyManagerClient::StartUsingPermission(AccessTokenID tokenId, const std::string& permissionName,
    const std::shared_ptr<StateCustomizedCbk>& callback)
{
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "customizedCb is nullptr");
        return PrivacyError::ERR_PARAM_INVALID;
    }

    sptr<StateChangeCallback> callbackWrap = nullptr;
    int32_t result = CreateStateChangeCbk(callback, callbackWrap);
    if (result != RET_SUCCESS) {
        return result;
    }

    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    result = proxy->StartUsingPermission(tokenId, permissionName, callbackWrap->AsObject());
    if (result == RET_SUCCESS) {
        std::lock_guard<std::mutex> lock(stateCbkMutex_);
        stateChangeCallback_ = callbackWrap;
        ACCESSTOKEN_LOG_INFO(LABEL, "callbackObject added");
    }
    return result;
}

int32_t PrivacyManagerClient::StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    {
        std::lock_guard<std::mutex> lock(stateCbkMutex_);
        stateChangeCallback_ = nullptr;
    }

    return proxy->StopUsingPermission(tokenID, permissionName);
}

int32_t PrivacyManagerClient::RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->RemovePermissionUsedRecords(tokenID, deviceID);
}

int32_t PrivacyManagerClient::GetPermissionUsedRecords(
    const PermissionUsedRequest& request, PermissionUsedResult& result)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    PermissionUsedRequestParcel requestParcel;
    PermissionUsedResultParcel resultParcel;
    requestParcel.request = request;
    int32_t ret = proxy->GetPermissionUsedRecords(requestParcel, resultParcel);
    result = resultParcel.result;
    return ret;
}

int32_t PrivacyManagerClient::GetPermissionUsedRecords(const PermissionUsedRequest& request,
    const sptr<OnPermissionUsedRecordCallback>& callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    PermissionUsedRequestParcel requestParcel;
    requestParcel.request = request;
    return proxy->GetPermissionUsedRecords(requestParcel, callback);
}

int32_t PrivacyManagerClient::CreateActiveStatusChangeCbk(
    const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback, sptr<PermActiveStatusChangeCallback>& callbackWrap)
{
    std::lock_guard<std::mutex> lock(activeCbkMutex_);

    if (activeCbkMap_.size() >= MAX_CALLBACK_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "the maximum number of subscribers has been reached");
        return PrivacyError::ERR_CALLBACKS_EXCEED_LIMITATION;
    }

    auto goalCallback = activeCbkMap_.find(callback);
    if (goalCallback != activeCbkMap_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "activeCbkMap_ already has such callback");
        return PrivacyError::ERR_CALLBACK_ALREADY_EXIST;
    } else {
        callbackWrap =
            new (std::nothrow) PermActiveStatusChangeCallback(callback);
        if (!callbackWrap) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "memory allocation for callbackWrap failed!");
            return PrivacyError::ERR_MALLOC_FAILED;
        }
    }
    return RET_SUCCESS;
}

int32_t PrivacyManagerClient::RegisterPermActiveStatusCallback(
    const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called!");
    if (callback == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "customizedCb is nullptr");
        return PrivacyError::ERR_PARAM_INVALID;
    }

    sptr<PermActiveStatusChangeCallback> callbackWrap = nullptr;
    int32_t result = CreateActiveStatusChangeCbk(callback, callbackWrap);
    if (result != RET_SUCCESS) {
        return result;
    }

    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    std::vector<std::string> permList;
    callback->GetPermList(permList);
    if (permList.size() > MAX_PERM_LIST_SIZE) {
        return PrivacyError::ERR_PARAM_INVALID;
    }

    result = proxy->RegisterPermActiveStatusCallback(permList, callbackWrap->AsObject());
    if (result == RET_SUCCESS) {
        std::lock_guard<std::mutex> lock(activeCbkMutex_);
        activeCbkMap_[callback] = callbackWrap;
        ACCESSTOKEN_LOG_INFO(LABEL, "callbackObject added");
    }
    return result;
}

int32_t PrivacyManagerClient::UnRegisterPermActiveStatusCallback(
    const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "called!");

    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    std::lock_guard<std::mutex> lock(activeCbkMutex_);
    auto goalCallback = activeCbkMap_.find(callback);
    if (goalCallback == activeCbkMap_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "goalCallback already is not exist");
        return PrivacyError::ERR_CALLBACK_NOT_EXIST;
    }

    int32_t result = proxy->UnRegisterPermActiveStatusCallback(goalCallback->second->AsObject());
    if (result == RET_SUCCESS) {
        activeCbkMap_.erase(goalCallback);
    }
    return result;
}

bool PrivacyManagerClient::IsAllowedUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return false;
    }
    return proxy->IsAllowedUsingPermission(tokenID, permissionName);
}

void PrivacyManagerClient::InitProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr) {
        auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (sam == nullptr) {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "GetSystemAbilityManager is null");
            return;
        }
        auto privacySa = sam->GetSystemAbility(IPrivacyManager::SA_ID_PRIVACY_MANAGER_SERVICE);
        if (privacySa == nullptr) {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "GetSystemAbility %{public}d is null",
                IPrivacyManager::SA_ID_PRIVACY_MANAGER_SERVICE);
            return;
        }

        serviceDeathObserver_ = new (std::nothrow) PrivacyDeathRecipient();
        if (serviceDeathObserver_ != nullptr) {
            privacySa->AddDeathRecipient(serviceDeathObserver_);
        }
        proxy_ = iface_cast<IPrivacyManager>(privacySa);
        if (proxy_ == nullptr) {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "iface_cast get null");
        }
    }
}

void PrivacyManagerClient::OnRemoteDiedHandle()
{
    {
        std::lock_guard<std::mutex> lock(proxyMutex_);
        proxy_ = nullptr;
    }
    InitProxy();
}

sptr<IPrivacyManager> PrivacyManagerClient::GetProxy()
{
    if (proxy_ == nullptr) {
        InitProxy();
    }
    return proxy_;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
