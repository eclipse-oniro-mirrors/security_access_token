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
#include "privacy_manager_client.h"

#include <algorithm>
#include "accesstoken_log.h"
#include "iservice_registry.h"
#include "privacy_error.h"
#include "privacy_manager_proxy.h"
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
#include "sec_comp_enhance_data_parcel.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyManagerClient"
};
const static int32_t MAX_CALLBACK_SIZE = 200;
const static int32_t MAX_PERM_LIST_SIZE = 1024;
std::recursive_mutex g_instanceMutex;
} // namespace

PrivacyManagerClient& PrivacyManagerClient::GetInstance()
{
    static PrivacyManagerClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new PrivacyManagerClient();
        }
    }
    return *instance;
}

PrivacyManagerClient::PrivacyManagerClient()
{}

PrivacyManagerClient::~PrivacyManagerClient()
{
    ACCESSTOKEN_LOG_ERROR(LABEL, "~PrivacyManagerClient");
}

int32_t PrivacyManagerClient::AddPermissionUsedRecord(const AddPermParamInfo& info, bool asyncMode)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    AddPermParamInfoParcel infoParcel;
    infoParcel.info = info;
    return proxy->AddPermissionUsedRecord(infoParcel, asyncMode);
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

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
int32_t PrivacyManagerClient::RegisterSecCompEnhance(const SecCompEnhanceData& enhance)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    SecCompEnhanceDataParcel registerParcel;
    registerParcel.enhanceData = enhance;
    return proxy->RegisterSecCompEnhance(registerParcel);
}

int32_t PrivacyManagerClient::UpdateSecCompEnhance(int32_t pid, int32_t seqNum)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Proxy is null.");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    return proxy->UpdateSecCompEnhance(pid, seqNum);
}

int32_t PrivacyManagerClient::GetSecCompEnhance(int32_t pid, SecCompEnhanceData& enhance)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    SecCompEnhanceDataParcel parcel;
    int32_t res = proxy->GetSecCompEnhance(pid, parcel);
    if (res != RET_SUCCESS) {
        return res;
    }
    enhance = parcel.enhanceData;
    return RET_SUCCESS;
}

int32_t PrivacyManagerClient::GetSpecialSecCompEnhance(const std::string& bundleName,
    std::vector<SecCompEnhanceData>& enhanceList)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    std::vector<SecCompEnhanceDataParcel> parcelList;
    int32_t res = proxy->GetSpecialSecCompEnhance(bundleName, parcelList);
    if (res != RET_SUCCESS) {
        return res;
    }

    std::transform(parcelList.begin(), parcelList.end(), std::back_inserter(enhanceList),
        [](SecCompEnhanceDataParcel pair) { return pair.enhanceData; });
    return RET_SUCCESS;
}
#endif

int32_t PrivacyManagerClient::GetPermissionUsedTypeInfos(const AccessTokenID tokenId, const std::string& permissionName,
    std::vector<PermissionUsedTypeInfo>& results)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    std::vector<PermissionUsedTypeInfoParcel> resultsParcel;
    int32_t res = proxy->GetPermissionUsedTypeInfos(tokenId, permissionName, resultsParcel);
    if (res != RET_SUCCESS) {
        return res;
    }

    std::transform(resultsParcel.begin(), resultsParcel.end(), std::back_inserter(results),
        [](PermissionUsedTypeInfoParcel parcel) { return parcel.info; });
    return RET_SUCCESS;
}

int32_t PrivacyManagerClient::SetMutePolicy(uint32_t policyType, uint32_t callerType, bool isMute)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Proxy is null");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->SetMutePolicy(policyType, callerType, isMute);
}

void PrivacyManagerClient::InitProxy()
{
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
    std::lock_guard<std::mutex> lock(proxyMutex_);
    proxy_ = nullptr;
    InitProxy();
}

sptr<IPrivacyManager> PrivacyManagerClient::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr) {
        InitProxy();
    }
    return proxy_;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
