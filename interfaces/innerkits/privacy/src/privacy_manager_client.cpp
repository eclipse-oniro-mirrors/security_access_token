/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "accesstoken_common_log.h"
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
const static int32_t MAX_CALLBACK_SIZE = 200;
const static int32_t MAX_PERM_LIST_SIZE = 1024;
constexpr const char* CAMERA_PERMISSION_NAME = "ohos.permission.CAMERA";
static const int32_t SA_ID_PRIVACY_MANAGER_SERVICE = 3505;
std::recursive_mutex g_instanceMutex;
} // namespace

PrivacyManagerClient& PrivacyManagerClient::GetInstance()
{
    static PrivacyManagerClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            PrivacyManagerClient* tmp = new PrivacyManagerClient();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

PrivacyManagerClient::PrivacyManagerClient()
{}

PrivacyManagerClient::~PrivacyManagerClient()
{
    LOGE(PRI_DOMAIN, PRI_TAG, "~PrivacyManagerClient");
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ReleaseProxy();
}

static int32_t ConvertResult(int32_t ret)
{
    switch (ret) {
        case ERR_INVALID_DATA:
            ret = ERR_WRITE_PARCEL_FAILED;
            break;
        case ERR_TRANSACTION_FAILED:
            ret = ERR_SERVICE_ABNORMAL;
            break;
        default:
            return ret;
    }
    return ret;
}

int32_t PrivacyManagerClient::AddPermissionUsedRecord(const AddPermParamInfo& info, bool asyncMode)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    AddPermParamInfoParcel infoParcel;
    infoParcel.info = info;
    int32_t ret;
    if (asyncMode) {
        ret = proxy->AddPermissionUsedRecordAsync(infoParcel);
    } else {
        ret = proxy->AddPermissionUsedRecord(infoParcel);
    }
    return ConvertResult(ret);
}

int32_t PrivacyManagerClient::SetPermissionUsedRecordToggleStatus(int32_t userID, bool status)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t ret = proxy->SetPermissionUsedRecordToggleStatus(userID, status);
    return ConvertResult(ret);
}

int32_t PrivacyManagerClient::GetPermissionUsedRecordToggleStatus(int32_t userID, bool& status)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t ret = proxy->GetPermissionUsedRecordToggleStatus(userID, status);
    return ConvertResult(ret);
}

int32_t PrivacyManagerClient::StartUsingPermission(
    AccessTokenID tokenID, int32_t pid, const std::string& permissionName, PermissionUsedType type)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    PermissionUsedTypeInfoParcel parcel;
    parcel.info.tokenId = tokenID;
    parcel.info.pid = pid;
    parcel.info.permissionName = permissionName;
    parcel.info.type = type;

    auto anonyStub = GetAnonyStub();
    if (anonyStub == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy death recipent is null.");
        return PrivacyError::ERR_MALLOC_FAILED;
    }
    int32_t ret = proxy->StartUsingPermission(parcel, anonyStub);
    return ConvertResult(ret);
}

int32_t PrivacyManagerClient::CreateStateChangeCbk(uint64_t id,
    const std::shared_ptr<StateCustomizedCbk>& callback, sptr<StateChangeCallback>& callbackWrap)
{
    std::lock_guard<std::mutex> lock(stateCbkMutex_);
    auto iter = stateChangeCallbackMap_.find(id);
    if (iter != stateChangeCallbackMap_.end()) {
        LOGE(PRI_DOMAIN, PRI_TAG, " Callback has been used.");
        return PrivacyError::ERR_CALLBACK_ALREADY_EXIST;
    } else {
        callbackWrap = new (std::nothrow) StateChangeCallback(callback);
        if (callbackWrap == nullptr) {
            LOGE(PRI_DOMAIN, PRI_TAG, "Memory allocation for callbackWrap failed!");
            return PrivacyError::ERR_MALLOC_FAILED;
        }
    }
    return RET_SUCCESS;
}

int32_t PrivacyManagerClient::StartUsingPermission(AccessTokenID tokenId, int32_t pid,
    const std::string& permissionName, const std::shared_ptr<StateCustomizedCbk>& callback, PermissionUsedType type)
{
    if (callback == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Callback is nullptr.");
        return PrivacyError::ERR_PARAM_INVALID;
    }

    sptr<StateChangeCallback> callbackWrap = nullptr;
    uint64_t id = GetUniqueId(tokenId, pid);
    int32_t result = CreateStateChangeCbk(id, callback, callbackWrap);
    if (result != RET_SUCCESS) {
        return result;
    }

    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    PermissionUsedTypeInfoParcel parcel;
    parcel.info.tokenId = tokenId;
    parcel.info.pid = pid;
    parcel.info.permissionName = permissionName;
    parcel.info.type = type;
    auto anonyStub = GetAnonyStub();
    if (anonyStub == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy death recipent is null.");
        return PrivacyError::ERR_MALLOC_FAILED;
    }
    result = proxy->StartUsingPermissionCallback(parcel, callbackWrap->AsObject(), anonyStub);
    if (result == RET_SUCCESS) {
        std::lock_guard<std::mutex> lock(stateCbkMutex_);
        stateChangeCallbackMap_[id] = callbackWrap;
        LOGI(PRI_DOMAIN, PRI_TAG, "CallbackObject added.");
    }
    return ConvertResult(result);
}

int32_t PrivacyManagerClient::StopUsingPermission(
    AccessTokenID tokenID, int32_t pid, const std::string& permissionName)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    if (permissionName == CAMERA_PERMISSION_NAME) {
        uint64_t id = GetUniqueId(tokenID, pid);
        std::lock_guard<std::mutex> lock(stateCbkMutex_);
        auto iter = stateChangeCallbackMap_.find(id);
        if (iter != stateChangeCallbackMap_.end()) {
            stateChangeCallbackMap_.erase(id);
        }
    }

    int32_t ret = proxy->StopUsingPermission(tokenID, pid, permissionName);
    return ConvertResult(ret);
}

int32_t PrivacyManagerClient::RemovePermissionUsedRecords(AccessTokenID tokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    int32_t ret = proxy->RemovePermissionUsedRecords(tokenID);
    return ConvertResult(ret);
}

int32_t PrivacyManagerClient::GetPermissionUsedRecords(
    const PermissionUsedRequest& request, PermissionUsedResult& result)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    PermissionUsedRequestParcel requestParcel;
    PermissionUsedResultParcel resultParcel;
    requestParcel.request = request;
    int32_t ret = proxy->GetPermissionUsedRecords(requestParcel, resultParcel);
    result = resultParcel.result;
    return ConvertResult(ret);
}

int32_t PrivacyManagerClient::GetPermissionUsedRecords(const PermissionUsedRequest& request,
    const sptr<OnPermissionUsedRecordCallback>& callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    PermissionUsedRequestParcel requestParcel;
    requestParcel.request = request;
    int32_t ret = proxy->GetPermissionUsedRecordsAsync(requestParcel, callback);
    return ConvertResult(ret);
}

int32_t PrivacyManagerClient::CreateActiveStatusChangeCbk(
    const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback, sptr<PermActiveStatusChangeCallback>& callbackWrap)
{
    std::lock_guard<std::mutex> lock(activeCbkMutex_);

    if (activeCbkMap_.size() >= MAX_CALLBACK_SIZE) {
        return PrivacyError::ERR_CALLBACKS_EXCEED_LIMITATION;
    }

    auto goalCallback = activeCbkMap_.find(callback);
    if (goalCallback != activeCbkMap_.end()) {
        return PrivacyError::ERR_CALLBACK_ALREADY_EXIST;
    } else {
        callbackWrap =
            new (std::nothrow) PermActiveStatusChangeCallback(callback);
        if (!callbackWrap) {
            return PrivacyError::ERR_MALLOC_FAILED;
        }
    }
    return RET_SUCCESS;
}

int32_t PrivacyManagerClient::RegisterPermActiveStatusCallback(
    const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback)
{
    if (callback == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "CustomizedCb is nullptr.");
        return PrivacyError::ERR_PARAM_INVALID;
    }

    sptr<PermActiveStatusChangeCallback> callbackWrap = nullptr;
    int32_t result = CreateActiveStatusChangeCbk(callback, callbackWrap);
    if (result != RET_SUCCESS) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to create callback, err: %{public}d.", result);
        return result;
    }

    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
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
        LOGI(PRI_DOMAIN, PRI_TAG, "CallbackObject added.");
    }
    return ConvertResult(result);
}

int32_t PrivacyManagerClient::UnRegisterPermActiveStatusCallback(
    const std::shared_ptr<PermActiveStatusCustomizedCbk>& callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    std::lock_guard<std::mutex> lock(activeCbkMutex_);
    auto goalCallback = activeCbkMap_.find(callback);
    if (goalCallback == activeCbkMap_.end()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "GoalCallback already is not exist.");
        return PrivacyError::ERR_CALLBACK_NOT_EXIST;
    }

    int32_t result = proxy->UnRegisterPermActiveStatusCallback(goalCallback->second->AsObject());
    if (result == RET_SUCCESS) {
        activeCbkMap_.erase(goalCallback);
    }
    return ConvertResult(result);
}

bool PrivacyManagerClient::IsAllowedUsingPermission(AccessTokenID tokenID, const std::string& permissionName,
    int32_t pid)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return false;
    }
    bool isAllowed = false;
    proxy->IsAllowedUsingPermission(tokenID, permissionName, pid, isAllowed);
    return isAllowed;
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
int32_t PrivacyManagerClient::RegisterSecCompEnhance(const SecCompEnhanceData& enhance)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    SecCompEnhanceDataParcel registerParcel;
    registerParcel.enhanceData = enhance;
    int32_t ret = proxy->RegisterSecCompEnhance(registerParcel);
    return ConvertResult(ret);
}

int32_t PrivacyManagerClient::UpdateSecCompEnhance(int32_t pid, uint32_t seqNum)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    int32_t ret = proxy->UpdateSecCompEnhance(pid, seqNum);
    return ConvertResult(ret);
}

int32_t PrivacyManagerClient::GetSecCompEnhance(int32_t pid, SecCompEnhanceData& enhance)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    SecCompEnhanceDataParcel parcel;
    int32_t res = proxy->GetSecCompEnhance(pid, parcel);
    if (res != RET_SUCCESS) {
        return ConvertResult(res);
    }
    enhance = parcel.enhanceData;
    return RET_SUCCESS;
}

int32_t PrivacyManagerClient::GetSpecialSecCompEnhance(const std::string& bundleName,
    std::vector<SecCompEnhanceData>& enhanceList)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_PARAM_INVALID;
    }
    std::vector<SecCompEnhanceDataParcel> parcelList;
    int32_t res = proxy->GetSpecialSecCompEnhance(bundleName, parcelList);
    if (res != RET_SUCCESS) {
        return ConvertResult(res);
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
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    std::vector<PermissionUsedTypeInfoParcel> resultsParcel;
    int32_t res = proxy->GetPermissionUsedTypeInfos(tokenId, permissionName, resultsParcel);
    if (res != RET_SUCCESS) {
        return ConvertResult(res);
    }

    std::transform(resultsParcel.begin(), resultsParcel.end(), std::back_inserter(results),
        [](PermissionUsedTypeInfoParcel parcel) { return parcel.info; });
    return RET_SUCCESS;
}

int32_t PrivacyManagerClient::SetMutePolicy(uint32_t policyType, uint32_t callerType, bool isMute,
    AccessTokenID tokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    int32_t ret = proxy->SetMutePolicy(policyType, callerType, isMute, tokenID);
    return ConvertResult(ret);
}

int32_t PrivacyManagerClient::SetHapWithFGReminder(uint32_t tokenId, bool isAllowed)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    int32_t ret = proxy->SetHapWithFGReminder(tokenId, isAllowed);
    return ConvertResult(ret);
}

uint64_t PrivacyManagerClient::GetUniqueId(uint32_t tokenId, int32_t pid) const
{
    uint32_t tmpPid = (pid <= 0) ? 0 : static_cast<uint32_t>(pid);
    return (static_cast<uint64_t>(tmpPid) << 32) | (static_cast<uint64_t>(tokenId) & 0xFFFFFFFF); // 32: bit
}

void PrivacyManagerClient::InitProxy()
{
    if (proxy_ == nullptr || proxy_->AsObject() == nullptr || proxy_->AsObject()->IsObjectDead()) {
        auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (sam == nullptr) {
            LOGE(PRI_DOMAIN, PRI_TAG, "GetSystemAbilityManager is null");
            return;
        }
        auto privacySa = sam->CheckSystemAbility(SA_ID_PRIVACY_MANAGER_SERVICE);
        if (privacySa == nullptr) {
            LOGE(PRI_DOMAIN, PRI_TAG, "CheckSystemAbility %{public}d is null", SA_ID_PRIVACY_MANAGER_SERVICE);
            return;
        }

        serviceDeathObserver_ = sptr<PrivacyDeathRecipient>::MakeSptr();
        if (serviceDeathObserver_ != nullptr) {
            privacySa->AddDeathRecipient(serviceDeathObserver_);
        }
        proxy_ = new PrivacyManagerProxy(privacySa);
        if (proxy_ == nullptr || proxy_->AsObject() == nullptr || proxy_->AsObject()->IsObjectDead()) {
            LOGE(PRI_DOMAIN, PRI_TAG, "Iface_cast get null");
        }
    }
}

void PrivacyManagerClient::OnRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ReleaseProxy();
    InitProxy();
}

sptr<IPrivacyManager> PrivacyManagerClient::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr || proxy_->AsObject() == nullptr || proxy_->AsObject()->IsObjectDead()) {
        InitProxy();
    }
    return proxy_;
}

void PrivacyManagerClient::ReleaseProxy()
{
    if (proxy_ != nullptr && serviceDeathObserver_ != nullptr) {
        proxy_->AsObject()->RemoveDeathRecipient(serviceDeathObserver_);
    }
    proxy_ = nullptr;
    serviceDeathObserver_ = nullptr;
}

sptr<ProxyDeathCallBackStub> PrivacyManagerClient::GetAnonyStub()
{
    std::lock_guard<std::mutex> lock(stubMutex_);
    if (anonyStub_ == nullptr) {
        anonyStub_ = sptr<ProxyDeathCallBackStub>::MakeSptr();
    }
    return anonyStub_;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
