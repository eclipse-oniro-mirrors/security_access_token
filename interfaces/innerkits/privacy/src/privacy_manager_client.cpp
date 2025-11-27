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
#include "active_change_response_parcel.h"
#include "iservice_registry.h"
#include "privacy_error.h"
#include "privacy_manager_proxy.h"
#include "proxy_death_callback_stub.h"


namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
const static int32_t MAX_CALLBACK_SIZE = 200;
const static int32_t MAX_DISABLE_CALLBACK_SIZE = 20;
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
            PrivacyManagerClient* tmp = new (std::nothrow) PrivacyManagerClient();
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
    ret = ConvertResult(ret);
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", ret);
    return ret;
}

int32_t PrivacyManagerClient::SetPermissionUsedRecordToggleStatus(int32_t userID, bool status)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t ret = proxy->SetPermissionUsedRecordToggleStatus(userID, status);
    ret = ConvertResult(ret);
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", ret);
    return ret;
}

int32_t PrivacyManagerClient::GetPermissionUsedRecordToggleStatus(int32_t userID, bool& status)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    int32_t ret = proxy->GetPermissionUsedRecordToggleStatus(userID, status);
    ret = ConvertResult(ret);
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", ret);
    return ret;
}

std::function<void(int32_t, const std::string &)> PrivacySaAddCallback()
{
    return [](int32_t systemAbilityId, const std::string &deviceId) {
        if (systemAbilityId == SA_ID_PRIVACY_MANAGER_SERVICE) {
            PrivacyManagerClient::GetInstance().OnAddPrivacySa();
        }
    };
}

void PrivacyManagerClient::SubscribeSystemAbility(const SubscribeSACallbackFunc& callbackFunc)
{
    sptr<ISystemAbilityStatusChange> statusChangeListener =
        new (std::nothrow) SystemAbilityStatusChangeListener(callbackFunc);
    if (statusChangeListener == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "statusChangeListener is nullptr.");
        return;
    }
    auto saProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saProxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "saProxy is NULL.");
        return;
    }
    int32_t ret = saProxy->SubscribeSystemAbility(SA_ID_PRIVACY_MANAGER_SERVICE, statusChangeListener);
    if (ret != ERR_OK) {
        LOGE(PRI_DOMAIN, PRI_TAG, "SubscribeSystemAbility is failed.");
        return;
    }
    return;
}

void PrivacyManagerClient::OnAddPrivacySa(void)
{
    LOGI(PRI_DOMAIN, PRI_TAG, "Enter.");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return;
    }
    auto anonyStub = GetAnonyStub();
    if (anonyStub == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy death recipent is null.");
        return;
    }
    std::lock_guard<std::mutex> lock(startUsingPermInputMutex_);
    LOGI(PRI_DOMAIN, PRI_TAG, "CacheList_ size %{public}zu.", cacheList_.size());
    for (auto it = cacheList_.begin(); it != cacheList_.end(); ++it) {
        PermissionUsedTypeInfoParcel parcel;
        parcel.info = it->input;
        LOGI(PRI_DOMAIN, PRI_TAG, "TokenId %{public}d, pid %{public}d, permission %{public}s.",
            it->input.tokenId, it->input.pid, it->input.permissionName.c_str());
        if (it->hasCbk) {
            uint64_t id = GetUniqueId(it->input.tokenId, it->input.pid);
            std::lock_guard<std::mutex> lock(stateCbkMutex_);
            auto iter = stateChangeCallbackMap_.find(id);
            if (iter == stateChangeCallbackMap_.end()) {
                LOGE(PRI_DOMAIN, PRI_TAG, "Callback is not exist, tokenid %{public}u, pid %{public}d.",
                    it->input.tokenId, it->input.pid);
                continue;
            }
            int32_t ret = proxy->StartUsingPermissionCallback(parcel, iter->second->AsObject(), anonyStub->AsObject());
            ret = ConvertResult(ret);
            LOGI(PRI_DOMAIN, PRI_TAG, "Recover StartUsingPermissionCallback result is %{public}d.", ret);
        } else {
            int32_t ret = proxy->StartUsingPermission(parcel, anonyStub->AsObject());
            ret = ConvertResult(ret);
            LOGI(PRI_DOMAIN, PRI_TAG, "Recover StartUsingPermission result is %{public}d.", ret);
        }
    }
}

void PrivacyManagerClient::SetInputCache(
    const PermissionUsedTypeInfo& info, bool hasCbk)
{
    StartUsingPermInputInfo cache;
    cache.input = info;
    cache.hasCbk = hasCbk;

    std::lock_guard<std::mutex> lock(startUsingPermInputMutex_);
    for (auto it = cacheList_.begin(); it != cacheList_.end(); ++it) {
        if ((it->input.permissionName == info.permissionName) &&
            (it->input.pid == info.pid) && (it->input.tokenId == info.tokenId)) {
            LOGE(PRI_DOMAIN, PRI_TAG, "It already exists in cache.");
            return;
        }
    }
    cacheList_.emplace_back(cache);
    LOGI(PRI_DOMAIN, PRI_TAG, "Cache is added.");
}

void PrivacyManagerClient::DeleteInputCache(AccessTokenID tokenID, int32_t pid, const std::string& permissionName)
{
    std::lock_guard<std::mutex> lock(startUsingPermInputMutex_);
    for (auto it = cacheList_.begin(); it != cacheList_.end(); ++it) {
        if ((it->input.permissionName == permissionName) &&
            (it->input.pid == pid) && (it->input.tokenId == tokenID)) {
            cacheList_.erase(it);
            LOGI(PRI_DOMAIN, PRI_TAG, "Cache is cleared.");
            break;
        }
    }
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

    int32_t ret = proxy->StartUsingPermission(parcel, anonyStub->AsObject());
    ret = ConvertResult(ret);
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", ret);
    if (ret == RET_SUCCESS) {
        SetInputCache(parcel.info, false);
    }
    return ret;
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
    if (permissionName != CAMERA_PERMISSION_NAME) {
        LOGE(PRI_DOMAIN, PRI_TAG, "permission %{public}s is not supported.", permissionName.c_str());
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
    result = proxy->StartUsingPermissionCallback(parcel, callbackWrap->AsObject(), anonyStub->AsObject());
    if (result == RET_SUCCESS) {
        std::lock_guard<std::mutex> lock(stateCbkMutex_);
        stateChangeCallbackMap_[id] = callbackWrap;
        LOGI(PRI_DOMAIN, PRI_TAG, "CallbackObject added.");
        SetInputCache(parcel.info, true);
    } else {
        result = ConvertResult(result);
        LOGE(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", result);
    }
    return result;
}

int32_t PrivacyManagerClient::StopUsingPermission(
    AccessTokenID tokenID, int32_t pid, const std::string& permissionName)
{
    DeleteInputCache(tokenID, pid, permissionName);

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
    ret = ConvertResult(ret);
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", ret);
    return ret;
}

int32_t PrivacyManagerClient::RemovePermissionUsedRecords(AccessTokenID tokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    int32_t ret = proxy->RemovePermissionUsedRecords(tokenID);
    ret = ConvertResult(ret);
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", ret);
    return ret;
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
    if (ret == RET_SUCCESS) {
        result = resultParcel.result;
    } else {
        ret = ConvertResult(ret);
    }
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", ret);
    return ret;
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
    ret = ConvertResult(ret);
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", ret);
    return ret;
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
    } else {
        result = ConvertResult(result);
    }
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", result);
    return result;
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
    if (goalCallback->second == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "GoalCallback is null.");
        return PrivacyError::ERR_CALLBACK_NOT_EXIST;
    }

    int32_t result = proxy->UnRegisterPermActiveStatusCallback(goalCallback->second->AsObject());
    if (result == RET_SUCCESS) {
        activeCbkMap_.erase(goalCallback);
    } else {
        result = ConvertResult(result);
    }
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", result);
    return result;
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
    LOGI(PRI_DOMAIN, PRI_TAG, "Request result is %{public}s.", (isAllowed ? "true" : "false"));
    return isAllowed;
}

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
        res = ConvertResult(res);
        LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", res);
        return res;
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
    ret = ConvertResult(ret);
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", ret);
    return ret;
}

int32_t PrivacyManagerClient::SetHapWithFGReminder(uint32_t tokenId, bool isAllowed)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    int32_t ret = proxy->SetHapWithFGReminder(tokenId, isAllowed);
    ret = ConvertResult(ret);
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", ret);
    return ret;
}

int32_t PrivacyManagerClient::SetDisablePolicy(const std::string& permissionName, bool isDisable)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    int32_t ret = proxy->SetDisablePolicy(permissionName, isDisable);
    ret = ConvertResult(ret);
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", ret);
    return ret;
}

int32_t PrivacyManagerClient::GetDisablePolicy(const std::string& permissionName, bool& isDisable)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    int32_t ret = proxy->GetDisablePolicy(permissionName, isDisable);
    ret = ConvertResult(ret);
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", ret);
    return ret;
}

int32_t PrivacyManagerClient::GetCurrUsingPermInfo(std::vector<CurrUsingPermInfo> &infoList)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    std::vector<ActiveChangeResponseParcel> resultParcelList;

    int32_t ret = proxy->GetCurrUsingPermInfo(resultParcelList);
    ret = ConvertResult(ret);
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", ret);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    for (const auto& resultParcel : resultParcelList) {
        infoList.emplace_back(resultParcel.changeResponse);
    }
    return ret;
}

int32_t PrivacyManagerClient::CreatePermDisablePolicyCbk(
    const std::shared_ptr<DisablePolicyChangeCallback>& callback,
    sptr<PermDisablePolicyChangeCallback>& callbackWrap)
{
    if (callback == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Callback is nullptr!");
        return PrivacyError::ERR_PARAM_INVALID;
    }

    std::lock_guard<std::mutex> lock(disableCbkMutex_);
    if (disableCbkMap_.size() >= MAX_DISABLE_CALLBACK_SIZE) {
        return PrivacyError::ERR_CALLBACKS_EXCEED_LIMITATION;
    }

    auto goalCallback = disableCbkMap_.find(callback);
    if (goalCallback != disableCbkMap_.end()) {
        return PrivacyError::ERR_CALLBACK_ALREADY_EXIST;
    } else {
        callbackWrap = new (std::nothrow) PermDisablePolicyChangeCallback(callback);
        if (callbackWrap == nullptr) {
            return PrivacyError::ERR_MALLOC_FAILED;
        }
    }
    return RET_SUCCESS;
}

int32_t PrivacyManagerClient::RegisterPermDisablePolicyCallback(
    const std::shared_ptr<DisablePolicyChangeCallback>& callback)
{
    if (callback == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Callback is nullptr!");
        return PrivacyError::ERR_PARAM_INVALID;
    }

    std::vector<std::string> permList;
    callback->GetPermList(permList);
    if (permList.size() > MAX_PERM_LIST_SIZE) {
        return PrivacyError::ERR_OVERSIZE;
    }

    sptr<PermDisablePolicyChangeCallback> callbackWrap = nullptr;
    int32_t result = CreatePermDisablePolicyCbk(callback, callbackWrap);
    if (result != RET_SUCCESS) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Failed to create callback, err: %{public}d.", result);
        return result;
    }

    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }
    
    result = proxy->RegisterPermDisablePolicyCallback(permList, callbackWrap->AsObject());
    if (result == RET_SUCCESS) {
        std::lock_guard<std::mutex> lock(disableCbkMutex_);
        disableCbkMap_[callback] = callbackWrap;
        LOGI(PRI_DOMAIN, PRI_TAG, "CallbackObject added.");
    } else {
        result = ConvertResult(result);
    }
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", result);
    return result;
}

int32_t PrivacyManagerClient::UnRegisterPermDisablePolicyCallback(
    const std::shared_ptr<DisablePolicyChangeCallback>& callback)
{
    if (callback == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Callback is nullptr!");
        return PrivacyError::ERR_PARAM_INVALID;
    }

    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Proxy is null.");
        return PrivacyError::ERR_SERVICE_ABNORMAL;
    }

    std::lock_guard<std::mutex> lock(disableCbkMutex_);
    auto it = disableCbkMap_.find(callback);
    if (it == disableCbkMap_.end()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Callback has not register.");
        return PrivacyError::ERR_CALLBACK_NOT_EXIST;
    }
    if (it->second == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Callback is null.");
        return PrivacyError::ERR_CALLBACK_NOT_EXIST;
    }

    int32_t result = proxy->UnRegisterPermDisablePolicyCallback(it->second->AsObject());
    if (result == RET_SUCCESS) {
        disableCbkMap_.erase(it);
    } else {
        result = ConvertResult(result);
    }
    LOGI(PRI_DOMAIN, PRI_TAG, "Result is %{public}d.", result);
    return result;
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
        proxy_ = new (std::nothrow) PrivacyManagerProxy(privacySa);
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
    if (!isSubscribeSA_) {
        isSubscribeSA_ = true;
        SubscribeSystemAbility(PrivacySaAddCallback());
    }
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

sptr<ProxyDeathCallBack> PrivacyManagerClient::GetAnonyStub()
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
