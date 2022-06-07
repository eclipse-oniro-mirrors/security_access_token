/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "accesstoken_log.h"
#include "data_validator.h"
#include "iservice_registry.h"
#include "privacy_manager_proxy.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyManagerClient"
};
} // namespace

const static int32_t ERROR = -1;

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
    if (!DataValidator::IsTokenIDValid(tokenID) || !DataValidator::IsPermissionNameValid(permissionName) ||
        (successCount < 0 || failCount < 0)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "parameter is invalid");
        return ERROR;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return ERROR;
    }
    return proxy->AddPermissionUsedRecord(tokenID, permissionName, successCount, failCount);
}

int32_t PrivacyManagerClient::StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    if (!DataValidator::IsTokenIDValid(tokenID) || !DataValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "parameter is invalid");
        return ERROR;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return ERROR;
    }
    return proxy->StartUsingPermission(tokenID, permissionName);
}

int32_t PrivacyManagerClient::StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    if (!DataValidator::IsTokenIDValid(tokenID) || !DataValidator::IsPermissionNameValid(permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "parameter is invalid");
        return ERROR;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return ERROR;
    }
    return proxy->StopUsingPermission(tokenID, permissionName);
}

int32_t PrivacyManagerClient::RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID)
{
    if (!DataValidator::IsTokenIDValid(tokenID) && !DataValidator::IsDeviceIdValid(deviceID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "parameter is invalid");
        return ERROR;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return ERROR;
    }
    return proxy->RemovePermissionUsedRecords(tokenID, deviceID);
}

int32_t PrivacyManagerClient::GetPermissionUsedRecords(
    const PermissionUsedRequest& request, PermissionUsedResult& result)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return ERROR;
    }

    PermissionUsedRequestParcel requestParcel;
    PermissionUsedResultParcel reultParcel;
    requestParcel.request = request;
    int32_t ret = proxy->GetPermissionUsedRecords(requestParcel, reultParcel);
    result = reultParcel.result;
    return ret;
}

int32_t PrivacyManagerClient::GetPermissionUsedRecords(const PermissionUsedRequest& request,
    const sptr<OnPermissionUsedRecordCallback>& callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return ERROR;
    }

    PermissionUsedRequestParcel requestParcel;
    requestParcel.request = request;
    return proxy->GetPermissionUsedRecords(requestParcel, callback);
}

std::string PrivacyManagerClient::DumpRecordInfo(const std::string& bundleName, const std::string& permissionName)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return "";
    }

    return proxy->DumpRecordInfo(bundleName, permissionName);
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
