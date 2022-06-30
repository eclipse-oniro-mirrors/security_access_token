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

#include "privacy_manager_service.h"

#include "accesstoken_log.h"
#include "constant.h"
#include "ipc_skeleton.h"
#include "permission_record_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacyManagerService"
};
}

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<PrivacyManagerService>::GetInstance().get());

PrivacyManagerService::PrivacyManagerService()
    : SystemAbility(SA_ID_PRIVACY_MANAGER_SERVICE, true), state_(ServiceRunningState::STATE_NOT_START)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "PrivacyManagerService()");
}

PrivacyManagerService::~PrivacyManagerService()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "~PrivacyManagerService()");
}

void PrivacyManagerService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        ACCESSTOKEN_LOG_INFO(LABEL, "PrivacyManagerService has already started!");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "PrivacyManagerService is starting");
    if (!Initialize()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to initialize");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    bool ret = Publish(DelayedSingleton<PrivacyManagerService>::GetInstance().get());
    if (!ret) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to publish service!");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Congratulations, PrivacyManagerService start successfully!");
}

void PrivacyManagerService::OnStop()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "stop service");
    state_ = ServiceRunningState::STATE_NOT_START;
}

int32_t PrivacyManagerService::AddPermissionUsedRecord(
    AccessTokenID tokenID, const std::string& permissionName, int32_t successCount, int32_t failCount)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry, tokenID: 0x%{public}x, permission: %{public}s",
        tokenID, permissionName.c_str());
    return PermissionRecordManager::GetInstance().AddPermissionUsedRecord(
        tokenID, permissionName, successCount, failCount);
}

int32_t PrivacyManagerService::StartUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry, tokenID: 0x%{public}x, permission: %{public}s",
        tokenID, permissionName.c_str());
    return Constant::SUCCESS;
}

int32_t PrivacyManagerService::StopUsingPermission(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry, tokenID: 0x%{public}x, permission: %{public}s",
        tokenID, permissionName.c_str());
    return Constant::SUCCESS;
}

int32_t PrivacyManagerService::RemovePermissionUsedRecords(AccessTokenID tokenID, const std::string& deviceID)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry, tokenID: 0x%{public}x, deviceID: %{private}s", tokenID, deviceID.c_str());
    PermissionRecordManager::GetInstance().RemovePermissionUsedRecords(tokenID, deviceID);
    return Constant::SUCCESS;
}

int32_t PrivacyManagerService::GetPermissionUsedRecords(
    const PermissionUsedRequestParcel& request, PermissionUsedResultParcel& result)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry");
    PermissionUsedResult permissionRecord;
    int32_t ret =  PermissionRecordManager::GetInstance().GetPermissionUsedRecords(request.request, permissionRecord);
    result.result = permissionRecord;
    return ret;
}

int32_t PrivacyManagerService::GetPermissionUsedRecords(
    const PermissionUsedRequestParcel& request, const sptr<OnPermissionUsedRecordCallback>& callback)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry");
    return PermissionRecordManager::GetInstance().GetPermissionUsedRecordsAsync(request.request, callback);
}

std::string PrivacyManagerService::DumpRecordInfo(const std::string& bundleName, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "Entry, bundleName: %{public}s, permissionName: %{public}s",
        bundleName.c_str(), permissionName.c_str());
    return PermissionRecordManager::GetInstance().DumpRecordInfo(bundleName, permissionName);
}

bool PrivacyManagerService::Initialize() const
{
    PermissionRecordManager::GetInstance().Init();
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
