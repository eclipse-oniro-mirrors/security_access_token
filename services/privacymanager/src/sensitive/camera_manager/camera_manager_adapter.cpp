/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "camera_manager_adapter.h"
#include "access_token_error.h"
#include "accesstoken_log.h"
#include "camera_service_ipc_interface_code.h"
#include <iremote_proxy.h>
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "CameraManagerAdapter"
};
const std::u16string CAMERA_MGR_DESCRIPTOR = u"ICameraService";
}

CameraManagerAdapter& CameraManagerAdapter::GetInstance()
{
    static CameraManagerAdapter *instance = new (std::nothrow) CameraManagerAdapter();
    return *instance;
}

CameraManagerAdapter::CameraManagerAdapter()
{}

CameraManagerAdapter::~CameraManagerAdapter()
{}

int32_t CameraManagerAdapter::MuteCameraPersist(PolicyType policyType, bool muteMode)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to GetProxy.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(CAMERA_MGR_DESCRIPTOR)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteInt32(static_cast<int32_t>(policyType))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write policyType.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    if (!data.WriteBool(muteMode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write muteMode.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    int32_t error = proxy->SendRequest(
        static_cast<uint32_t>(CameraStandard::CameraServiceInterfaceCode::CAMERA_SERVICE_MUTE_CAMERA_PERSIST),
        data, reply, option);
    if (error != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

bool CameraManagerAdapter::IsCameraMuted()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to GetProxy.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(CAMERA_MGR_DESCRIPTOR)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return AccessTokenError::ERR_WRITE_PARCEL_FAILED;
    }
    int32_t error = proxy->SendRequest(
        static_cast<uint32_t>(CameraStandard::CameraServiceInterfaceCode::CAMERA_SERVICE_IS_CAMERA_MUTED),
        data, reply, option);
    if (error != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest error: %{public}d", error);
        return error;
    }
    return reply.ReadBool();
}

void CameraManagerAdapter::InitProxy()
{
    if (proxy_ != nullptr && (!proxy_->IsObjectDead())) {
        return;
    }
    sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemManager == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to get system ability registry.");
        return;
    }
    sptr<IRemoteObject> remoteObj = systemManager->CheckSystemAbility(CAMERA_SERVICE_ID);
    if (remoteObj == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Fail to connect ability manager service.");
        return;
    }

    deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) CameraManagerDeathRecipient());
    if (deathRecipient_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to create CameraManagerDeathRecipient!");
        return;
    }
    if ((remoteObj->IsProxyObject()) && (!remoteObj->AddDeathRecipient(deathRecipient_))) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Add death recipient to AbilityManagerService failed.");
        return;
    }
    proxy_ = remoteObj;
}

sptr<IRemoteObject> CameraManagerAdapter::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr || proxy_->IsObjectDead()) {
        InitProxy();
    }
    return proxy_;
}

void CameraManagerAdapter::ReleaseProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if ((proxy_ != nullptr) && (proxy_ == remote.promote())) {
        proxy_->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
        deathRecipient_ = nullptr;
    }
}

void CameraManagerAdapter::CameraManagerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    ACCESSTOKEN_LOG_ERROR(LABEL, "CameraManagerDeathRecipient handle remote died.");
    CameraManagerAdapter::GetInstance().ReleaseProxy(remote);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
