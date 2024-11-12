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
#include "accesstoken_log.h"
#ifdef CAMERA_FRAMEWORK_ENABLE
#include "camera_service_ipc_interface_code.h"
#endif
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

bool CameraManagerAdapter::IsCameraMuted()
{
#ifndef CAMERA_FRAMEWORK_ENABLE
    ACCESSTOKEN_LOG_INFO(LABEL, "camera framework is not support.");
    return false;
#else
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to GetProxy.");
        return false;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    std::u16string CAMERA_MGR_DESCRIPTOR = u"ICameraService";
    if (!data.WriteInterfaceToken(CAMERA_MGR_DESCRIPTOR)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to write WriteInterfaceToken.");
        return false;
    }
    int32_t error = proxy->SendRequest(
        static_cast<uint32_t>(CameraStandard::CameraServiceInterfaceCode::CAMERA_SERVICE_IS_CAMERA_MUTED),
        data, reply, option);
    if (error != NO_ERROR) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "SendRequest error: %{public}d", error);
        return false;
    }
    return reply.ReadBool();
#endif
}

#ifdef CAMERA_FRAMEWORK_ENABLE
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
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
