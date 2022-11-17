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
#include "camera_manager_privacy_client.h"

#include "accesstoken_log.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "CameraManagerPrivacyClient"
};
} // namespace

CameraManagerPrivacyClient& CameraManagerPrivacyClient::GetInstance()
{
    static CameraManagerPrivacyClient instance;
    return instance;
}

CameraManagerPrivacyClient::CameraManagerPrivacyClient()
{}

CameraManagerPrivacyClient::~CameraManagerPrivacyClient()
{}

int32_t CameraManagerPrivacyClient::SetMuteCallback(const sptr<ICameraMuteServiceCallback>& callback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return -1;
    }
    return proxy->SetMuteCallback(callback);
}

int32_t CameraManagerPrivacyClient::MuteCamera(bool muteMode)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return false;
    }
    return proxy->MuteCamera(muteMode);
}

bool CameraManagerPrivacyClient::IsCameraMuted()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return false;
    }
    bool muteMode = false;
    proxy->IsCameraMuted(muteMode);
    return muteMode;
}

void CameraManagerPrivacyClient::InitProxy()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbilityManager is null");
        return;
    }
    auto cameraManagerSa = sam->GetSystemAbility(CAMERA_SERVICE_ID);
    if (cameraManagerSa == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbility %{public}d is null",
            CAMERA_SERVICE_ID);
        return;
    }

    serviceDeathObserver_ = new (std::nothrow) CameraManagerPrivacyDeathRecipient();
    if (serviceDeathObserver_ != nullptr) {
        cameraManagerSa->AddDeathRecipient(serviceDeathObserver_);
    }

    proxy_ = iface_cast<ICameraService>(cameraManagerSa);
    if (proxy_ == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "iface_cast get null");
    }
}

void CameraManagerPrivacyClient::OnRemoteDiedHandle()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    proxy_ = nullptr;
}

sptr<ICameraService> CameraManagerPrivacyClient::GetProxy()
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

