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

#include "atm_device_state_callback.h"

#include <vector>
#include <thread>

#include "accesstoken_log.h"
#include "constant.h"
#include "device_manager.h"
#include "dm_device_info.h"
#include "token_sync_manager_client.h"
#include "accesstoken_manager_service.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
using OHOS::DistributedHardware::DeviceStateCallback;
using OHOS::DistributedHardware::DmDeviceInfo;
using OHOS::DistributedHardware::DmInitCallback;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AtmDeviceStateCallback"};
}

AtmDeviceStateCallback::AtmDeviceStateCallback()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "AtmDeviceStateCallback()");
}

AtmDeviceStateCallback::~AtmDeviceStateCallback()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "~AtmDeviceStateCallback()");
}

void AtmDeviceStateCallback::OnDeviceOnline(const DmDeviceInfo &deviceInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "device online");

    // when remote device online and token sync remote object is null, start a thread to load token sync
    if (TokenSyncManagerClient::GetInstance().GetRemoteObject() == nullptr) {
        std::function<void()> runner = [&]() {
            TokenSyncManagerClient::GetInstance().LoadTokenSync();

            ACCESSTOKEN_LOG_INFO(LABEL, "load tokensync.");

            return;
        };

        std::thread initThread(runner);
        initThread.detach();
    }
}

void AtmDeviceStateCallback::OnDeviceOffline(const DmDeviceInfo &deviceInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "device offline");
}

void AtmDeviceStateCallback::OnDeviceReady(const DmDeviceInfo &deviceInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "device ready");
}

void AtmDeviceStateCallback::OnDeviceChanged(const DmDeviceInfo &deviceInfo)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "device changed");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
