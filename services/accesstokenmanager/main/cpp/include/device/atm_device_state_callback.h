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

#ifndef ATM_DEVICE_STATE_CALLBACK_H
#define ATM_DEVICE_STATE_CALLBACK_H

#include "device_manager_callback.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
using OHOS::DistributedHardware::DeviceStateCallback;
using OHOS::DistributedHardware::DmDeviceInfo;
using OHOS::DistributedHardware::DmInitCallback;

class AtmDmInitCallback final : public DmInitCallback {
    void OnRemoteDied() override
    {}
};

class AtmDeviceStateCallback final : public DeviceStateCallback {
public:
    AtmDeviceStateCallback();
    ~AtmDeviceStateCallback();

    void OnDeviceOnline(const DmDeviceInfo &deviceInfo) override;
    void OnDeviceOffline(const DmDeviceInfo &deviceInfo) override;
    void OnDeviceReady(const DmDeviceInfo &deviceInfo) override;
    void OnDeviceChanged(const DmDeviceInfo &deviceInfo) override;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif // ATM_DEVICE_STATE_CALLBACK_H
