/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_ACCESS_TOKEN_DEVICE_MANAGER_CALLBACK_H
#define OHOS_ACCESS_TOKEN_DEVICE_MANAGER_CALLBACK_H

#include "dm_device_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace DistributedHardware {
class DmInitCallback {
public:
    virtual ~DmInitCallback()
    {
    }
    virtual void OnRemoteDied() = 0;
};

class DeviceStateCallback {
public:
    virtual ~DeviceStateCallback()
    {
    }
    virtual void OnDeviceOnline(const DmDeviceInfo &deviceInfo) = 0;
    virtual void OnDeviceOffline(const DmDeviceInfo &deviceInfo) = 0;
    virtual void OnDeviceChanged(const DmDeviceInfo &deviceInfo) = 0;
    virtual void OnDeviceReady(const DmDeviceInfo &deviceInfo) = 0;
};
} // namespace DistributedHardware
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // OHOS_ACCESS_TOKEN_DEVICE_MANAGER_CALLBACK_H
