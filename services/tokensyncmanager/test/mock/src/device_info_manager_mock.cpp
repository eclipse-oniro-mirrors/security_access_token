/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <string>
#include <vector>

#include "device_info.h"
#include "device_info_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
DeviceInfoManager &DeviceInfoManager::GetInstance()
{
    static DeviceInfoManager instance;
    return instance;
}

bool DeviceInfoManager::GetDeviceInfo(const std::string &srcDeviceId, DeviceIdType type, DeviceInfo &devInfo)
{
    if (srcDeviceId == "valid_deviceId1") {
        devInfo.deviceId.uniqueDeviceId = "valid_deviceId1";
    }
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
