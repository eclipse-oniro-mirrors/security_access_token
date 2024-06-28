/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ACCESS_TOKEN_DEVICE_MANAGER_H
#define OHOS_ACCESS_TOKEN_DEVICE_MANAGER_H

#include <string>
#include <vector>

#include "device_manager_callback.h"
#include "dm_device_info.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace DistributedHardware {
class DeviceManager {
public:
    static DeviceManager &GetInstance()
    {
        static DeviceManager instance;
        return instance;
    }

    int32_t InitDeviceManager(const std::string &pkgName, std::shared_ptr<DmInitCallback> dmInitCallback)
    {
        return 0;
    }

    int32_t UnInitDeviceManager(const std::string &pkgName)
    {
        return 0;
    }

    int32_t RegisterDevStateCallback(const std::string &pkgName, const std::string &extra,
        std::shared_ptr<DeviceStateCallback> callback)
    {
        return 0;
    }

    int32_t UnRegisterDevStateCallback(const std::string &pkgName)
    {
        return 0;
    }

    int32_t GetTrustedDeviceList(const std::string &pkgName, const std::string &extra,
        std::vector<DmDeviceInfo> &deviceList)
    {
        return 0;
    }

    int32_t GetLocalDeviceInfo(const std::string &pkgName, DmDeviceInfo &deviceInfo)
    {
        strcpy_s(deviceInfo.networkId, DM_MAX_DEVICE_ID_LEN + 1, "deviceid-1");
        return 0;
    }

    int32_t GetUdidByNetworkId(const std::string &pkgName, const std::string &netWorkId, std::string &udid)
    {
        udid = netWorkId + ":udid-001";
        return 0;
    }

    int32_t GetUuidByNetworkId(const std::string &pkgName, const std::string &netWorkId, std::string &uuid)
    {
        uuid = netWorkId + ":uuid-001";
        return 0;
    }
};
} // namespace DistributedHardware
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // OHOS_ACCESS_TOKEN_DEVICE_MANAGER_H