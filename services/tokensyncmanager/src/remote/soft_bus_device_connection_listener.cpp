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

#include "soft_bus_device_connection_listener.h"
#include "remote_command_manager.h"
#include "soft_bus_manager.h"
#include "device_info_manager.h"
#include "softbus_bus_center.h"
#include "constant_common.h"
#include "device_manager.h"
#include "dm_device_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
using OHOS::DistributedHardware::DeviceStateCallback;
using OHOS::DistributedHardware::DmDeviceInfo;
using OHOS::DistributedHardware::DmInitCallback;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "SoftBusDeviceConnectionListener"};
}

const std::string ACCESSTOKEN_PACKAGE_NAME = "ohos.security.distributed_access_token";

SoftBusDeviceConnectionListener::SoftBusDeviceConnectionListener()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "SoftBusDeviceConnectionListener()");
}
SoftBusDeviceConnectionListener::~SoftBusDeviceConnectionListener()
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "~SoftBusDeviceConnectionListener()");
}

void SoftBusDeviceConnectionListener::OnDeviceOnline(const DmDeviceInfo &info)
{
    std::string networkId = info.deviceId;
    std::string uuid = SoftBusManager::GetInstance().GetUniversallyUniqueIdByNodeId(networkId);
    std::string udid = SoftBusManager::GetInstance().GetUniqueDeviceIdByNodeId(networkId);

    ACCESSTOKEN_LOG_INFO(LABEL,
        "networkId: %{public}s, uuid: %{public}s, udid: %{public}s",
        networkId.c_str(),
        uuid.c_str(),
        ConstantCommon::EncryptDevId(udid).c_str());

    if (uuid != "" && udid != "") {
        DeviceInfoManager::GetInstance().AddDeviceInfo(
            networkId, uuid, udid, info.deviceName, std::to_string(info.deviceTypeId));
        RemoteCommandManager::GetInstance().NotifyDeviceOnline(udid);
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "uuid or udid is empty, online failed.");
    }
    // no need to load local permissions by now.
}

void SoftBusDeviceConnectionListener::OnDeviceOffline(const DmDeviceInfo &info)
{
    std::string networkId = info.deviceId;
    std::string uuid = DeviceInfoManager::GetInstance().ConvertToUniversallyUniqueIdOrFetch(networkId);
    std::string udid = DeviceInfoManager::GetInstance().ConvertToUniqueDeviceIdOrFetch(networkId);

    ACCESSTOKEN_LOG_INFO(LABEL,
        "networkId: %{public}s,  uuid: %{public}s, udid: %{public}s",
        networkId.c_str(),
        uuid.c_str(),
        ConstantCommon::EncryptDevId(udid).c_str());

    if (uuid != "" && udid != "") {
        RemoteCommandManager::GetInstance().NotifyDeviceOffline(uuid);
        RemoteCommandManager::GetInstance().NotifyDeviceOffline(udid);
        DeviceInfoManager::GetInstance().RemoveRemoteDeviceInfo(networkId, DeviceIdType::NETWORK_ID);

        std::string packageName = ACCESSTOKEN_PACKAGE_NAME;
        std::string extra = "";
        std::vector<DmDeviceInfo> deviceList;

        int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetTrustedDeviceList(packageName,
            extra, deviceList);
        if (ret != Constant::SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GetTrustedDeviceList error, result: %{public}d", ret);
            return;
        }

        if (deviceList.empty()) {
            ACCESSTOKEN_LOG_INFO(LABEL, "there is no remote decice online, exit tokensync process");

            exit(0);
        }
    } else {
        ACCESSTOKEN_LOG_ERROR(LABEL, "uuid or udid is empty, offline failed.");
    }
}

void SoftBusDeviceConnectionListener::OnDeviceReady(const DmDeviceInfo &info)
{
    std::string networkId = info.deviceId;
    ACCESSTOKEN_LOG_INFO(LABEL, "networkId: %{public}s", networkId.c_str());
}

void SoftBusDeviceConnectionListener::OnDeviceChanged(const DmDeviceInfo &info)
{
    std::string networkId = info.deviceId;
    ACCESSTOKEN_LOG_INFO(LABEL, "networkId: %{public}s", networkId.c_str());
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
