/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "iservice_registry.h"
#include "softbus_bus_center.h"
#include "soft_bus_socket_listener.h"
#include "system_ability_definition.h"
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
    std::string networkId = info.networkId;
    std::string uuid = SoftBusManager::GetInstance().GetUniversallyUniqueIdByNodeId(networkId);
    std::string udid = SoftBusManager::GetInstance().GetUniqueDeviceIdByNodeId(networkId);

    ACCESSTOKEN_LOG_INFO(LABEL,
        "networkId: %{public}s, uuid: %{public}s, udid: %{public}s",
        ConstantCommon::EncryptDevId(networkId).c_str(),
        ConstantCommon::EncryptDevId(uuid).c_str(),
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

void SoftBusDeviceConnectionListener::UnloadTokensyncService()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Get samgr failed.");
        return ;
    }
    int32_t ret = samgr->UnloadSystemAbility(TOKEN_SYNC_MANAGER_SERVICE_ID);
    if (ret != ERR_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Remove system ability failed.");
    }
}

void SoftBusDeviceConnectionListener::OnDeviceOffline(const DmDeviceInfo &info)
{
    std::string networkId = info.networkId;
    std::string uuid = DeviceInfoManager::GetInstance().ConvertToUniversallyUniqueIdOrFetch(networkId);
    std::string udid = DeviceInfoManager::GetInstance().ConvertToUniqueDeviceIdOrFetch(networkId);
    if ((uuid == "") || (udid == "")) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Uuid or udid is empty, offline failed.");
        return;
    }

    ACCESSTOKEN_LOG_INFO(LABEL, "NetworkId: %{public}s,  uuid: %{public}s, udid: %{public}s.",
        ConstantCommon::EncryptDevId(networkId).c_str(),
        ConstantCommon::EncryptDevId(uuid).c_str(),
        ConstantCommon::EncryptDevId(udid).c_str());

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
        ACCESSTOKEN_LOG_INFO(LABEL, "There is no remote decice online, exit tokensync process");

        UnloadTokensyncService();
    }
}

void SoftBusDeviceConnectionListener::OnDeviceReady(const DmDeviceInfo &info)
{
    std::string networkId = info.networkId;
    ACCESSTOKEN_LOG_INFO(LABEL, "networkId: %{public}s", ConstantCommon::EncryptDevId(networkId).c_str());
}

void SoftBusDeviceConnectionListener::OnDeviceChanged(const DmDeviceInfo &info)
{
    std::string networkId = info.networkId;
    ACCESSTOKEN_LOG_INFO(LABEL, "networkId: %{public}s", ConstantCommon::EncryptDevId(networkId).c_str());
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
