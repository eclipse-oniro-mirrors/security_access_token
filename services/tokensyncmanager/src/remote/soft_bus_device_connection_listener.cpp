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
#include "device_info_manager.h"
#include "device_manager.h"
#include "iservice_registry.h"
#include "soft_bus_manager.h"
#include "soft_bus_socket_listener.h"
#include "system_ability_definition.h"
#include "constant_common.h"
#include "dm_device_info.h"
#ifdef MEMORY_MANAGER_ENABLE
#include "mem_mgr_client.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {

const std::string ACCESSTOKEN_PACKAGE_NAME = "ohos.security.distributed_access_token";

SoftBusDeviceConnectionListener::SoftBusDeviceConnectionListener()
{
    LOGD(ATM_DOMAIN, ATM_TAG, "SoftBusDeviceConnectionListener()");
}
SoftBusDeviceConnectionListener::~SoftBusDeviceConnectionListener()
{
    LOGD(ATM_DOMAIN, ATM_TAG, "~SoftBusDeviceConnectionListener()");
}

void SoftBusDeviceConnectionListener::OnDeviceOnline(const DistributedHardware::DmDeviceInfo &info)
{
#ifdef MEMORY_MANAGER_ENABLE
    int32_t pid = getpid();
    Memory::MemMgrClient::GetInstance().SetCritical(pid, true, TOKEN_SYNC_MANAGER_SERVICE_ID);
#endif
    if (!DeviceInfoManager::GetInstance().CheckOsTypeValid(info.extraData)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Unsupport osType, no need to add deviceInfo, networkId:%{public}s",
            ConstantCommon::EncryptDevId(info.networkId).c_str());
        return;
    }

    std::string networkId = std::string(info.networkId);
    std::string uuid = SoftBusManager::GetInstance().GetUniversallyUniqueIdByNodeId(networkId);
    std::string udid = SoftBusManager::GetInstance().GetUniqueDeviceIdByNodeId(networkId);

    LOGI(ATM_DOMAIN, ATM_TAG,
        "networkId: %{public}s, uuid: %{public}s, udid: %{public}s",
        ConstantCommon::EncryptDevId(networkId).c_str(),
        ConstantCommon::EncryptDevId(uuid).c_str(),
        ConstantCommon::EncryptDevId(udid).c_str());

    if (uuid != "" && udid != "") {
        DeviceInfoManager::GetInstance().AddDeviceInfo(
            networkId, uuid, udid, info.deviceName, std::to_string(info.deviceTypeId));
        RemoteCommandManager::GetInstance().NotifyDeviceOnline(udid);
    } else {
        LOGE(ATM_DOMAIN, ATM_TAG, "Uuid or udid is empty, online failed.");
    }
    // no need to load local permissions by now.
}

void SoftBusDeviceConnectionListener::UnloadTokensyncService()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get samgr failed.");
        return ;
    }
    int32_t ret = samgr->UnloadSystemAbility(TOKEN_SYNC_MANAGER_SERVICE_ID);
    if (ret != ERR_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Remove system ability failed.");
    }
}

void SoftBusDeviceConnectionListener::OnDeviceOffline(const DistributedHardware::DmDeviceInfo &info)
{
    std::string networkId = std::string(info.networkId);
    std::string uuid = SoftBusManager::GetInstance().ConvertToUniversallyUniqueIdOrFetch(networkId);
    std::string udid = SoftBusManager::GetInstance().ConvertToUniqueDeviceIdOrFetch(networkId);
    if ((uuid == "") || (udid == "")) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Uuid or udid is empty, offline failed.");
        return;
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "NetworkId: %{public}s,  uuid: %{public}s, udid: %{public}s.",
        ConstantCommon::EncryptDevId(networkId).c_str(),
        ConstantCommon::EncryptDevId(uuid).c_str(),
        ConstantCommon::EncryptDevId(udid).c_str());

    RemoteCommandManager::GetInstance().NotifyDeviceOffline(uuid);
    RemoteCommandManager::GetInstance().NotifyDeviceOffline(udid);
    DeviceInfoManager::GetInstance().RemoveRemoteDeviceInfo(networkId, DeviceIdType::NETWORK_ID);

    std::string packageName = ACCESSTOKEN_PACKAGE_NAME;
    std::string extra = "";
    std::vector<DistributedHardware::DmDeviceInfo> deviceList;

    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetTrustedDeviceList(packageName,
        extra, deviceList);
    if (ret != Constant::SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetTrustedDeviceList error, result: %{public}d", ret);
        return;
    }

    if (deviceList.empty()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "There is no remote decice online, exit tokensync process");

        UnloadTokensyncService();
#ifdef MEMORY_MANAGER_ENABLE
        int32_t pid = getpid();
        Memory::MemMgrClient::GetInstance().SetCritical(pid, false, TOKEN_SYNC_MANAGER_SERVICE_ID);
#endif
    }
}

void SoftBusDeviceConnectionListener::OnDeviceReady(const DistributedHardware::DmDeviceInfo &info)
{
    std::string networkId = std::string(info.networkId);
    LOGI(ATM_DOMAIN, ATM_TAG, "NetworkId: %{public}s", ConstantCommon::EncryptDevId(networkId).c_str());
}

void SoftBusDeviceConnectionListener::OnDeviceChanged(const DistributedHardware::DmDeviceInfo &info)
{
    std::string networkId = std::string(info.networkId);
    LOGI(ATM_DOMAIN, ATM_TAG, "NetworkId: %{public}s", ConstantCommon::EncryptDevId(networkId).c_str());
}
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
