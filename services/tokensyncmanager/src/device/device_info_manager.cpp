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

#include "device_info_manager.h"
#include "constant_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "DeviceInfoManager"};
}
DeviceInfoManager &DeviceInfoManager::GetInstance()
{
    static DeviceInfoManager instance;
    return instance;
}

bool DeviceInfoManager::GetDeviceInfo(
    const std::string &nodeId, DeviceIdType deviceIdType, DeviceInfo &deviceInfo) const
{
    return DeviceInfoRepository::GetInstance().FindDeviceInfo(nodeId, deviceIdType, deviceInfo);
}

bool DeviceInfoManager::ExistDeviceInfo(const std::string &nodeId, DeviceIdType deviceIdType) const
{
    DeviceInfo deviceInfo;
    return DeviceInfoRepository::GetInstance().FindDeviceInfo(nodeId, deviceIdType, deviceInfo);
}

void DeviceInfoManager::AddDeviceInfo(const std::string &networkId, const std::string &universallyUniqueId,
    const std::string &uniqueDeviceId, const std::string &deviceName, const std::string &deviceType)
{
    if (!DataValidator::IsDeviceIdValid(networkId) ||
        !DataValidator::IsDeviceIdValid(universallyUniqueId) ||
        !DataValidator::IsDeviceIdValid(uniqueDeviceId) || deviceName.empty() || deviceType.empty()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "addDeviceInfo: input param is invalid");
        return;
    }
    DeviceInfoRepository::GetInstance().SaveDeviceInfo(
        networkId, universallyUniqueId, uniqueDeviceId, deviceName, deviceType);
}

void DeviceInfoManager::RemoveAllRemoteDeviceInfo()
{
    std::string localDevice = ConstantCommon::GetLocalDeviceId();

    DeviceInfo localDeviceInfoOpt;
    if (DeviceInfoRepository::GetInstance().FindDeviceInfo(
        localDevice, DeviceIdType::UNIQUE_DISABILITY_ID, localDeviceInfoOpt)) {
        DeviceInfoRepository::GetInstance().DeleteAllDeviceInfoExceptOne(localDeviceInfoOpt);
    }
}

void DeviceInfoManager::RemoveRemoteDeviceInfo(const std::string &nodeId, DeviceIdType deviceIdType)
{
    if (!DataValidator::IsDeviceIdValid(nodeId)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "removeDeviceInfoByNetworkId: nodeId is invalid");
    } else {
        DeviceInfo deviceInfo;
        std::string localDevice = ConstantCommon::GetLocalDeviceId();
        if (DeviceInfoRepository::GetInstance().FindDeviceInfo(nodeId, deviceIdType, deviceInfo)) {
            if (deviceInfo.deviceId.uniqueDeviceId != localDevice) {
                DeviceInfoRepository::GetInstance().DeleteDeviceInfo(nodeId, deviceIdType);
            }
        }
    }
}

std::string DeviceInfoManager::ConvertToUniversallyUniqueIdOrFetch(const std::string &nodeId) const
{
    std::string result;
    if (!DataValidator::IsDeviceIdValid(nodeId)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertToUniversallyUniqueIdOrFetch: nodeId is invalid.");
        return result;
    }
    DeviceInfo deviceInfo;
    if (!(DeviceInfoRepository::GetInstance().FindDeviceInfo(nodeId, DeviceIdType::UNKNOWN, deviceInfo))) {
        return result;
    }
    std::string universallyUniqueId = deviceInfo.deviceId.universallyUniqueId;
    if (!universallyUniqueId.empty()) {
        result = universallyUniqueId;
        return result;
    }
    std::string udid = SoftBusManager::GetInstance().GetUniversallyUniqueIdByNodeId(nodeId);
    if (!udid.empty()) {
        result = udid;
    }
    return result;
}

std::string DeviceInfoManager::ConvertToUniqueDeviceIdOrFetch(const std::string &nodeId) const
{
    std::string result;
    if (!DataValidator::IsDeviceIdValid(nodeId)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ConvertToUniqueDeviceIdOrFetch: nodeId is invalid.");
        return result;
    }
    DeviceInfo deviceInfo;
    if (DeviceInfoRepository::GetInstance().FindDeviceInfo(nodeId, DeviceIdType::UNKNOWN, deviceInfo)) {
        std::string uniqueDeviceId = deviceInfo.deviceId.uniqueDeviceId;
        if (uniqueDeviceId.empty()) {
            std::string udid = SoftBusManager::GetInstance().GetUniqueDeviceIdByNodeId(nodeId);
            if (!udid.empty()) {
                result = udid;
            } else {
                ACCESSTOKEN_LOG_DEBUG(LABEL,
                    "FindDeviceInfo succeed, udid and local udid is empty, nodeId(%{public}s)",
                    ConstantCommon::EncryptDevId(nodeId).c_str());
            }
        } else {
            ACCESSTOKEN_LOG_DEBUG(LABEL,
                "FindDeviceInfo succeed, udid is empty, nodeId(%{public}s) ",
                ConstantCommon::EncryptDevId(nodeId).c_str());
            result = uniqueDeviceId;
        }
    } else {
        ACCESSTOKEN_LOG_DEBUG(
            LABEL, "FindDeviceInfo failed, nodeId(%{public}s)",
            ConstantCommon::EncryptDevId(nodeId).c_str());
        auto list = DeviceInfoRepository::GetInstance().ListDeviceInfo();
        auto iter = list.begin();
        for (; iter != list.end(); iter++) {
            DeviceInfo info = (*iter);
            ACCESSTOKEN_LOG_DEBUG(
                LABEL, ">>> DeviceInfoRepository device name: %{public}s", info.deviceName.c_str());
            ACCESSTOKEN_LOG_DEBUG(
                LABEL, ">>> DeviceInfoRepository device type: %{public}s", info.deviceType.c_str());
            ACCESSTOKEN_LOG_DEBUG(LABEL,
                ">>> DeviceInfoRepository device network id: %{public}s",
                ConstantCommon::EncryptDevId(info.deviceId.networkId).c_str());
        }
    }
    return result;
}

bool DeviceInfoManager::IsDeviceUniversallyUniqueId(const std::string &nodeId) const
{
    if (!DataValidator::IsDeviceIdValid(nodeId)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "IsDeviceUniversallyUniqueId: nodeId is invalid");
        return false;
    }
    DeviceInfo deviceInfo;
    if (DeviceInfoRepository::GetInstance().FindDeviceInfo(nodeId, DeviceIdType::UNIVERSALLY_UNIQUE_ID, deviceInfo)) {
        return deviceInfo.deviceId.universallyUniqueId == nodeId;
    }
    return false;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
