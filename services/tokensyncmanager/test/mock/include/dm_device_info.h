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

#ifndef OHOS_ACCESS_TOKEN_DEVICE_INFO_H
#define OHOS_ACCESS_TOKEN_DEVICE_INFO_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace DistributedHardware {
static constexpr int32_t DM_MAX_DEVICE_ID_LEN = 96;
static constexpr int32_t DM_MAX_DEVICE_NAME_LEN = 128;

typedef struct DmDeviceInfo {
    /**
     * Device Id of the device.
     */
    char deviceId[DM_MAX_DEVICE_ID_LEN];
    /**
     * Device name of the device.
     */
    char deviceName[DM_MAX_DEVICE_NAME_LEN];
    /**
     * Device type of the device.
     */
    uint16_t deviceTypeId;
    /**
     * NetworkId of the device.
     */
    char networkId[DM_MAX_DEVICE_ID_LEN];
    /**
     * The distance of discovered device, in centimeter(cm).
     */
    int32_t range;
    /**
     * NetworkType of the device.
     */
    int32_t networkType;
    /**
     * Extra data of the device.
     * include json keys: "CONN_ADDR_TYPE", "BR_MAC_", "BLE_MAC", "WIFI_IP", "WIFI_PORT", "CUSTOM_DATA"
     */
    std::string extraData;
} DmDeviceInfo;
} // namespace DistributedHardware
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // OHOS_ACCESS_TOKEN_DEVICE_INFO_H
