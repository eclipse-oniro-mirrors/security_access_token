/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef TOKEN_SYNC_SERVICE_TEST_H
#define TOKEN_SYNC_SERVICE_TEST_H

#include <gtest/gtest.h>
#include "device_info_manager.h"
#include "device_manager_callback.h"
#include "dm_device_info.h"
#include "remote_command_manager.h"
#include "softbus_bus_center.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
using OHOS::DistributedHardware::DeviceStateCallback;
using OHOS::DistributedHardware::DmDeviceInfo;
using OHOS::DistributedHardware::DmInitCallback;
class TokenSyncServiceTest : public testing::Test {
public:
    TokenSyncServiceTest();
    ~TokenSyncServiceTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void OnDeviceOffline(const DmDeviceInfo &info);
    void SetUp();
    void TearDown();
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif  // TOKEN_SYNC_SERVICE_TEST_H