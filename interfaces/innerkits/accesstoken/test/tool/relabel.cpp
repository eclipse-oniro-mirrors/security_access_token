/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include "accesstoken_kit.h"
#include "battery_srv_client.h"
#include "common_event_constant.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "test_common.h"
#include "token_setproc.h"
#include "want.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::PowerMgr;
using namespace OHOS::AAFwk;
using namespace OHOS::EventFwk;

void PublishCommonEvent(const std::string& event)
{
    Want want;
    want.SetAction(event);

    CommonEventData data;
    data.SetWant(want);

    /* publish */
    if (!CommonEventManager::PublishCommonEvent(data)) {
        std::cout << "Failed to publish " << event << "." << std::endl;
    } else {
        std::cout << "Succeed to publish " << event << "." << std::endl;
    }
}

void PublishBatteryCommonEvent(const std::string& event)
{
    const char* uevent = "relabel";
    Want want;
    want.SetParam(BatteryInfo::COMMON_EVENT_KEY_CAPACITY, BatterySrvClient::GetInstance().GetCapacity());
    want.SetParam(BatteryInfo::COMMON_EVENT_KEY_VOLTAGE, BatterySrvClient::GetInstance().GetVoltage());
    want.SetParam(BatteryInfo::COMMON_EVENT_KEY_TEMPERATURE, BatterySrvClient::GetInstance().GetBatteryTemperature());
    want.SetParam(BatteryInfo::COMMON_EVENT_KEY_HEALTH_STATE,
        static_cast<int32_t>(BatterySrvClient::GetInstance().GetHealthStatus()));
    want.SetParam(BatteryInfo::COMMON_EVENT_KEY_PLUGGED_TYPE,
        static_cast<int32_t>(BatterySrvClient::GetInstance().GetPluggedType()));
    want.SetParam(BatteryInfo::COMMON_EVENT_KEY_CHARGE_STATE,
        static_cast<int32_t>(BatterySrvClient::GetInstance().GetChargingStatus()));
    want.SetParam(BatteryInfo::COMMON_EVENT_KEY_PRESENT, BatterySrvClient::GetInstance().GetPresent());
    want.SetParam(BatteryInfo::COMMON_EVENT_KEY_TECHNOLOGY, BatterySrvClient::GetInstance().GetTechnology());
    want.SetParam(BatteryInfo::COMMON_EVENT_KEY_UEVENT, uevent);

    want.SetAction(event);
    CommonEventData data;
    data.SetWant(want);
    CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(false);

    /* publish */
    if (!CommonEventManager::PublishCommonEvent(data, publishInfo)) {
        std::cout << "Failed to publish " << event << "." << std::endl;
    } else {
        std::cout << "Succeed to publish " << event << "." << std::endl;
    }
}

void PublishThermalLevelCommonEvent(const std::string& event, int32_t level)
{
    Want want;
    want.SetParam(std::to_string(0), level); // ThermalCommonEventCode::CODE_THERMAL_LEVEL_CHANGED
    want.SetAction(event);
    CommonEventData data;
    data.SetWant(want);
    CommonEventPublishInfo publishInfo;
    publishInfo.SetOrdered(false);

    /* publish */
    if (!CommonEventManager::PublishCommonEvent(data, publishInfo)) {
        std::cout << "Failed to publish " << event << "." << std::endl;
    } else {
        std::cout << "Succeed to publish " << event << ", level " << level << "." << std::endl;
    }
}

int32_t main(int argc, char *argv[])
{
    if (argc < 2) { // 2: size
        std::cout << "Help: ./Relabel 0/1 (0: stop, 1: start).\n" << std::endl;
        return -1;
    }

    AccessTokenID mockToken = GetNativeTokenId("accountmgr");
    SetSelfTokenID(mockToken);
    setuid(5557); // 5557: uid
    std::cout << "Self token is " << GetSelfTokenID() << std::endl;

    bool isStart = static_cast<bool>(atoi(argv[1]));
    if (isStart) {
        PublishCommonEvent("usual.event.SCREEN_LOCKED");
        PublishCommonEvent("usual.event.USER_UNLOCKED");
        PublishCommonEvent("usual.event.POWER_CONNECTED");
        PublishBatteryCommonEvent("usual.event.BATTERY_CHANGED");
        PublishThermalLevelCommonEvent("usual.event.THERMAL_LEVEL_CHANGED", 0); // 0: COOL
    } else {
        PublishCommonEvent("usual.event.POWER_DISCONNECTED");
        PublishThermalLevelCommonEvent("usual.event.THERMAL_LEVEL_CHANGED", 3); // 3: HOT
    }
    return 0;
}
