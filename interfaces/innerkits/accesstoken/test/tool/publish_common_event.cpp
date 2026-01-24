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

static std::map<int32_t, std::string> g_event = {
    std::map<int32_t, std::string>::value_type(1, "usual.event.SCREEN_LOCKED"),
    std::map<int32_t, std::string>::value_type(2, "usual.event.SCREEN_UNLOCKED"),
    std::map<int32_t, std::string>::value_type(3, "usual.event.USER_UNLOCKED"),
    std::map<int32_t, std::string>::value_type(4, "usual.event.POWER_CONNECTED"),
    std::map<int32_t, std::string>::value_type(5, "usual.event.POWER_DISCONNECTED"),
    std::map<int32_t, std::string>::value_type(6, "usual.event.THERMAL_LEVEL_CHANGED"),
    std::map<int32_t, std::string>::value_type(7, "usual.event.BATTERY_CHANGED"),
};

static std::map<std::string, int32_t> g_thermalLevel = {
    std::map<std::string, int32_t>::value_type("COOL", 0), // 0: ThermalLevel::COOL
    std::map<std::string, int32_t>::value_type("HOT", 3), // 3: ThermalLevel::HOT
};

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

void PublishBatteryCommonEvent(const std::string& event, int32_t capacity)
{
    const char* uevent = "publish";
    Want want;
    want.SetParam(BatteryInfo::COMMON_EVENT_KEY_CAPACITY, capacity);
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

void PublishThermalLevelCommonEvent(const std::string& event, const std::string& level)
{
    int32_t levelInt;
    if (g_thermalLevel.count(level) == 0) {
        std::cout << "Noexist level, default COOL." << std::endl;
        levelInt = 0;
    } else {
        levelInt = g_thermalLevel[level];
    }
    Want want;
    want.SetParam(std::to_string(0), levelInt);
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

static void PrintUsage()
{
    std::cout << "Help:" << std::endl;
    std::cout << "./Publish 1/2/3/4/5/6/7" << std::endl;
    std::cout << "1: SCREEN_LOCKED" << std::endl;
    std::cout << "2: SCREEN_UNLOCKED" << std::endl;
    std::cout << "3: USER_UNLOCKED" << std::endl;
    std::cout << "4: POWER_CONNECTED" << std::endl;
    std::cout << "5: POWER_DISCONNECTED" << std::endl;
    std::cout << "6: THERMAL_LEVEL_CHANGED" << std::endl;
    std::cout << "7: BATTERY_CHANGED" << std::endl;
}

int32_t main(int argc, char *argv[])
{
    AccessTokenID mockToken = GetNativeTokenId("accountmgr");
    SetSelfTokenID(mockToken);
    setuid(5557); // 5557: uid

    if (argc < 2) { // 2: size
        PrintUsage();
        return -1;
    }

    int32_t event = atoi(argv[1]);
    if (g_event.count(event) == 0) {
        PrintUsage();
        return -1;
    }

    if (event == 6) { // 6: THERMAL_LEVEL_CHANGED
        if (argc < 3) { // 3: size
            std::cout << "./Publish 6 COOL/HOT" << std::endl;
            return -1;
        }
        std::string level = std::string(argv[2]);
        PublishThermalLevelCommonEvent(g_event[event], level);
        return 0;
    }

    if (event == 7) { // 7: BATTERY_CHANGED
        if (argc < 3) { // 3: size
            std::cout << "./Publish 7 capacity" << std::endl;
            return -1;
        }
        int32_t capacity = atoi(argv[2]);
        PublishBatteryCommonEvent(g_event[event], capacity);
        return 0;
    }
    
    PublishCommonEvent(g_event[event]);
    return 0;
}
