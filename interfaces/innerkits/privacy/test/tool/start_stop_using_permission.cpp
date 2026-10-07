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
#include <sstream>
#include <string>
#include "accesstoken_kit.h"
#include "privacy_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr uint32_t INDEX_ONE = 1;
static constexpr uint32_t INDEX_TWO = 2;
static constexpr uint32_t INDEX_THREE = 3;
static constexpr uint32_t INDEX_FOUR = 4;
static constexpr uint32_t INPUT_COUNT_FOUR = 4; // 4: prog + action + tokenid + permissionName
static constexpr uint32_t INPUT_COUNT_FIVE = 5; // 5: prog + action + tokenid + permissionName + pid
static constexpr int32_t DEFAULT_PID = -1;
static constexpr int32_t RET_NOT_ALLOWED = 1;
static const std::string ACTION_START = "start";
static const std::string ACTION_STOP = "stop";
static const std::string TAG_INIT = "[Init]";
static const std::string TAG_START = "[Start]";
static const std::string TAG_STOP = "[Stop]";
}

void PrintHelp()
{
    std::cout << "Usage:\n"
              << "  StartStopUsingPermission start <tokenid> <permissionName> [pid]\n"
              << "  StartStopUsingPermission stop <tokenid> <permissionName> [pid]\n"
              << "Example:\n"
              << "  ./StartStopUsingPermission start 537002041 ohos.permission.CAMERA\n"
              << "Note:\n"
              << "  start: check IsAllowedUsingPermission first, skip StartUsingPermission when denied.\n"
              << "  pid is optional, default -1.\n"
              << "  Exit code: 0 success, 1 not allowed, others API error code." << std::endl;
}

AccessTokenID GetNativeTokenIdFromProcess(const std::string &process)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.processName = process;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    size_t pos = dumpInfo.find("\"tokenID\": ");
    if (pos == std::string::npos) {
        return 0;
    }
    pos += std::string("\"tokenID\": ").length();
    std::string numStr;
    while (pos < dumpInfo.length() && isdigit(dumpInfo[pos])) {
        numStr += dumpInfo[pos];
        ++pos;
    }

    std::istringstream iss(numStr);
    AccessTokenID tokenID;
    iss >> tokenID;
    return tokenID;
}

void PrintInput(const std::string& tag, const AccessTokenID tokenId, const std::string& permissionName,
    int32_t pid)
{
    std::cout << tag << " input: tokenId=" << tokenId << ", permission=" << permissionName
        << ", pid=" << pid << std::endl;
}

int32_t StartUsingPermission(const AccessTokenID tokenId, const std::string& permissionName, int32_t pid)
{
    PrintInput(TAG_START, tokenId, permissionName, pid);

    bool isAllowed = PrivacyKit::IsAllowedUsingPermission(tokenId, permissionName, pid);
    std::cout << TAG_START << " IsAllowedUsingPermission: " << (isAllowed ? "allowed" : "denied") << std::endl;
    if (!isAllowed) {
        std::cout << TAG_START << " StartUsingPermission skipped: not allowed" << std::endl;
        return RET_NOT_ALLOWED;
    }

    int32_t ret = PrivacyKit::StartUsingPermission(tokenId, permissionName, pid);
    if (ret == RET_SUCCESS) {
        std::cout << TAG_START << " StartUsingPermission: success" << std::endl;
    } else {
        std::cout << TAG_START << " StartUsingPermission: failed, ret=" << ret << std::endl;
    }
    return ret;
}

int32_t StopUsingPermission(const AccessTokenID tokenId, const std::string& permissionName, int32_t pid)
{
    PrintInput(TAG_STOP, tokenId, permissionName, pid);

    int32_t ret = PrivacyKit::StopUsingPermission(tokenId, permissionName, pid);
    if (ret == RET_SUCCESS) {
        std::cout << TAG_STOP << " StopUsingPermission: success" << std::endl;
    } else {
        std::cout << TAG_STOP << " StopUsingPermission: failed, ret=" << ret << std::endl;
    }
    return ret;
}

int32_t main(int argc, char *argv[])
{
    if (argc < static_cast<int32_t>(INPUT_COUNT_FOUR)) {
        PrintHelp();
        return 0;
    }

    std::string action = argv[INDEX_ONE];
    if ((action != ACTION_START) && (action != ACTION_STOP)) {
        PrintHelp();
        return 0;
    }

    AccessTokenID mockTokenID = GetNativeTokenIdFromProcess("camera_service");
    SetSelfTokenID(mockTokenID);
    std::cout << TAG_INIT << " selfTokenId=" << GetSelfTokenID() << " (camera_service)" << std::endl;
    if (mockTokenID == 0) {
        std::cout << TAG_INIT << " warning: camera_service native token not found, calls may be denied"
            << std::endl;
    }

    AccessTokenID tokenId = static_cast<AccessTokenID>(strtoul(argv[INDEX_TWO], nullptr, 0));
    std::string permissionName = argv[INDEX_THREE];
    int32_t pid = (argc >= static_cast<int32_t>(INPUT_COUNT_FIVE)) ? atoi(argv[INDEX_FOUR]) : DEFAULT_PID;

    if (action == ACTION_START) {
        return StartUsingPermission(tokenId, permissionName, pid);
    }
    return StopUsingPermission(tokenId, permissionName, pid);
}
