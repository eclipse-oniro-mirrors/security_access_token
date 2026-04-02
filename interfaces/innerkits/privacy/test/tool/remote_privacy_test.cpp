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
#include "accesstoken_kit.h"
#include <iostream>
#include "token_setproc.h"
#include "privacy_kit.h"

#include <string>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "permission_def.h"
#include "permission_state_full.h"
#include "token_setproc.h"
#include "atm_tools_param_info.h"

#include "perm_active_status_customized_cbk.h"
#include "remote_permission_used_info.h"
#include <vector>
#include <memory>
#include <sstream>
#include <unistd.h>
#include <chrono>
#include <thread>

using namespace std;
using namespace OHOS::Security::AccessToken;

const int32_t LOOP_COUNT = 100;
const int32_t DEFAULT_USER_ID = 100;
const int32_t USER_INDEX = 200000;
const int32_t SLEEP_TIME = 250;
int32_t g_cnt = 0;
AccessTokenID g_audioId = 0;
AccessTokenID g_foundationId = 0;
AccessTokenID g_edmId = 0;
int32_t g_selfUid = 0;

void PrintActiveInfo(ActiveChangeResponse& result)
{
    std::cout << "---------- recv active event ----------" << std::endl;
    std::cout << "callingTokenID = " << result.callingTokenID << std::endl;
    std::cout << "tokenID = " << result.tokenID << std::endl;
    std::cout << "permissionName = " << result.permissionName << std::endl;
    std::cout << "type = " << static_cast<int32_t>(result.type) << std::endl;
    std::cout << "usedType = " << static_cast<int32_t>(result.usedType) << std::endl;
    std::cout << "pid = " << result.pid << std::endl;
    std::cout << "isRemote = " << result.isRemote << std::endl;
    std::cout << "deviceId = " << result.deviceId << std::endl;
    std::cout << "remoteDeviceName = " << result.remoteDeviceName << std::endl;
    std::cout << std::endl;
}

class TestCallback : public PermActiveStatusCustomizedCbk {
public:
explicit TestCallback(const std::vector<std::string>& permList) : PermActiveStatusCustomizedCbk(permList)
{}

virtual void ActiveStatusChangeCallback(ActiveChangeResponse& result)
{
    g_cnt++;
    std::cout << "---------- callback, g_cnt = " << g_cnt << " ----------" << std::endl;
    PrintActiveInfo(result);
}
};

std::vector<shared_ptr<TestCallback>> cbList;

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
    while (pos < dumpInfo.length() && std::isdigit(dumpInfo[pos])) {
        numStr += dumpInfo[pos];
        ++pos;
    }

    return static_cast<AccessTokenID>(std::stoi(numStr));
}

struct MockNativeToken {
    uint64_t selfToken;

    explicit MockNativeToken(const std::string& process)
    {
        selfToken = GetSelfTokenID();
        uint32_t tokenId = GetNativeTokenIdFromProcess(process);
        SetSelfTokenID(tokenId);
    }
    ~MockNativeToken()
    {
        SetSelfTokenID(selfToken);
    }
};

void PrintHelp()
{
    std::cout << "help :" << std::endl;
    std::cout << "addremote deviceId deviceName permissionName successCnt failCnt" << std::endl;
    std::cout << "getremote userId [cam/mic/permissionName] beginTime endTime flag" << std::endl;
    std::cout << std::endl;
    std::cout << "startusing tokenID permissionName" << std::endl;
    std::cout << "stopusing tokenID permissionName" << std::endl;
    std::cout << "startremoteusing deviceId deviceName permissionName" << std::endl;
    std::cout << "stopremoteusing deviceId deviceName permissionName" << std::endl;
    std::cout << "reg cam/mic/all/permissionName" << std::endl;
    std::cout << "unreg" << std::endl;
    std::cout << "getnow" << std::endl;
    std::cout << std::endl;
}

std::vector<std::string> ExtractFromBracketsSimple(const std::string& str)
{
    std::vector<std::string> result;

    size_t start = str.find('[');
    size_t end = str.find(']');
    if (start != std::string::npos && end != std::string::npos && end > start) {
        std::string content = str.substr(start + 1, end - start - 1);
        if (!content.empty()) {
            std::stringstream ss(content);
            std::string token;
            while (std::getline(ss, token, '/')) {
                result.push_back(token);
            }
        }
    }

    return result;
}

void PrintResult(PermissionUsedResult& result)
{
    std::cout << "beginTime = " << result.beginTimeMillis << ", endTIme = " << result.endTimeMillis << std::endl;
    std::vector<BundleUsedRecord>& bundles = result.bundleRecords;
    for (auto& bundle : bundles) {
        std::cout << "deviceId = " << bundle.deviceId << ", deviceName = " << bundle.deviceName;
        std::cout << ", records.size = " << bundle.permissionRecords.size() << std::endl;

        std::cout << "{" << std::endl;
        std::vector<PermissionUsedRecord>& records = bundle.permissionRecords;
        for (auto& record : records) {
            std::cout << "    [perm: " << record.permissionName << " accCnt: " << record.accessCount;
            std::cout << " secCnt: " << record.secAccessCount;
            std::cout << " rejCnt: " << record.rejectCount << " lastAccTime: " << record.lastAccessTime;
            std::cout << " lastRejTime: " << record.lastRejectTime;
            std::cout << " lastDu: " << record.lastAccessDuration << "]" << std::endl;

            std::cout << "        accRec:" << std::endl;
            std::vector<UsedRecordDetail>& accRecords = record.accessRecords;
            for (auto& detail : accRecords) {
                std::cout << "        [time: " << detail.timestamp << " cnt: " << detail.count << "]" << std::endl;
            }

            std::cout << "        rejRec:" << std::endl;
            std::vector<UsedRecordDetail>& rejRecords = record.rejectRecords;
            for (auto& detail : rejRecords) {
                std::cout << "        [time: " << detail.timestamp << " cnt: " << detail.count << "]" << std::endl;
            }
        }

        std::cout << "}" << std::endl << std::endl;
    }
}

void AddRemoteCommand()
{
    RemoteCallerInfo info;
    std::cin >> info.remoteDeviceId;
    std::cin >> info.remoteDeviceName;
    std::string perm;
    std::cin >> perm;

    int32_t successCnt;
    int32_t failCnt;
    std::cin >> successCnt >> failCnt;

    int32_t ret = PrivacyKit::AddRemotePermissionUsedRecord(info, perm, successCnt, failCnt);
    std::cout << "ret = " << ret << std::endl;
}

void GetRemoteCommand()
{
    int32_t userId = 0;
    std::cin >> userId;
    std::string permList;
    std::cin >> permList;
    std::vector<std::string> listTemp = ExtractFromBracketsSimple(permList);
    std::vector<std::string> list;
    for (auto &perm : listTemp) {
        if (perm == "cam") {
            list.push_back("ohos.permission.CAMERA");
        } else if (perm == "mic") {
            list.push_back("ohos.permission.MICROPHONE");
        } else {
            list.push_back(perm);
        }
    }

    int64_t beginTime;
    int64_t endTime;
    int64_t flag;
    std::cin >> beginTime >> endTime >> flag;

    PermissionUsedRequest request;
    request.isRemote = true;
    request.permissionList = list;
    request.beginTimeMillis = beginTime;
    request.endTimeMillis = endTime;
    request.flag = static_cast<PermissionUsageFlag>(flag);

    int32_t uid = userId * USER_INDEX;
    setuid(uid);

    PermissionUsedResult result;
    int32_t ret = PrivacyKit::GetRemotePermissionUsedRecords(request, result);
    if (ret != 0) {
        std::cout << "ret = " << ret << std::endl;
        return;
    }

    PrintResult(result);
    setuid(g_selfUid);
}

void TestAddRemoteStabilityCommand()
{
    RemoteCallerInfo info;
    info.remoteDeviceId = "wendingid";
    info.remoteDeviceName = "wendingname";
    std::string perm = "ohos.permission.CAMERA";
    int32_t failCnt = 0;
    for (int i = 1; i <= LOOP_COUNT; i++) {
        int32_t ret = PrivacyKit::AddRemotePermissionUsedRecord(info, perm, i, failCnt);
        std::cout << "i = " << i << ", ret = " << ret << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    }

    PermissionUsedRequest request;
    request.isRemote = true;
    request.permissionList = std::vector<std::string>();
    request.beginTimeMillis = 0;
    request.endTimeMillis = 0;
    request.flag = static_cast<PermissionUsageFlag>(1);

    int32_t uid = DEFAULT_USER_ID * USER_INDEX;
    setuid(uid);

    for (int i = 1; i <= LOOP_COUNT; i++) {
        PermissionUsedResult result;
        int32_t ret = PrivacyKit::GetRemotePermissionUsedRecords(request, result);
        std::cout << "i = " << i << ", ret = " << ret << std::endl;
    }

    setuid(g_selfUid);
}

void StartCommand()
{
    AccessTokenID id;
    std::cin >> id;
    std::string perm;
    std::cin >> perm;

    int32_t ret = PrivacyKit::StartUsingPermission(id, perm);
    std::cout << "ret = " << ret << std::endl;
}

void StopCommand()
{
    AccessTokenID id;
    std::cin >> id;
    std::string perm;
    std::cin >> perm;

    int32_t ret = PrivacyKit::StopUsingPermission(id, perm);
    std::cout << "ret = " << ret << std::endl;
}

void StartRemoteCommand()
{
    RemoteCallerInfo info;
    std::cin >> info.remoteDeviceId;
    std::cin >> info.remoteDeviceName;
    std::string perm;
    std::cin >> perm;

    int32_t ret = PrivacyKit::StartRemoteUsingPermission(info, perm);
    std::cout << "ret = " << ret << std::endl;
}

void StopRemoteCommand()
{
    RemoteCallerInfo info;
    std::cin >> info.remoteDeviceId;
    std::cin >> info.remoteDeviceName;
    std::string perm;
    std::cin >> perm;

    int32_t ret = PrivacyKit::StopRemoteUsingPermission(info, perm);
    std::cout << "ret = " << ret << std::endl;
}

void RegisterCommand()
{
    std::string perm;
    std::cin >> perm;
    std::vector<std::string> permList;
    if (perm == "cam") {
        permList.push_back("ohos.permission.CAMERA");
    } else if (perm == "mic") {
        permList.push_back("ohos.permission.MICROPHONE");
    } else if (perm == "all") {
        // nothing to filter
    } else {
        permList.push_back(perm);
    }
    std::shared_ptr<TestCallback> ptr = std::make_shared<TestCallback>(permList);
    cbList.push_back(ptr);
    int32_t ret = PrivacyKit::RegisterPermActiveStatusCallback(ptr);
    std::cout << "ret = " << ret << std::endl;
}

void UnregisterCommand()
{
    for (auto ptr : cbList) {
        int32_t ret = PrivacyKit::UnRegisterPermActiveStatusCallback(ptr);
        std::cout << "ret = " << ret << std::endl;
    }
    cbList.clear();
}

void GetNowUsingCommand()
{
    std::vector<CurrUsingPermInfo> infoList;
    int32_t ret = PrivacyKit::GetCurrUsingPermInfo(infoList);
    std::cout << "ret = " << ret << std::endl;
    for (auto info : infoList) {
        PrintActiveInfo(info);
    }
}

void TestStartRemoteStabilityCommand()
{
    RemoteCallerInfo info;
    std::cin >> info.remoteDeviceId;
    std::cin >> info.remoteDeviceName;
    std::string perm;
    std::cin >> perm;

    for (int i = 0; i < LOOP_COUNT; i++) {
        int32_t ret = PrivacyKit::StartRemoteUsingPermission(info, perm);
        std::cout << "i = " << i << "\t, ret = " << ret << std::endl;
    }
    for (int i = 0; i < LOOP_COUNT; i++) {
        int32_t ret = PrivacyKit::StopRemoteUsingPermission(info, perm);
        std::cout << "i = " << i << "\t, ret = " << ret << std::endl;
    }
}

int main(int argc, char **argv)
{
    g_audioId = GetNativeTokenIdFromProcess("audio_server");
    g_foundationId = GetNativeTokenIdFromProcess("foundation");
    g_edmId = GetNativeTokenIdFromProcess("edm");
    g_selfUid = getuid();

    MockNativeToken mock("foundation");

    PrintHelp();

    std::string command;
    while (std::cin >> command) {
        if (command == "h" || command == "-h" || command == "help") {
            PrintHelp();
        } else if (command == "addremote") {
            AddRemoteCommand();
        } else if (command == "getremote") {
            GetRemoteCommand();
        } else if (command == "wendingadd") {
            TestAddRemoteStabilityCommand();
        } else if (command == "startusing") {
            StartCommand();
        } else if (command == "stopusing") {
            StopCommand();
        } else if (command == "startremoteusing") {
            StartRemoteCommand();
        } else if (command == "stopremoteusing") {
            StopRemoteCommand();
        } else if (command == "reg") {
            RegisterCommand();
        } else if (command == "unreg") {
            UnregisterCommand();
        } else if (command == "getnow") {
            GetNowUsingCommand();
        } else if (command == "wendingstart") {
            TestStartRemoteStabilityCommand();
        }
    }

    return 0;
}
