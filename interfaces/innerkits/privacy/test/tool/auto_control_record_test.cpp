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
#include "atm_tools_param_info.h"

#include <vector>
#include <sstream>
#include <unistd.h>

using namespace std;
using namespace OHOS::Security::AccessToken;

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
    std::cout << "add <tokenId> <permissionName> <targetTokenId> <successCount> <failCount>" << std::endl;
    std::cout << "get <tokenId> <permissionName>  (tokenId=0 means all, permissionName=all means all)" << std::endl;
    std::cout << "remove <tokenId>" << std::endl;
    std::cout << std::endl;
}

void PrintResult(PermissionUsedResult& result)
{
    std::cout << "beginTime = " << result.beginTimeMillis << ", endTime = " << result.endTimeMillis << std::endl;
    std::vector<BundleUsedRecord>& bundles = result.bundleRecords;
    for (auto& bundle : bundles) {
        std::cout << "tokenId = " << bundle.tokenId << ", bundleName = " << bundle.bundleName
                  << ", records.size = " << bundle.permissionRecords.size() << std::endl;

        std::cout << "{" << std::endl;
        std::vector<PermissionUsedRecord>& records = bundle.permissionRecords;
        for (auto& record : records) {
            std::cout << "    [perm: " << record.permissionName
                      << " accCnt: " << record.accessCount
                      << " rejCnt: " << record.rejectCount
                      << " lastAccTime: " << record.lastAccessTime
                      << " lastRejTime: " << record.lastRejectTime
                      << " lastDu: " << record.lastAccessDuration;
            if (record.targetTokenId != 0 && !record.targetBundleName.empty()) {
                std::cout << " targetTokenId: " << record.targetTokenId
                          << " targetBundleName: " << record.targetBundleName;
            }
            std::cout << "]" << std::endl;

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

void AddCommand()
{
    AccessTokenID tokenId = 0;
    AccessTokenID targetTokenId = 0;
    std::string permissionName;
    int32_t successCount = 0;
    int32_t failCount = 0;
    std::cin >> tokenId >> permissionName >> targetTokenId >> successCount >> failCount;

    AddPermParamInfo info;
    info.tokenId = tokenId;
    info.permissionName = permissionName;
    info.successCount = successCount;
    info.failCount = failCount;
    info.targetTokenId = targetTokenId;

    int32_t ret = PrivacyKit::AddPermissionUsedRecord(info);
    std::cout << "ret = " << ret << std::endl;
}

void GetCommand()
{
    AccessTokenID tokenId = 0;
    std::string permissionName;
    std::cin >> tokenId >> permissionName;

    PermissionUsedRequest request;
    request.tokenId = tokenId;
    request.flag = FLAG_PERMISSION_USAGE_DETAIL;
    if (permissionName != "all") {
        request.permissionList.push_back(permissionName);
    }

    PermissionUsedResult result;
    int32_t ret = PrivacyKit::GetPermissionUsedRecords(request, result);
    if (ret != 0) {
        std::cout << "ret = " << ret << std::endl;
        return;
    }
    PrintResult(result);
}

void RemoveCommand()
{
    AccessTokenID tokenId = 0;
    std::cin >> tokenId;

    int32_t ret = PrivacyKit::RemovePermissionUsedRecords(tokenId);
    std::cout << "ret = " << ret << std::endl;
}

int main(int argc, char **argv)
{
    MockNativeToken mock("foundation");

    PrintHelp();

    std::string command;
    while (std::cin >> command) {
        if (command == "h" || command == "-h" || command == "help") {
            PrintHelp();
        } else if (command == "add") {
            AddCommand();
        } else if (command == "get") {
            GetCommand();
        } else if (command == "remove") {
            RemoveCommand();
        }
    }

    return 0;
}
