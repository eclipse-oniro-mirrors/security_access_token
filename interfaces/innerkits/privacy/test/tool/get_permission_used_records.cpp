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

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "atm_tools_param_info.h"
#include "permission_used_request.h"
#include "permission_used_result.h"
#include "privacy_kit.h"
#include "token_setproc.h"

using namespace OHOS::Security::AccessToken;

namespace {
const char* CAMERA_SERVICE = "camera_service";
const char* OPTION_PERMISSION = "--permission";
const char* OPTION_TOKEN_ID = "--tokenid";
const char* OPTION_BEGIN = "--begin";
const char* OPTION_END = "--end";
const char* OPTION_FLAG = "--flag";
constexpr int OPTION_ARG_STEP = 2;

AccessTokenID GetNativeTokenIdFromProcess(const std::string& process)
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

    std::istringstream iss(numStr);
    AccessTokenID tokenID = 0;
    iss >> tokenID;
    return tokenID;
}

void PrintHelp()
{
    std::cout << "Usage:\n"
        << "  ./GetPermissionUsedRecords --permission <permissionName> [--flag <flag>]\n"
        << "  ./GetPermissionUsedRecords --tokenid <tokenId> [--flag <flag>]\n"
        << "Examples:\n"
        << "  ./GetPermissionUsedRecords --permission ohos.permission.CAMERA\n"
        << "  ./GetPermissionUsedRecords --tokenid 537919488 --flag 1\n"
        << "Flag:\n"
        << "  0: summary records\n"
        << "  1: detail records\n"
        << std::endl;
}

bool ParseInt64(const std::string& text, int64_t& value)
{
    char* end = nullptr;
    long long result = std::strtoll(text.c_str(), &end, 10);
    if ((end == text.c_str()) || (*end != '\0')) {
        return false;
    }
    value = static_cast<int64_t>(result);
    return true;
}

bool ParseInt32(const std::string& text, int32_t& value)
{
    char* end = nullptr;
    long result = std::strtol(text.c_str(), &end, 10);
    if ((end == text.c_str()) || (*end != '\0')) {
        return false;
    }
    value = static_cast<int32_t>(result);
    return true;
}

struct QueryOptions {
    bool hasPermission = false;
    bool hasTokenId = false;
    std::string permissionName;
    AccessTokenID tokenId = 0;
    int64_t beginTime = 0;
    int64_t endTime = 0;
    int32_t flag = static_cast<int32_t>(PermissionUsageFlag::FLAG_PERMISSION_USAGE_SUMMARY);
};

bool ParseArgs(int argc, char* argv[], QueryOptions& options)
{
    int index = 1;
    while (index < argc) {
        std::string option = argv[index];
        if ((index + 1) >= argc) {
            return false;
        }

        std::string value = argv[index + 1];
        if (option == OPTION_PERMISSION) {
            options.permissionName = value;
            options.hasPermission = true;
            index += OPTION_ARG_STEP;
            continue;
        }
        if (option == OPTION_TOKEN_ID) {
            int64_t tokenId = 0;
            if (!ParseInt64(value, tokenId) || tokenId <= 0) {
                return false;
            }
            options.tokenId = static_cast<AccessTokenID>(tokenId);
            options.hasTokenId = true;
            index += OPTION_ARG_STEP;
            continue;
        }
        if (option == OPTION_BEGIN) {
            if (!ParseInt64(value, options.beginTime)) {
                return false;
            }
            index += OPTION_ARG_STEP;
            continue;
        }
        if (option == OPTION_END) {
            if (!ParseInt64(value, options.endTime)) {
                return false;
            }
            index += OPTION_ARG_STEP;
            continue;
        }
        if (option == OPTION_FLAG) {
            if (!ParseInt32(value, options.flag)) {
                return false;
            }
            index += OPTION_ARG_STEP;
            continue;
        }
        return false;
    }

    bool hasTarget = options.hasPermission || options.hasTokenId;
    return hasTarget;
}

void PrintResult(const PermissionUsedResult& result)
{
    std::cout << "beginTimeMillis=" << result.beginTimeMillis
        << ", endTimeMillis=" << result.endTimeMillis << std::endl;
    for (const auto& bundle : result.bundleRecords) {
        std::cout << "bundleName=" << bundle.bundleName
            << ", tokenId=" << bundle.tokenId
            << ", isRemote=" << bundle.isRemote
            << ", deviceId=" << bundle.deviceId
            << ", deviceName=" << bundle.deviceName << std::endl;
        for (const auto& record : bundle.permissionRecords) {
            std::cout << "  permissionName=" << record.permissionName
                << ", enhancedIdentity=" << record.enhancedIdentity
                << ", accessCount=" << record.accessCount
                << ", secAccessCount=" << record.secAccessCount
                << ", rejectCount=" << record.rejectCount
                << ", lastAccessTime=" << record.lastAccessTime
                << ", lastRejectTime=" << record.lastRejectTime
                << ", lastAccessDuration=" << record.lastAccessDuration << std::endl;
            for (const auto& detail : record.accessRecords) {
                std::cout << "    accessRecord: status=" << detail.status
                    << ", lockScreenStatus=" << detail.lockScreenStatus
                    << ", timestamp=" << detail.timestamp
                    << ", accessDuration=" << detail.accessDuration
                    << ", count=" << detail.count
                    << ", type=" << static_cast<int32_t>(detail.type) << std::endl;
            }
            for (const auto& detail : record.rejectRecords) {
                std::cout << "    rejectRecord: status=" << detail.status
                    << ", lockScreenStatus=" << detail.lockScreenStatus
                    << ", timestamp=" << detail.timestamp
                    << ", accessDuration=" << detail.accessDuration
                    << ", count=" << detail.count
                    << ", type=" << static_cast<int32_t>(detail.type) << std::endl;
            }
        }
    }
}
} // namespace

int main(int argc, char* argv[])
{
    QueryOptions options;
    if (!ParseArgs(argc, argv, options)) {
        PrintHelp();
        return 0;
    }

    AccessTokenID selfTokenId = GetNativeTokenIdFromProcess(CAMERA_SERVICE);
    if (selfTokenId == 0) {
        std::cout << "Failed to get native token for " << CAMERA_SERVICE << std::endl;
        return 0;
    }
    SetSelfTokenID(selfTokenId);

    PermissionUsedRequest request;
    request.beginTimeMillis = options.beginTime;
    request.endTimeMillis = options.endTime;
    request.flag = static_cast<PermissionUsageFlag>(options.flag);
    if (options.hasPermission) {
        request.permissionList = { options.permissionName };
    }
    if (options.hasTokenId) {
        request.tokenId = options.tokenId;
    }

    PermissionUsedResult result;
    int32_t ret = PrivacyKit::GetPermissionUsedRecords(request, result);
    if (ret != RET_SUCCESS) {
        std::cout << "GetPermissionUsedRecords failed, ret=" << ret << std::endl;
        return 0;
    }

    PrintResult(result);
    return 0;
}
