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

#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "accesstoken_kit.h"

using namespace OHOS::Security::AccessToken;

namespace {
constexpr int32_t TIME_FIELD_WIDTH = 2;
constexpr char TIME_PADDING_CHAR = '0';
constexpr int32_t DECIMAL_BASE = 10;
constexpr int32_t FIRST_USER_ARG_INDEX = 1;
constexpr int32_t NEXT_ARG_OFFSET = 1;
constexpr int32_t MILLISECONDS_PER_SECOND = 1000;
constexpr int32_t TM_YEAR_BASE = 1900;
constexpr uint64_t INVALID_TIMESTAMP = 0;
constexpr int32_t SUCCESS_EXIT_CODE = 0;
constexpr bool QUERY_ONLY_HAP = true;
constexpr const char* OPTION_PREFIX = "--";

void PrintHelp()
{
    std::cout << "Help:\n"
        << "  ./QueryPermissionStatus --permission permissionName\n"
        << "  ./QueryPermissionStatus --tokenid tokenId\n"
        << std::endl;
}

void PrintPermissionStatus(const PermissionStatus& status)
{
    std::string timestampText = "invalid";
    if (status.timestamp != INVALID_TIMESTAMP) {
        const time_t timestampSec = static_cast<time_t>(status.timestamp / MILLISECONDS_PER_SECOND);
        struct tm localTime = {};
        localtime_r(&timestampSec, &localTime);

        std::ostringstream oss;
        oss << (localTime.tm_year + TM_YEAR_BASE) << "-" <<
            std::setw(TIME_FIELD_WIDTH) << std::setfill(TIME_PADDING_CHAR) << (localTime.tm_mon + 1) << "-" <<
            std::setw(TIME_FIELD_WIDTH) << std::setfill(TIME_PADDING_CHAR) << localTime.tm_mday << " " <<
            std::setw(TIME_FIELD_WIDTH) << std::setfill(TIME_PADDING_CHAR) << localTime.tm_hour << ":" <<
            std::setw(TIME_FIELD_WIDTH) << std::setfill(TIME_PADDING_CHAR) << localTime.tm_min << ":" <<
            std::setw(TIME_FIELD_WIDTH) << std::setfill(TIME_PADDING_CHAR) << localTime.tm_sec;
        timestampText = oss.str();
    }

    std::cout << "tokenID=" << status.tokenID
        << ", permissionName=" << status.permissionName
        << ", grantStatus=" << status.grantStatus
        << ", grantFlag=" << status.grantFlag
        << ", timestamp=" << status.timestamp << " (" << timestampText << ")"
        << std::endl;
}

bool ParseArgs(int argc, char* argv[], AccessTokenID& tokenID, std::vector<std::string>& permissionList)
{
    int32_t i = FIRST_USER_ARG_INDEX;
    while (i < argc) {
        std::string arg = argv[i];
        if (arg == "--tokenid") {
            if ((i + NEXT_ARG_OFFSET) >= argc || tokenID != INVALID_TOKENID || !permissionList.empty()) {
                return false;
            }
            const int32_t nextIndex = i + NEXT_ARG_OFFSET;
            tokenID = static_cast<AccessTokenID>(strtoull(argv[nextIndex], nullptr, DECIMAL_BASE));
            i += NEXT_ARG_OFFSET + 1;
            continue;
        }
        if (arg == "--permission") {
            if (tokenID != INVALID_TOKENID || !permissionList.empty()) {
                return false;
            }
            if ((i + NEXT_ARG_OFFSET) >= argc) {
                return false;
            }
            const int32_t nextIndex = i + NEXT_ARG_OFFSET;
            std::string permissionName = argv[nextIndex];
            if (permissionName.rfind(OPTION_PREFIX, 0) == 0) {
                return false;
            }
            permissionList.emplace_back(permissionName);
            i += NEXT_ARG_OFFSET + 1;
            continue;
        }
        return false;
    }
    return (tokenID != INVALID_TOKENID) ^ (!permissionList.empty());
}
}

int32_t main(int argc, char* argv[])
{
    AccessTokenID tokenID = INVALID_TOKENID;
    std::vector<std::string> permissionList;
    if (!ParseArgs(argc, argv, tokenID, permissionList)) {
        PrintHelp();
        return SUCCESS_EXIT_CODE;
    }

    std::vector<PermissionStatus> permissionInfoList;
    int32_t ret = RET_SUCCESS;
    if (tokenID != INVALID_TOKENID) {
        ret = AccessTokenKit::QueryStatusByTokenID({tokenID}, permissionInfoList);
    } else {
        ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList, QUERY_ONLY_HAP);
    }

    std::cout << "QueryPermissionStatus ret=" << ret
        << ", resultSize=" << permissionInfoList.size() << std::endl;
    for (const auto& status : permissionInfoList) {
        PrintPermissionStatus(status);
    }
    return SUCCESS_EXIT_CODE;
}
