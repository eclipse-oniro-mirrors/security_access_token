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
#include <iostream>
#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace OHOS::Security::AccessToken;

namespace {
constexpr int32_t FIRST_OPTION_ARG_INDEX = 1;
constexpr int32_t NEXT_ARG_OFFSET = 1;
constexpr int32_t DECIMAL_BASE = 10;
const std::string OPTION_TOKEN_ID = "--tokenid";
const std::string OPTION_PERMISSION = "--permission";
const std::string OPTION_STATUS = "--status";
const std::string OPTION_FLAG = "--flag";
const std::string EDM_PROCESS_NAME = "edm";

void PrintHelp()
{
    std::cout << "Usage: ./SetPermissionStatusWithPolicy <tokenId> <status> <flag> <permission...>\n"
        << "   or: ./SetPermissionStatusWithPolicy --tokenid <tokenId> --status <status> --flag <flag> "
        << "--permission <permission> [--permission <permission> ...]\n"
        << "Example: ./SetPermissionStatusWithPolicy 123456 0 128 ohos.permission.MICROPHONE\n"
        << "status: granted=0, denied=-1; flag: fixedByAdmin=128, cancelAdminPolicy=256\n"
        << std::endl;
}

bool ParseUint32(const char* text, uint32_t& value)
{
    char* end = nullptr;
    unsigned long result = std::strtoul(text, &end, DECIMAL_BASE);
    if ((end == text) || (*end != '\0')) {
        return false;
    }
    value = static_cast<uint32_t>(result);
    return true;
}

bool ParseInt32(const char* text, int32_t& value)
{
    char* end = nullptr;
    long result = std::strtol(text, &end, DECIMAL_BASE);
    if ((end == text) || (*end != '\0')) {
        return false;
    }
    value = static_cast<int32_t>(result);
    return true;
}

bool IsInvalidPermissionArg(const std::string& text)
{
    return text.empty() || text.rfind("--", 0) == 0;
}

bool ParseArgs(int32_t argc, char* argv[], AccessTokenID& tokenId, std::vector<std::string>& permissionList,
    int32_t& status, uint32_t& flag)
{
    if (argc >= 5 && std::string(argv[FIRST_OPTION_ARG_INDEX]).rfind("--", 0) != 0) { // 5: positional min argc
        if (!ParseUint32(argv[1], tokenId) || !ParseInt32(argv[2], status) || !ParseUint32(argv[3], flag)) {
            return false;
        }
        for (int32_t index = 4; index < argc; ++index) { // 4: first permission index
            std::string permissionName = argv[index];
            if (IsInvalidPermissionArg(permissionName)) {
                return false;
            }
            permissionList.emplace_back(permissionName);
        }
        return !permissionList.empty();
    }

    bool hasTokenId = false;
    bool hasStatus = false;
    bool hasFlag = false;

    for (int32_t index = FIRST_OPTION_ARG_INDEX; index < argc; ++index) {
        std::string option = argv[index];
        if ((index + NEXT_ARG_OFFSET) >= argc) {
            return false;
        }

        if (option == OPTION_TOKEN_ID) {
            if (hasTokenId || !ParseUint32(argv[++index], tokenId)) {
                return false;
            }
            hasTokenId = true;
            continue;
        }

        if (option == OPTION_STATUS) {
            if (hasStatus || !ParseInt32(argv[++index], status)) {
                return false;
            }
            hasStatus = true;
            continue;
        }

        if (option == OPTION_FLAG) {
            if (hasFlag || !ParseUint32(argv[++index], flag)) {
                return false;
            }
            hasFlag = true;
            continue;
        }

        if (option == OPTION_PERMISSION) {
            std::string permissionName = argv[++index];
            if (IsInvalidPermissionArg(permissionName)) {
                return false;
            }
            permissionList.emplace_back(permissionName);
            continue;
        }

        return false;
    }

    return hasTokenId && hasStatus && hasFlag && !permissionList.empty();
}

bool SetEdmCaller()
{
    AccessTokenID tokenId = GetNativeTokenId(EDM_PROCESS_NAME);
    if (tokenId == INVALID_TOKENID) {
        std::cout << "Failed to get native token for " << EDM_PROCESS_NAME << std::endl;
        return false;
    }
    SetSelfTokenID(tokenId);
    return true;
}
}

int32_t main(int32_t argc, char* argv[])
{
    AccessTokenID tokenId = INVALID_TOKENID;
    std::vector<std::string> permissionList;
    int32_t status = PERMISSION_DENIED;
    uint32_t flag = PERMISSION_DEFAULT_FLAG;
    if (!ParseArgs(argc, argv, tokenId, permissionList, status, flag)) {
        PrintHelp();
        return 0;
    }

    if (!SetEdmCaller()) {
        return 0;
    }

    int32_t ret = AccessTokenKit::SetPermissionStatusWithPolicy(tokenId, permissionList, status, flag);
    std::cout << "SetPermissionStatusWithPolicy ret=" << ret
        << ", tokenId=" << tokenId
        << ", status=" << status
        << ", flag=" << flag
        << ", permissionCount=" << permissionList.size() << std::endl;
    return 0;
}
