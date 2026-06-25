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

#include <iostream>
#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace OHOS::Security::AccessToken;

namespace {
constexpr int32_t MIN_ARG_COUNT = 2;
constexpr int32_t FIRST_OPTION_ARG_INDEX = 1;
const std::string OPTION_PERMISSION = "--permission";
const std::string EDM_PROCESS_NAME = "edm";

void PrintHelp()
{
    std::cout << "Usage: ./ClearUserPolicy <permission...>\n"
        << "   or: ./ClearUserPolicy --permission <permission> [--permission <permission> ...]\n"
        << "Example: ./ClearUserPolicy ohos.permission.CAMERA\n"
        << std::endl;
}

bool IsInvalidPermissionArg(const std::string& text)
{
    return text.empty() || text.rfind("--", 0) == 0;
}

bool ParseArgs(int32_t argc, char* argv[], std::vector<std::string>& permissionList)
{
    if (argc >= MIN_ARG_COUNT && std::string(argv[FIRST_OPTION_ARG_INDEX]).rfind("--", 0) != 0) {
        for (int32_t index = FIRST_OPTION_ARG_INDEX; index < argc; ++index) {
            std::string permissionName = argv[index];
            if (IsInvalidPermissionArg(permissionName)) {
                return false;
            }
            permissionList.emplace_back(permissionName);
        }
        return true;
    }

    for (int32_t index = FIRST_OPTION_ARG_INDEX; index < argc; ++index) {
        std::string option = argv[index];
        if ((option != OPTION_PERMISSION) || ((index + 1) >= argc)) {
            return false;
        }

        std::string permissionName = argv[++index];
        if (IsInvalidPermissionArg(permissionName)) {
            return false;
        }
        permissionList.emplace_back(permissionName);
    }
    return !permissionList.empty();
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

int32_t main(int argc, char* argv[])
{
    if (argc < MIN_ARG_COUNT) {
        PrintHelp();
        return 0;
    }

    std::vector<std::string> permissionList;
    if (!ParseArgs(argc, argv, permissionList)) {
        PrintHelp();
        return 0;
    }

    if (!SetEdmCaller()) {
        return 0;
    }

    int32_t ret = AccessTokenKit::ClearUserPolicy(permissionList);
    std::cout << "ClearUserPolicy ret=" << ret << ", permissionCount=" << permissionList.size() << std::endl;
    return 0;
}
