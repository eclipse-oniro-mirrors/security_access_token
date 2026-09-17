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
#include <string>
#include <unordered_set>
#include <vector>
#include "test_common.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace {
struct CreateHapTokenOptions final {
    std::string bundleName;
    std::vector<std::string> reqPerm;
    std::vector<std::string> preAuthPerm;
    bool isSystemApp = true;
    int32_t userId = 0;
    int32_t instIndex = 0;
};

void PrintCreateHapTokenHelp()
{
    std::cout << "Usage: ./CreateHapToken <bundleName> [userId] [--user <userId>] [--inst-index <index>] "
        << "[--system-app <true|false>] "
        << "<reqPermission...> [--preauth <permission...>]\n"
        << "Example: ./CreateHapToken com.example.demo --user 100 ohos.permission.CAMERA\n"
        << "Example: ./CreateHapToken com.example.demo.clone --user 100 --inst-index 1 "
        << "ohos.permission.CAMERA\n"
        << "Note: --preauth permissions must also appear in req permissions.\n"
        << std::endl;
}

bool ValidatePreAuthorizedPermissions(const std::vector<std::string>& reqPerm,
    const std::vector<std::string>& preAuthPerm)
{
    std::unordered_set<std::string> reqPermSet(reqPerm.begin(), reqPerm.end());
    for (const auto& permission : preAuthPerm) {
        if (reqPermSet.count(permission) == 0) {
            std::cout << "CreateHapToken failed, pre-authorized permission must be declared in req permissions: "
                << permission << std::endl;
            return false;
        }
    }
    return true;
}

bool ParseBoolArg(const std::string& value, bool& result)
{
    if ((value == "true") || (value == "1")) {
        result = true;
        return true;
    }
    if ((value == "false") || (value == "0")) {
        result = false;
        return true;
    }
    return false;
}

bool ParseInt32Arg(const std::string& value, int32_t& result)
{
    char* end = nullptr;
    long parsedValue = strtol(value.c_str(), &end, 10); // 10: decimal base
    if ((end == value.c_str()) || (*end != '\0')) {
        return false;
    }
    result = static_cast<int32_t>(parsedValue);
    return true;
}

bool ParseCreateHapTokenArgs(int argc, char* argv[], CreateHapTokenOptions& options)
{
    options.bundleName = argv[1]; // 1: index
    bool isPreAuthMode = false;
    bool hasUserId = false;
    for (int32_t i = 2; i < argc; ++i) { // 2: start index
        std::string arg = argv[i];
        if (arg == "--preauth") {
            isPreAuthMode = true;
            continue;
        }
        if (arg == "--system-app") {
            if ((i + 1) >= argc) {
                std::cout << "CreateHapToken failed, missing value for --system-app" << std::endl;
                return false;
            }
            if (!ParseBoolArg(argv[i + 1], options.isSystemApp)) {
                std::cout << "CreateHapToken failed, invalid --system-app value: " << argv[i + 1] << std::endl;
                return false;
            }
            ++i;
            continue;
        }
        if ((arg == "--user") || (arg == "--user-id")) {
            if ((i + 1) >= argc) {
                std::cout << "CreateHapToken failed, missing value for " << arg << std::endl;
                return false;
            }
            if (!ParseInt32Arg(argv[i + 1], options.userId)) {
                std::cout << "CreateHapToken failed, invalid " << arg << " value: " << argv[i + 1] << std::endl;
                return false;
            }
            hasUserId = true;
            ++i;
            continue;
        }
        if (arg == "--inst-index") {
            if ((i + 1) >= argc) {
                std::cout << "CreateHapToken failed, missing value for --inst-index" << std::endl;
                return false;
            }
            if (!ParseInt32Arg(argv[i + 1], options.instIndex) || options.instIndex < 0) {
                std::cout << "CreateHapToken failed, invalid --inst-index value: " << argv[i + 1] << std::endl;
                return false;
            }
            ++i;
            continue;
        }
        if (!arg.empty() && arg[0] == '-') {
            std::cout << "CreateHapToken failed, unsupported option: " << arg << std::endl;
            return false;
        }
        int32_t userId = 0;
        if (!hasUserId && options.reqPerm.empty() && options.preAuthPerm.empty() && ParseInt32Arg(arg, userId)) {
            options.userId = userId;
            hasUserId = true;
            continue;
        }
        if (isPreAuthMode) {
            options.preAuthPerm.emplace_back(arg);
            continue;
        }
        options.reqPerm.emplace_back(arg);
    }
    return ValidatePreAuthorizedPermissions(options.reqPerm, options.preAuthPerm);
}

int32_t RunCreateHapToken(const CreateHapTokenOptions& options)
{
    FullTokenID tokenId = GetHapTokenId(
        options.bundleName, options.reqPerm, options.preAuthPerm, options.isSystemApp, options.userId,
        options.instIndex);
    if (tokenId == INVALID_TOKENID) {
        std::cout << "CreateHapToken ret=" << RET_FAILED << ", bundleName=" << options.bundleName << std::endl;
        return RET_FAILED;
    }
    std::cout << "CreateHapToken ret=" << RET_SUCCESS
        << ", tokenId=" << tokenId
        << ", bundleName=" << options.bundleName
        << ", userId=" << options.userId
        << ", instIndex=" << options.instIndex << std::endl;
    return RET_SUCCESS;
}
}

int32_t main(int argc, char *argv[])
{
    if (argc < 2) { // 2: size
        PrintCreateHapTokenHelp();
        return 0;
    }

    CreateHapTokenOptions options;
    if (!ParseCreateHapTokenArgs(argc, argv, options)) {
        return RET_FAILED;
    }
    return RunCreateHapToken(options);
}
