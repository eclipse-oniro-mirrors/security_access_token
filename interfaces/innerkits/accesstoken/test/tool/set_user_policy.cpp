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
#include <utility>
#include <vector>

#include "accesstoken_kit.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace OHOS::Security::AccessToken;

namespace {
constexpr int32_t FIRST_OPTION_ARG_INDEX = 1;
constexpr int32_t MIN_ARG_COUNT = 4;
constexpr int32_t DECIMAL_BASE = 10;
const std::string OPTION_PERMISSION = "--permission";
const std::string OPTION_PERSIST = "--persist";
const std::string OPTION_USER = "--user";
const std::string EDM_PROCESS_NAME = "edm";

void PrintHelp()
{
    std::cout << "Usage: ./SetUserPolicy <permission> <persist> <userId:isRestricted...>\n"
        << "   or: ./SetUserPolicy --permission <permission> --persist <true|false> "
        << "--user <userId:isRestricted> [--user <userId:isRestricted> ...]\n"
        << "Example1: ./SetUserPolicy ohos.permission.CAMERA false 100:true\n"
        << "Example2: ./SetUserPolicy --permission ohos.permission.CAMERA --persist false "
        << "--user 100:true --permission ohos.permission.MICROPHONE --persist false --user 100:true\n"
        << "isRestricted: true means restricted by admin, false means clear restriction.\n"
        << std::endl;
}

bool ParseBool(const std::string& text, bool& value)
{
    if ((text == "true") || (text == "1")) {
        value = true;
        return true;
    }
    if ((text == "false") || (text == "0")) {
        value = false;
        return true;
    }
    return false;
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

bool IsOptionName(const std::string& text)
{
    return (text == OPTION_PERMISSION) || (text == OPTION_PERSIST) || (text == OPTION_USER);
}

bool ParseUserPolicy(const std::string& text, UserPolicy& userPolicy)
{
    size_t separator = text.find(':');
    if ((separator == std::string::npos) || (separator == 0) || (separator == text.size() - 1)) {
        return false;
    }

    std::string userId = text.substr(0, separator);
    std::string isRestricted = text.substr(separator + 1);
    return ParseInt32(userId.c_str(), userPolicy.userId) && ParseBool(isRestricted, userPolicy.isRestricted);
}

bool FinalizePolicy(UserPermissionPolicy& policy, bool hasPolicy, bool hasPersist,
    std::vector<UserPermissionPolicy>& policyList)
{
    if (!hasPolicy) {
        return true;
    }
    if (policy.permissionName.empty() || !hasPersist || policy.userPolicyList.empty()) {
        return false;
    }
    policyList.emplace_back(std::move(policy));
    policy = {};
    return true;
}

bool ParseArgs(int32_t argc, char* argv[], std::vector<UserPermissionPolicy>& policyList)
{
    if (argc >= 4 && std::string(argv[FIRST_OPTION_ARG_INDEX]).rfind("--", 0) != 0) { // 4: positional min argc
        UserPermissionPolicy policy;
        policy.permissionName = argv[1]; // 1: permission index
        if (policy.permissionName.empty() || IsOptionName(policy.permissionName)) {
            return false;
        }
        if (!ParseBool(argv[2], policy.isPersist)) { // 2: persist index
            return false;
        }
        for (int32_t index = 3; index < argc; ++index) { // 3: first user policy index
            UserPolicy userPolicy;
            if (!ParseUserPolicy(argv[index], userPolicy)) {
                return false;
            }
            policy.userPolicyList.emplace_back(userPolicy);
        }
        policyList.emplace_back(std::move(policy));
        return true;
    }

    UserPermissionPolicy currentPolicy;
    bool hasCurrentPolicy = false;
    bool hasPersist = false;

    for (int32_t index = FIRST_OPTION_ARG_INDEX; index < argc; ++index) {
        std::string option = argv[index];
        if ((index + 1) >= argc) {
            return false;
        }

        if (option == OPTION_PERMISSION) {
            if (!FinalizePolicy(currentPolicy, hasCurrentPolicy, hasPersist, policyList)) {
                return false;
            }
            std::string permissionName = argv[++index];
            if (IsOptionName(permissionName)) {
                return false;
            }
            currentPolicy.permissionName = permissionName;
            hasCurrentPolicy = true;
            hasPersist = false;
            continue;
        }

        if (!hasCurrentPolicy) {
            return false;
        }

        if (option == OPTION_PERSIST) {
            if (hasPersist || !ParseBool(argv[++index], currentPolicy.isPersist)) {
                return false;
            }
            hasPersist = true;
            continue;
        }

        if (option == OPTION_USER) {
            UserPolicy userPolicy;
            if (!ParseUserPolicy(argv[++index], userPolicy)) {
                return false;
            }
            currentPolicy.userPolicyList.emplace_back(userPolicy);
            continue;
        }

        return false;
    }

    return FinalizePolicy(currentPolicy, hasCurrentPolicy, hasPersist, policyList) && !policyList.empty();
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

    std::vector<UserPermissionPolicy> policyList;
    if (!ParseArgs(argc, argv, policyList)) {
        PrintHelp();
        return 0;
    }

    if (!SetEdmCaller()) {
        return 0;
    }

    int32_t ret = AccessTokenKit::SetUserPolicy(policyList);
    std::cout << "SetUserPolicy ret=" << ret << ", permissionCount=" << policyList.size() << std::endl;
    return 0;
}
