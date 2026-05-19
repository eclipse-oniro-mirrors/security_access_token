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
constexpr int32_t PERMISSION_ARG_INDEX = 1;
constexpr int32_t PERSIST_ARG_INDEX = 2;
constexpr int32_t FIRST_USER_POLICY_ARG_INDEX = 3;
constexpr int32_t USER_POLICY_ARG_COUNT = 2;
constexpr int32_t MIN_ARG_COUNT = 5;
constexpr int32_t DECIMAL_BASE = 10;
const std::string EDM_PROCESS_NAME = "edm";

void PrintHelp()
{
    std::cout << "Help:\n"
        << "  ./SetUserPolicy permissionName isPersist userId isRestricted [userId isRestricted ...]\n"
        << "Example:\n"
        << "  ./SetUserPolicy ohos.permission.INTERNET false 100 true\n"
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

bool SetEdmCaller()
{
    AccessTokenID tokenId = GetNativeTokenId(EDM_PROCESS_NAME);
    if (tokenId == INVALID_TOKENID) {
        std::cout << "Failed to get native token for " << EDM_PROCESS_NAME << std::endl;
        return false;
    }
    SetSelfTokenID(tokenId);
    std::cout << "Self tokenId is " << GetSelfTokenID() << std::endl;
    return true;
}
}

int32_t main(int argc, char* argv[])
{
    if ((argc < MIN_ARG_COUNT) || ((argc - FIRST_USER_POLICY_ARG_INDEX) % USER_POLICY_ARG_COUNT != 0)) {
        PrintHelp();
        return 0;
    }

    UserPermissionPolicy policy;
    policy.permissionName = argv[PERMISSION_ARG_INDEX];
    if (!ParseBool(argv[PERSIST_ARG_INDEX], policy.isPersist)) {
        PrintHelp();
        return 0;
    }

    for (int32_t index = FIRST_USER_POLICY_ARG_INDEX; index < argc; index += USER_POLICY_ARG_COUNT) {
        UserPolicy userPolicy;
        if (!ParseInt32(argv[index], userPolicy.userId) || !ParseBool(argv[index + 1], userPolicy.isRestricted)) {
            PrintHelp();
            return 0;
        }
        policy.userPolicyList.emplace_back(userPolicy);
    }

    if (!SetEdmCaller()) {
        return 0;
    }

    std::cout << "SetUserPolicy begin, permissionName=" << policy.permissionName
        << ", isPersist=" << policy.isPersist
        << ", userPolicySize=" << policy.userPolicyList.size() << std::endl;
    int32_t ret = AccessTokenKit::SetUserPolicy({ policy });
    std::cout << "SetUserPolicy end, ret=" << ret << std::endl << std::endl;
    return 0;
}
