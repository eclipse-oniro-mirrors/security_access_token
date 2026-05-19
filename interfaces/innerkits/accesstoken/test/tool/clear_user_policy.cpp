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
constexpr int32_t FIRST_PERMISSION_ARG_INDEX = 1;
const std::string EDM_PROCESS_NAME = "edm";

void PrintHelp()
{
    std::cout << "Help:\n"
        << "  ./ClearUserPolicy permissionName [permissionName ...]\n"
        << "Example:\n"
        << "  ./ClearUserPolicy ohos.permission.INTERNET\n"
        << std::endl;
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
    if (argc < MIN_ARG_COUNT) {
        PrintHelp();
        return 0;
    }

    std::vector<std::string> permissionList;
    for (int32_t index = FIRST_PERMISSION_ARG_INDEX; index < argc; ++index) {
        permissionList.emplace_back(argv[index]);
    }

    if (!SetEdmCaller()) {
        return 0;
    }

    std::cout << "ClearUserPolicy begin, permissionSize=" << permissionList.size() << std::endl;
    int32_t ret = AccessTokenKit::ClearUserPolicy(permissionList);
    std::cout << "ClearUserPolicy end, ret=" << ret << std::endl << std::endl;
    return 0;
}
