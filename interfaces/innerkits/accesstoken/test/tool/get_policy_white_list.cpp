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
constexpr int32_t ARG_COUNT = 2;
constexpr int32_t PERMISSION_ARG_INDEX = 1;
const std::string EDM_PROCESS_NAME = "edm";

void PrintHelp()
{
    std::cout << "Help:\n"
        << "  ./GetPolicyWhiteList permissionName\n"
        << "Example:\n"
        << "  ./GetPolicyWhiteList ohos.permission.INTERNET\n"
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
    if (argc != ARG_COUNT) {
        PrintHelp();
        return 0;
    }

    if (!SetEdmCaller()) {
        return 0;
    }

    std::string permissionName = argv[PERMISSION_ARG_INDEX];
    std::vector<AccessTokenID> tokenIdList;
    std::cout << "GetPolicyWhiteList begin, permissionName=" << permissionName << std::endl;
    int32_t ret = AccessTokenKit::GetPolicyWhiteList(permissionName, tokenIdList);
    std::cout << "GetPolicyWhiteList end, ret=" << ret << std::endl;
    std::cout << std::endl;
    std::cout << "tokenSize=" << tokenIdList.size() << std::endl;
    for (const auto& tokenId : tokenIdList) {
        std::cout << "tokenId=" << tokenId << std::endl;
    }
    std::cout << std::endl;
    return 0;
}
