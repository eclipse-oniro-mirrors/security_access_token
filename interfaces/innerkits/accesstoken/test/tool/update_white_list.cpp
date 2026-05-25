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

#include "accesstoken_kit.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace OHOS::Security::AccessToken;

namespace {
constexpr int32_t ARG_COUNT = 4;
constexpr int32_t TOKEN_ID_ARG_INDEX = 1;
constexpr int32_t PERMISSION_ARG_INDEX = 2;
constexpr int32_t TYPE_ARG_INDEX = 3;
constexpr int32_t DECIMAL_BASE = 10;
const std::string EDM_PROCESS_NAME = "edm";

void PrintHelp()
{
    std::cout << "Help:\n"
        << "  ./UpdateWhiteList tokenId permissionName add|delete\n"
        << "Example:\n"
        << "  ./UpdateWhiteList 537919489 ohos.permission.INTERNET add\n"
        << std::endl;
}

bool ParseTokenId(const char* text, AccessTokenID& tokenId)
{
    char* end = nullptr;
    unsigned long result = std::strtoul(text, &end, DECIMAL_BASE);
    if ((end == text) || (*end != '\0')) {
        return false;
    }
    tokenId = static_cast<AccessTokenID>(result);
    return true;
}

bool ParseUpdateType(const std::string& text, UpdateWhiteListType& type)
{
    if ((text == "add") || (text == "ADD") || (text == "0")) {
        type = ADD;
        return true;
    }
    if ((text == "delete") || (text == "DELETE") || (text == "del") || (text == "1")) {
        type = DELETE;
        return true;
    }
    return false;
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

    AccessTokenID tokenId = INVALID_TOKENID;
    UpdateWhiteListType type = ADD;
    if (!ParseTokenId(argv[TOKEN_ID_ARG_INDEX], tokenId) || !ParseUpdateType(argv[TYPE_ARG_INDEX], type)) {
        PrintHelp();
        return 0;
    }
    std::string permissionName = argv[PERMISSION_ARG_INDEX];

    if (!SetEdmCaller()) {
        return 0;
    }

    std::cout << "UpdateWhiteList begin, tokenId=" << tokenId
        << ", permissionName=" << permissionName
        << ", type=" << static_cast<int32_t>(type) << std::endl;
    int32_t ret = AccessTokenKit::UpdatePolicyWhiteList(tokenId, permissionName, type);
    std::cout << "UpdateWhiteList end, ret=" << ret << std::endl << std::endl;
    return 0;
}
