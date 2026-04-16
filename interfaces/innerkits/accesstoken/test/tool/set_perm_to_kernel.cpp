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

#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "perm_setproc.h"

using namespace OHOS::Security::AccessToken;

namespace {
constexpr int32_t MIN_ARGC = 3;
constexpr int32_t MAX_ARGC = 4;
constexpr int32_t TOKEN_ID_ARG_INDEX = 1;
constexpr int32_t PERMISSION_NAME_ARG_INDEX = 2;
constexpr int32_t STATUS_ARG_INDEX = 3;
constexpr int32_t DECIMAL_BASE = 10;

void PrintHelp()
{
    std::cout << "Help: ./SetPermToKernel tokenid permissionName [0/1]\n"
        << "  0: revoke in kernel\n"
        << "  1: grant in kernel (default)\n" << std::endl;
}

bool ParseTokenId(const char* tokenIdArg, AccessTokenID& tokenId)
{
    if (tokenIdArg == nullptr) {
        return false;
    }

    errno = 0;
    char* end = nullptr;
    unsigned long long rawTokenId = strtoull(tokenIdArg, &end, DECIMAL_BASE);
    if ((errno != 0) || (end == tokenIdArg) || (*end != '\0') ||
        (rawTokenId > static_cast<unsigned long long>(std::numeric_limits<AccessTokenID>::max()))) {
        return false;
    }

    tokenId = static_cast<AccessTokenID>(rawTokenId);
    return true;
}

bool ParseGrantStatus(int argc, char* argv[], bool& isGranted)
{
    if (argc == MIN_ARGC) {
        isGranted = true;
        return true;
    }

    std::string statusArg = argv[STATUS_ARG_INDEX];
    if (statusArg == "0") {
        isGranted = false;
        return true;
    }
    if (statusArg == "1") {
        isGranted = true;
        return true;
    }
    return false;
}
} // namespace

int32_t main(int argc, char* argv[])
{
    if ((argc < MIN_ARGC) || (argc > MAX_ARGC)) {
        PrintHelp();
        return 0;
    }
    setuid(3020); // 3020: access_token uid

    AccessTokenID tokenId = 0;
    if (!ParseTokenId(argv[TOKEN_ID_ARG_INDEX], tokenId)) {
        std::cout << "Invalid tokenid: " << argv[TOKEN_ID_ARG_INDEX] << std::endl;
        PrintHelp();
        return 0;
    }

    bool isGranted = true;
    if (!ParseGrantStatus(argc, argv, isGranted)) {
        std::cout << "Invalid kernel permission status: " << argv[STATUS_ARG_INDEX] << std::endl;
        PrintHelp();
        return 0;
    }

    std::string permissionName = argv[PERMISSION_NAME_ARG_INDEX];
    uint32_t opCode = 0;
    if (!AccessTokenKit::TransferPermissionToOpcode(permissionName, opCode)) {
        std::cout << "TransferPermissionToOpcode failed, permissionName=" << permissionName << std::endl;
        return 0;
    }

    std::cout << "SetPermToKernel begin, tokenId=" << tokenId
        << ", permissionName=" << permissionName
        << ", opCode=" << opCode
        << ", isGranted=" << isGranted << std::endl;
    int32_t ret = SetPermissionToKernel(tokenId, static_cast<int32_t>(opCode), isGranted);

    bool kernelGrantStatus = false;
    int32_t queryRet = GetPermissionFromKernel(tokenId, static_cast<int32_t>(opCode), kernelGrantStatus);
    std::cout << "SetPermToKernel end, tokenId=" << tokenId
        << ", permissionName=" << permissionName
        << ", opCode=" << opCode
        << ", isGranted=" << isGranted
        << ", ret=" << ret
        << ", queryRet=" << queryRet;
    if (queryRet == ACCESS_TOKEN_OK) {
        std::cout << ", kernelGrantStatus=" << kernelGrantStatus;
    }
    std::cout << std::endl << std::endl;

    return 0;
}
