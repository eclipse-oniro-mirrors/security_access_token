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
#include <memory>
#include <string>
#include <vector>
#include "accesstoken_kit.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace {
struct UpdateHapTokenOptions final {
    uint64_t tokenId = 0;
    std::vector<std::string> reqPerm;
    std::string appDistributionType;
    bool isSideloadApp = false;
    bool dataRefresh = false;
};

void PrintUpdateHapTokenHelp()
{
    std::cout << "Help: ./UpdateHapToken tokenId [--dist-type <distributionType>] "
        << "[--sideload <true|false>] [--data-refresh <true|false>] [requestPermission ...]\n"
        << "Example1: ./UpdateHapToken 281475008495616 ohos.permission.CAMERA\n"
        << "Example2: ./UpdateHapToken 281475008495616 "
        << "ohos.permission.CAMERA ohos.permission.MICROPHONE\n"
        << "Example3: ./UpdateHapToken 281475008495616 --dist-type developer_id --sideload true "
        << "ohos.permission.CAMERA\n"
        << "Example4: ./UpdateHapToken 281475008495616 --data-refresh true ohos.permission.CAMERA "
        << "ohos.permission.MANAGE_LOCAL_ACCOUNTS\n"
        << "Note: --sideload defaults to false; sideload app must be developer_id distributed, "
        << "inconsistent input is normalized to non-sideload.\n"
        << "Note: --data-refresh is the BMS OTA refresh entry, failed perms are recorded into "
        << "the undefined table for later recheck.\n"
        << std::endl;
}

bool ParseUint64Arg(const std::string& value, uint64_t& result)
{
    if (value.empty()) {
        return false;
    }
    char* end = nullptr;
    unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
    if ((end == nullptr) || (*end != '\0')) {
        return false;
    }
    result = static_cast<uint64_t>(parsed);
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

bool ParseUpdateHapTokenArgs(int argc, char* argv[], UpdateHapTokenOptions& options)
{
    if (!ParseUint64Arg(argv[1], options.tokenId)) {
        std::cout << "UpdateHapToken failed, invalid token id: " << argv[1] << std::endl << std::endl;
        return false;
    }
    for (int32_t i = 2; i < argc; ++i) { // 2: start index
        std::string arg = argv[i];
        if ((arg == "--dist-type") || (arg == "--distribution-type")) {
            if ((i + 1) >= argc) {
                std::cout << "UpdateHapToken failed, missing value for " << arg << std::endl << std::endl;
                return false;
            }
            options.appDistributionType = argv[i + 1];
            ++i;
            continue;
        }
        if ((arg == "--sideload") || (arg == "--is-sideload")) {
            if ((i + 1) >= argc) {
                std::cout << "UpdateHapToken failed, missing value for " << arg << std::endl << std::endl;
                return false;
            }
            if (!ParseBoolArg(argv[i + 1], options.isSideloadApp)) {
                std::cout << "UpdateHapToken failed, invalid " << arg << " value: " << argv[i + 1]
                    << std::endl << std::endl;
                return false;
            }
            ++i;
            continue;
        }
        if ((arg == "--data-refresh") || (arg == "--dataRefresh")) {
            if ((i + 1) >= argc) {
                std::cout << "UpdateHapToken failed, missing value for " << arg << std::endl << std::endl;
                return false;
            }
            if (!ParseBoolArg(argv[i + 1], options.dataRefresh)) {
                std::cout << "UpdateHapToken failed, invalid " << arg << " value: " << argv[i + 1]
                    << std::endl << std::endl;
                return false;
            }
            ++i;
            continue;
        }
        if (!arg.empty() && arg[0] == '-') {
            std::cout << "UpdateHapToken failed, unsupported option: " << arg << std::endl << std::endl;
            return false;
        }
        options.reqPerm.emplace_back(arg);
    }
    return true;
}

bool LoadUpdateContext(AccessTokenIDEx& tokenIdEx, std::string& bundleName, UpdateHapInfoParams& updateInfoParams)
{
    if (tokenIdEx.tokenIdExStruct.tokenID == INVALID_TOKENID) {
        std::cout << "UpdateHapToken failed, tokenId=" << tokenIdEx.tokenIDEx
            << ", token not found" << std::endl << std::endl;
        return false;
    }

    HapTokenInfo hapInfo;
    if (AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapInfo) != RET_SUCCESS) {
        std::cout << "UpdateHapToken failed, unable to query hap info for tokenId=" << tokenIdEx.tokenIDEx
            << std::endl << std::endl;
        return false;
    }
    tokenIdEx.tokenIdExStruct.tokenAttr = hapInfo.tokenAttr;
    bundleName = hapInfo.bundleName;

    HapTokenInfoExt hapInfoExt;
    if (AccessTokenKit::GetHapTokenInfoExtension(tokenIdEx.tokenIdExStruct.tokenID, hapInfoExt) != RET_SUCCESS) {
        std::cout << "UpdateHapToken failed, unable to query hap extension info for bundleName=" << bundleName
            << std::endl << std::endl;
        return false;
    }

    updateInfoParams = {
        .appIDDesc = hapInfoExt.appID,
        .apiVersion = hapInfo.apiVersion,
        .isSystemApp = AccessTokenKit::IsSystemAppByFullTokenID(tokenIdEx.tokenIDEx),
        .appDistributionType = "",
    };
    return true;
}

int32_t RunUpdateHapToken(const UpdateHapTokenOptions& options)
{
    uint64_t selfTokenId = GetSelfTokenID();
    AccessTokenID mockToken = GetNativeTokenId("foundation");
    if (mockToken != selfTokenId) {
        SetSelfTokenID(mockToken);
    }
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = options.tokenId;

    std::string bundleName;
    UpdateHapInfoParams updateInfoParams;
    if (!LoadUpdateContext(tokenIdEx, bundleName, updateInfoParams)) {
        return RET_FAILED;
    }
    updateInfoParams.appDistributionType = options.appDistributionType;
    updateInfoParams.isSideloadApp = options.isSideloadApp;
    updateInfoParams.dataRefresh = options.dataRefresh;

    HapPolicyParams policyParams;
    BuildHapPolicyParams(options.reqPerm, {}, policyParams);

    int32_t ret = AccessTokenKit::UpdateHapToken(tokenIdEx, updateInfoParams, policyParams);
    SetSelfTokenID(selfTokenId);

    std::cout << "UpdateHapToken end, bundleName=" << bundleName
        << ", apiVersion=" << updateInfoParams.apiVersion
        << ", distType=" << updateInfoParams.appDistributionType
        << ", sideload=" << updateInfoParams.isSideloadApp
        << ", dataRefresh=" << updateInfoParams.dataRefresh
        << ", permissionCount=" << options.reqPerm.size()
        << ", tokenId=" << tokenIdEx.tokenIDEx
        << ", ret=" << ret << std::endl << std::endl;
    return (ret == RET_SUCCESS) ? RET_SUCCESS : RET_FAILED;
}
}

int32_t main(int argc, char *argv[])
{
    if (argc < 2) { // 2: size
        PrintUpdateHapTokenHelp();
        return 0;
    }

    UpdateHapTokenOptions options;
    if (!ParseUpdateHapTokenArgs(argc, argv, options)) {
        return RET_FAILED;
    }
    return RunUpdateHapToken(options);
}
