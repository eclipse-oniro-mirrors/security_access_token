/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "test_common.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>
#include <iostream>
#include <memory>
#include "accesstoken_kit.h"
#include "token_setproc.h"

using namespace OHOS::Security::AccessToken;
void PrintCurrentTime()
{
    std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    );

    int64_t timestampMs = ms.count();
    time_t timestampS = static_cast<time_t>(timestampMs / 1000);
    struct tm t = {0};
    // localtime is not thread safe, localtime_r first param unit is second, timestamp unit is ms, so divided by 1000
    localtime_r(&timestampS, &t);

    std::cout << "[" << t.tm_hour << ":" << t.tm_min << ":" << t.tm_sec << "] ";
}

AccessTokenID GetNativeTokenId(const std::string& process)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.processName = process;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    size_t pos = dumpInfo.find("\"tokenID\": ");
    if (pos == std::string::npos) {
        return 0;
    }
    pos += std::string("\"tokenID\": ").length();
    std::string numStr;
    while (pos < dumpInfo.length() && std::isdigit(dumpInfo[pos])) {
        numStr += dumpInfo[pos];
        ++pos;
    }

    std::istringstream iss(numStr);
    AccessTokenID tokenID;
    iss >> tokenID;
    return tokenID;
}

AccessTokenID GetHapTokenId(const std::string& bundle, const std::vector<std::string>& reqPerm)
{
    uint64_t selfTokenId = GetSelfTokenID();
    HapInfoParams infoParams = {
        .userID = 0,
        .bundleName = bundle,
        .instIndex = 0,
        .appIDDesc = bundle,
        .apiVersion = 8, // 8: API VERSION
        .isSystemApp = true,
        .appDistributionType = "",
    };

    HapPolicyParams policyParams = {
        .apl = APL_NORMAL,
        .domain = "accesstoken_test_tool",
    };
    for (size_t i = 0; i < reqPerm.size(); ++i) {
        PermissionDef permDefResult;
        if (AccessTokenKit::GetDefPermission(reqPerm[i], permDefResult) != RET_SUCCESS) {
            continue;
        }
        PermissionStateFull permState = {
            .permissionName = reqPerm[i],
            .isGeneral = true,
            .resDeviceID = {"local3"},
            .grantStatus = {PermissionState::PERMISSION_DENIED},
            .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
        };
        policyParams.permStateList.emplace_back(permState);
        if (permDefResult.availableLevel > policyParams.apl) {
            policyParams.aclRequestedList.emplace_back(reqPerm[i]);
        }
    }

    AccessTokenIDEx tokenIdEx = {0};
    AccessTokenID mockToken = GetNativeTokenId("foundation");
    if (mockToken != selfTokenId) {
        // set sh token for self
        SetSelfTokenID(mockToken);
    }

    AccessTokenKit::InitHapToken(infoParams, policyParams, tokenIdEx);

    // restore
    SetSelfTokenID(selfTokenId);
    return tokenIdEx.tokenIdExStruct.tokenID;
}

int32_t DeleteHapTokenID(const std::string& bundleName, bool isReservedTokenId)
{
    uint64_t selfTokenId = GetSelfTokenID();
    AccessTokenID mockToken = GetNativeTokenId("foundation");
    if (mockToken != selfTokenId) {
        SetSelfTokenID(mockToken);
    }
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(0, bundleName, 0);
    if (tokenId != 0) {
        AccessTokenKit::DeleteToken(tokenId, isReservedTokenId);
    } else {
        std::cout << "Failed to get token ID for bundle: " << bundleName << std::endl;
    }
    SetSelfTokenID(selfTokenId);
    return RET_SUCCESS;
}
