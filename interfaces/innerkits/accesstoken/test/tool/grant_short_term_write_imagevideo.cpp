/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

static void NativeTokenGet()
{
    uint64_t tokenID;
    const char **perms = new (std::nothrow) const char *[1]; // size of array
    perms[0] = "ohos.permission.GRANT_SHORT_TERM_WRITE_MEDIAVIDEO"; // 0: index

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1, // size of permission list
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };

    infoInstance.processName = "GrantShortTermWriteImageVideo";
    tokenID = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenID);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

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

int32_t main(int argc, char *argv[])
{
    if (argc < 4) { // 4: size
        std::cout << "Help: ./GrantShortTermWriteImageVideo tokenid permisisionName time(s)\n" << std::endl;
        return 0;
    }

    NativeTokenGet();

    uint32_t tokenId = static_cast<uint32_t>(atoi(argv[1])); // 1: index
    std::string permisisionName = argv[2]; // 2: index
    uint32_t time = static_cast<uint32_t>(atoi(argv[3])); // 3: index

    PrintCurrentTime();
    std::cout << "GrantPermissionForSpecifiedTime begin" << std::endl;
    int32_t ret = AccessTokenKit::GrantPermissionForSpecifiedTime(tokenId, permisisionName, time);
    PrintCurrentTime();
    std::cout << "GrantPermissionForSpecifiedTime end, " << ret << std::endl;
    return 0;
}
