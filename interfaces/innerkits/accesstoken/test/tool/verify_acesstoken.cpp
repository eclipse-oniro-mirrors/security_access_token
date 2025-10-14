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
#include <unistd.h>
#include "accesstoken_kit.h"

using namespace std;
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

int32_t main(int argc, char *argv[])
{
    if (argc < 4) { // 4: size
        std::cout << "Help: ./VerifyAccessToken tokenid permisisionName duration(s)\n" << std::endl;
        return 0;
    }

    uint32_t tokenId = static_cast<uint32_t>(atoi(argv[1])); // 1: index
    std::string permisisionName = argv[2]; // 2: index
    uint32_t count = static_cast<uint32_t>(atoi(argv[3])); // 3: index
    uint32_t i = 0;
    while (i < count) {
        int32_t status = AccessTokenKit::VerifyAccessToken(tokenId, permisisionName);
        PrintCurrentTime();
        std::cout << "tokenId: " << tokenId << ", perm: " << permisisionName << ", status: " << status << std::endl;
        i++;
        sleep(1);
    }
    return 0;
}
