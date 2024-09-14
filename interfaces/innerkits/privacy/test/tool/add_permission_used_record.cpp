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
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "privacy_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

static void NativeTokenGet()
{
    uint64_t tokenID;
    const char **perms = new const char *[1]; // size of array
    perms[0] = "ohos.permission.PERMISSION_USED_STATS"; // 0: index

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1, // size of permission list
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };

    infoInstance.processName = "AddPermissionUsedRecord";
    tokenID = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenID);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

int32_t main(int argc, char *argv[])
{
    if (argc < 3) { // 3: size
        std::cout << "Help: ./AddPermissionUsedRecord tokenid permisisionName\n" << std::endl;
        return 0;
    }

    NativeTokenGet();

    uint32_t tokenId = static_cast<uint32_t>(atoi(argv[1])); // 1: index
    std::string permisisionName = argv[2]; // 2: index
    int32_t ret = PrivacyKit::AddPermissionUsedRecord(tokenId, permisisionName, 1, 0);
    if (ret == 0) {
        std::cout << "Success" << ret << std::endl;
    } else {
        std::cout << "Failed, error: " << ret << std::endl;
    }
    return 0;
}
