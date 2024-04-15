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
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

static void NativeTokenGet()
{
    uint64_t tokenID;
    const char **perms = new const char *[5]; // size of array
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC"; // 0: index
    perms[1] = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS"; // 1: index
    perms[2] = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS"; // 2: index
    perms[3] = "ohos.permission.GET_SENSITIVE_PERMISSIONS"; // 3: index
    perms[4] = "ohos.permission.DISABLE_PERMISSION_DIALOG"; // 4: index

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 5, // size of permission list
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };

    infoInstance.processName = "SetPermDialogCapTest";
    tokenID = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenID);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

int32_t main(int argc, char *argv[])
{
    if (argc < 3) { // 3: size
        std::cout << "Help: ./SetPermDialogCapTest bundleName 0/1 (0: allow, 1: forbid)\n" << std::endl;
    }

    NativeTokenGet();

    std::string bundle = argv[1];
    bool isForbidden = static_cast<bool>(atoi(argv[2]));
    HapBaseInfo baseInfo;
    baseInfo.bundleName = bundle;
    baseInfo.instIndex = 0;
    baseInfo.userID = 100; // 100: user id
    AccessTokenKit::SetPermDialogCap(baseInfo, isForbidden);
    return 0;
}
