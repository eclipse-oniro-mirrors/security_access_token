/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "test_common.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

int32_t main(int argc, char *argv[])
{
    if (argc < 3) { // 3: size
        std::cout << "Help: ./SetPermDialogCap bundleName 0/1 (0: allow, 1: forbid)\n" << std::endl;
        return 0;
    }

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.DISABLE_PERMISSION_DIALOG");
    FullTokenID mockToken = GetHapTokenId("SetPermDialogCap", reqPerm);
    SetSelfTokenID(mockToken);
    std::cout << "Self tokenId is " << GetSelfTokenID() << std::endl;

    std::string bundle = argv[1];
    bool isForbidden = static_cast<bool>(atoi(argv[2]));
    HapBaseInfo baseInfo;
    baseInfo.bundleName = bundle;
    baseInfo.instIndex = 0;
    baseInfo.userID = 100; // 100: user id

    std::cout << "SetPermDialogCap begin" << std::endl;
    int32_t ret = AccessTokenKit::SetPermDialogCap(baseInfo, isForbidden);
    std::cout << "SetPermDialogCap end, " << ret << std::endl;

    AccessTokenKit::DeleteToken(static_cast<AccessTokenID>(mockToken));
    return 0;
}
