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
#include <string>
#include "accesstoken_kit.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

int32_t main(int argc, char *argv[])
{
    if (argc < 4) { // 4: size
        std::cout << "Help: ./GrantShortTermWriteImageVideo tokenid permisisionName time(s)\n" << std::endl;
        return 0;
    }

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GRANT_SHORT_TERM_WRITE_MEDIAVIDEO");
    FullTokenID mockToken = GetHapTokenId("GrantShortTermWriteImageVideo", reqPerm);
    SetSelfTokenID(mockToken);
    std::cout << "Self tokenId is " << GetSelfTokenID() << std::endl;

    uint32_t tokenId = static_cast<uint32_t>(atoi(argv[1])); // 1: index
    std::string permisisionName = argv[2]; // 2: index
    uint32_t time = static_cast<uint32_t>(atoi(argv[3])); // 3: index

    std::cout << "GrantPermissionForSpecifiedTime begin" << std::endl;
    int32_t ret = AccessTokenKit::GrantPermissionForSpecifiedTime(tokenId, permisisionName, time);
    std::cout << "GrantPermissionForSpecifiedTime end, " << ret << std::endl;

    AccessTokenKit::DeleteToken(static_cast<AccessTokenID>(mockToken));
    return 0;
}
