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
#include <sstream>
#include <string>
#include "accesstoken_kit.h"
#include "privacy_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

AccessTokenID GetNativeTokenIdFromProcess(const std::string &process)
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

int32_t main(int argc, char *argv[])
{
    if (argc < 3) { // 3: size
        std::cout << "Help: ./AddPermissionUsedRecord tokenid permisisionName\n" << std::endl;
        return 0;
    }

    AccessTokenID mockTokenID = GetNativeTokenIdFromProcess("camera_service");
    SetSelfTokenID(mockTokenID);
    std::cout << "#SelfTokenID: " << GetSelfTokenID() << std::endl;

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
