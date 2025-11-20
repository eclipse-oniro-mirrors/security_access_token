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
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include "accesstoken_kit.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static AccessTokenID GetTokenId(const AtmToolsParamInfo& info)
{
    std::string dumpInfo;
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

std::vector<TokenInfoForTest> GetAllTokenId()
{
    std::vector<TokenInfoForTest> result;
    AtmToolsParamInfo info;
    std::string dumpInfo;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);

    std::istringstream stream(dumpInfo);
    std::string line;
    while (std::getline(stream, line)) {
        TokenInfoForTest tokenInfo;
        size_t pos = line.find(':');
        if (pos != std::string::npos) {
            tokenInfo.tokenID = static_cast<AccessTokenID>(std::stoi(line.substr(0, pos)));
            std::string str = line.substr(pos + 1);
            str.erase(0, str.find_first_not_of(" \t"));
            tokenInfo.name = str;
            result.emplace_back(tokenInfo);
        }
    }
    return result;
}

AccessTokenID GetNativeTokenId(const std::string& process)
{
    AtmToolsParamInfo info;
    info.processName = process;
    return GetTokenId(info);
}

AccessTokenID GetHapTokenId(const std::string& bundle)
{
    AtmToolsParamInfo info;
    info.bundleName = bundle;
    return GetTokenId(info);
}
}
}
}