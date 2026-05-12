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

#ifndef ACCESSTOKEN_INFO_DUMPER_H
#define ACCESSTOKEN_INFO_DUMPER_H

#include <string>

#include "access_token.h"
#include "atm_tools_param_info.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenInfoDumper final {
public:
    static void DumpTokenInfo(const AtmToolsParamInfo& info, std::string& dumpInfo);

private:
    AccessTokenInfoDumper() = delete;
    ~AccessTokenInfoDumper() = delete;
    DISALLOW_COPY_AND_MOVE(AccessTokenInfoDumper);

    static void DumpHapTokenInfoByTokenId(AccessTokenID tokenId, std::string& dumpInfo);
    static void DumpHapTokenInfoByBundleName(const std::string& bundleName, std::string& dumpInfo);
    static void DumpAllHapTokenName(std::string& dumpInfo);
    static void DumpNativeTokenInfoByProcessName(const std::string& processName, std::string& dumpInfo);
    static void DumpAllNativeTokenName(std::string& dumpInfo);
    static std::string NativeTokenToString(AccessTokenID tokenId);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESSTOKEN_INFO_DUMPER_H
