/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "dumptokeninfo_fuzzer.h"

#include <string>
#include <vector>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
static const vector<OptType> TYPE_LIST = {
    DEFAULT_OPER,
    DUMP_TOKEN,
    DUMP_RECORD,
    DUMP_TYPE,
    DUMP_PERM,
    PERM_GRANT,
    PERM_REVOKE
};

namespace OHOS {
bool DumpTokenInfoFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    uint32_t typeIndex = provider.ConsumeIntegral<uint32_t>() % static_cast<uint32_t>(TYPE_LIST.size());
    OptType type = TYPE_LIST[typeIndex];
    AtmToolsParamInfo info = {
        .type = type,
        .tokenId = provider.ConsumeIntegral<AccessTokenID>(),
    };

    std::string dumpInfo;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DumpTokenInfoFuzzTest(data, size);
    return 0;
}
