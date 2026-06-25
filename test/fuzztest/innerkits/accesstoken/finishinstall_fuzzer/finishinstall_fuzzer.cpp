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

#include "finishinstall_fuzzer.h"

#include <map>
#include <string>

#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mock_permission.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr uint32_t MAX_MODULE_PATH_MAP_COUNT = 128;
}

void InitModulePathMap(FuzzedDataProvider& provider, std::map<std::string, std::string>& pathMap)
{
    uint32_t count = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_MODULE_PATH_MAP_COUNT);
    for (uint32_t i = 0; i < count; i++) {
        std::string key = provider.ConsumeRandomLengthString();
        std::string value = provider.ConsumeRandomLengthString();
        pathMap[key] = value;
    }
}

bool FinishInstallFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MockToken mock({ "ohos.permission.MANAGE_HAP_TOKENID" });
    
    FuzzedDataProvider provider(data, size);
    
    int32_t sessionId = provider.ConsumeIntegral<int32_t>();
    bool isSuccess = provider.ConsumeBool();
    
    std::map<std::string, std::string> modulePathMap;
    InitModulePathMap(provider, modulePathMap);
    
    AccessTokenKit::FinishInstall(sessionId, isSuccess, modulePathMap);
    
    return true;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Security::AccessToken::FinishInstallFuzzTest(data, size);
    return 0;
}
