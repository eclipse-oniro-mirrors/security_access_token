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

#include "checkhapsigninfo_fuzzer.h"

#include <string>
#include <vector>

#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "hap_token_info.h"
#include "mock_permission.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr uint32_t MAX_HAP_PATHS_COUNT = 128;
constexpr int32_t MAX_USER_ID = 1000;
}

void InitBundleHapList(FuzzedDataProvider& provider, BundleHapList& hapList)
{
    uint32_t pathCount = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_HAP_PATHS_COUNT);
    for (uint32_t i = 0; i < pathCount; i++) {
        hapList.hapPaths.emplace_back(provider.ConsumeRandomLengthString());
    }
    hapList.userId = provider.ConsumeIntegralInRange<int32_t>(0, MAX_USER_ID);
    hapList.isPreInstalled = provider.ConsumeBool();
}

bool CheckHapSignInfoFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MockToken mock({ "ohos.permission.MANAGE_HAP_TOKENID" });
    
    FuzzedDataProvider provider(data, size);
    
    BundleHapList hapList;
    InitBundleHapList(provider, hapList);
    
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    AccessTokenKit::CheckHapSignInfo(hapList, sessionId, bundleInfo, resultInfo);
    
    return true;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Security::AccessToken::CheckHapSignInfoFuzzTest(data, size);
    return 0;
}