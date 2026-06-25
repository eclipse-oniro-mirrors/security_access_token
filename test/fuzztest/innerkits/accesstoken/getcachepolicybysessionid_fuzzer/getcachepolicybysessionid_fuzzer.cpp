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

#include "getcachepolicybysessionid_fuzzer.h"

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

bool GetCachePolicyBySessionIdFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MockToken mock({ "ohos.permission.GET_TRUSTED_BUNDLE_INFO" });
    
    FuzzedDataProvider provider(data, size);
    
    int32_t sessionId = provider.ConsumeIntegral<int32_t>();
    std::string bundleName = provider.ConsumeRandomLengthString();
    BundlePolicyInfo bundlePolicyInfo;
    
    AccessTokenKit::GetCachePolicyBySessionId(sessionId, bundleName, bundlePolicyInfo);
    
    return true;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Security::AccessToken::GetCachePolicyBySessionIdFuzzTest(data, size);
    return 0;
}
