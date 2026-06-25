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

#include "updatehappolicy_fuzzer.h"

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
constexpr uint32_t MAX_PRE_AUTH_COUNT = 5;
}

void InitBundlePolicy(FuzzedDataProvider& provider, BundlePolicy& policy)
{
    uint32_t count = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_PRE_AUTH_COUNT);
    for (uint32_t i = 0; i < count; i++) {
        PreAuthorizationInfo info;
        info.permissionName = ConsumePermissionName(provider);
        info.userCancelable = provider.ConsumeBool();
        policy.preAuthorizationInfo.emplace_back(info);
    }
    policy.dlpType = static_cast<DlpType>(
        provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(DlpType::BUTT_DLP_TYPE)));
    policy.isDebugGrant = provider.ConsumeBool();
}

bool UpdateHapPolicyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MockToken mock({ "ohos.permission.MANAGE_HAP_TOKENID" });
    
    FuzzedDataProvider provider(data, size);
    
    int32_t sessionId = provider.ConsumeIntegral<int32_t>();
    int32_t tokenId = provider.ConsumeIntegral<int32_t>();
    
    BundlePolicy policy;
    InitBundlePolicy(provider, policy);
    
    AccessTokenKit::UpdateHapPolicy(sessionId, tokenId, policy);
    
    return true;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Security::AccessToken::UpdateHapPolicyFuzzTest(data, size);
    return 0;
}
