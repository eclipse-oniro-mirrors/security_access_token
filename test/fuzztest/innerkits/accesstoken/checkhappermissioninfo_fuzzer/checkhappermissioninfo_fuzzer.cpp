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

#include "checkhappermissioninfo_fuzzer.h"

#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "hap_token_info.h"
#include "mock_permission.h"
#include "access_token.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr uint32_t INSTALL_TYPE_MAX = 2; // TYPE_INSTALL=0, TYPE_REPLACE=1, TYPE_MERGE=2
}

InstallTypeEnum ConsumeInstallTypeEnum(FuzzedDataProvider& provider)
{
    return static_cast<InstallTypeEnum>(
        provider.ConsumeIntegralInRange<uint32_t>(0, INSTALL_TYPE_MAX));
}

bool CheckHapPermissionInfoFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    MockToken mock({ "ohos.permission.MANAGE_HAP_TOKENID" });
    
    FuzzedDataProvider provider(data, size);
    
    int32_t sessionId = provider.ConsumeIntegral<int32_t>();
    InstallTypeEnum type = ConsumeInstallTypeEnum(provider);
    
    HapInfoCheckResult result;
    
    AccessTokenKit::CheckHapPermissionInfo(sessionId, type, result);
    
    return true;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Security::AccessToken::CheckHapPermissionInfoFuzzTest(data, size);
    return 0;
}