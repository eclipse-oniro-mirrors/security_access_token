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

#include "setremotehaptokeninfo_fuzzer.h"

#include <string>
#include <vector>
#include <thread>

#undef private
#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    bool SetRemoteHapTokenInfoFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

#ifdef TOKEN_SYNC_ENABLE
        FuzzedDataProvider provider(data, size);
        HapTokenInfo baseInfo = {
            .ver = '1',
            .userID = provider.ConsumeIntegral<AccessTokenID>(),
            .bundleName = provider.ConsumeRandomLengthString(),
            .apiVersion = provider.ConsumeIntegral<int32_t>(),
            .instIndex = provider.ConsumeIntegral<int32_t>(),
            .dlpType = static_cast<int32_t>(
                provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(HapDlpType::BUTT_DLP_TYPE))),
            .tokenID = provider.ConsumeIntegral<AccessTokenID>(),
            .tokenAttr = provider.ConsumeIntegral<uint32_t>(),
        };

        PermissionStatus state = {
            .permissionName = provider.ConsumeRandomLengthString(),
            .grantStatus = static_cast<int32_t>(provider.ConsumeIntegralInRange<uint32_t>(
                0, static_cast<uint32_t>(PermissionState::PERMISSION_GRANTED))),
            .grantFlag = provider.ConsumeIntegralInRange<uint32_t>(
                0, static_cast<uint32_t>(PermissionFlag::PERMISSION_ALLOW_THIS_TIME))
        };
        std::vector<PermissionStatus> permStateList = {state};

        HapTokenInfoForSync remoteTokenInfo = {
            .baseInfo = baseInfo,
            .permStateList = permStateList
        };

        return AccessTokenKit::SetRemoteHapTokenInfo(
            provider.ConsumeRandomLengthString(), remoteTokenInfo) == RET_SUCCESS;
#else
        return true;
#endif
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetRemoteHapTokenInfoFuzzTest(data, size);
    return 0;
}

