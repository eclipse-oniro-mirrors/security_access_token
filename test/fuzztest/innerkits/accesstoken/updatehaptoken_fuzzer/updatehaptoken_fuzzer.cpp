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

#include "updatehaptoken_fuzzer.h"

#include <string>

#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
    void InitHapPolicy(FuzzedDataProvider& provider, HapPolicyParams& policy)
    {
        std::string permissionName = provider.ConsumeRandomLengthString();
        PermissionDef def = {
            .permissionName = permissionName,
            .bundleName = provider.ConsumeRandomLengthString(),
            .grantMode = static_cast<int32_t>(
                provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(GrantMode::SYSTEM_GRANT))),
            .availableLevel = static_cast<ATokenAplEnum>(
                provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(ATokenAplEnum::APL_ENUM_BUTT))),
            .provisionEnable = provider.ConsumeBool(),
            .distributedSceneEnable = provider.ConsumeBool(),
            .label = provider.ConsumeRandomLengthString(),
            .labelId = provider.ConsumeIntegral<int32_t>(),
            .description = provider.ConsumeRandomLengthString(),
            .descriptionId = provider.ConsumeIntegral<int32_t>(),
            .availableType = static_cast<ATokenAvailableTypeEnum>(provider.ConsumeIntegralInRange<uint32_t>(
                0, static_cast<uint32_t>(ATokenAvailableTypeEnum::AVAILABLE_TYPE_BUTT))),
            .isKernelEffect = provider.ConsumeBool(),
            .hasValue = provider.ConsumeBool(),
        };

        PermissionStateFull state = {
            .permissionName = permissionName,
            .isGeneral = provider.ConsumeBool(),
            .resDeviceID = {provider.ConsumeRandomLengthString()},
            .grantStatus = {static_cast<int32_t>(provider.ConsumeIntegralInRange<uint32_t>(
                0, static_cast<uint32_t>(PermissionState::PERMISSION_GRANTED)))},
            .grantFlags = {provider.ConsumeIntegralInRange<uint32_t>(
                0, static_cast<uint32_t>(PermissionFlag::PERMISSION_ALLOW_THIS_TIME))},
        };

        PreAuthorizationInfo info = {
            .permissionName = permissionName,
            .userCancelable = provider.ConsumeBool(),
        };

        policy.apl = static_cast<ATokenAplEnum>(
            provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(ATokenAplEnum::APL_ENUM_BUTT)));
        policy.domain = provider.ConsumeRandomLengthString();
        policy.permList = { def };
        policy.permStateList = { state };
        policy.aclRequestedList = {provider.ConsumeRandomLengthString()};
        policy.preAuthorizationInfo = { info };
        policy.checkIgnore = static_cast<HapPolicyCheckIgnore>(provider.ConsumeIntegralInRange<uint32_t>(
            0, static_cast<uint32_t>(HapPolicyCheckIgnore::ACL_IGNORE_CHECK)));
        policy.aclExtendedMap = {std::make_pair<std::string, std::string>(provider.ConsumeRandomLengthString(),
            provider.ConsumeRandomLengthString())};
    }

    bool UpdateHapTokenFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        AccessTokenIDEx tokenIDex = {
            .tokenIdExStruct.tokenID = provider.ConsumeIntegral<AccessTokenID>(),
            .tokenIdExStruct.tokenAttr = provider.ConsumeIntegral<uint32_t>(),
        };

        UpdateHapInfoParams info = {
            .appIDDesc = provider.ConsumeRandomLengthString(),
            .apiVersion = provider.ConsumeIntegral<int32_t>(),
            .isSystemApp = provider.ConsumeBool(),
            .appDistributionType = provider.ConsumeRandomLengthString(),
            .isAtomicService = provider.ConsumeBool(),
            .dataRefresh = provider.ConsumeBool(),
        };

        HapPolicyParams policy;
        InitHapPolicy(provider, policy);

        return AccessTokenKit::UpdateHapToken(tokenIDex, info, policy) == RET_SUCCESS;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::UpdateHapTokenFuzzTest(data, size);
    return 0;
}
