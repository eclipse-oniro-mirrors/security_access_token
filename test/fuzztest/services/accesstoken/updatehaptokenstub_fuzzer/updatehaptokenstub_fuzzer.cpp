/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#include "updatehaptokenstub_fuzzer.h"

#include <string>

#include "accesstoken_fuzzdata.h"
#include "fuzzer/FuzzedDataProvider.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "mock_permission.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
namespace {
constexpr int32_t TEST_USER_ID = 0;
constexpr int32_t DEFAULT_API_VERSION = 8;
const std::string TEST_BUNDLE_NAME = "updatehaptokenstub.fuzzer";
}

void InitValidHapInfoParams(HapInfoParams& param)
{
    param.userID = TEST_USER_ID;
    param.bundleName = TEST_BUNDLE_NAME;
    param.instIndex = 0;
    param.dlpType = static_cast<int32_t>(HapDlpType::DLP_COMMON);
    param.appIDDesc = "fuzzer";
    param.apiVersion = DEFAULT_API_VERSION;
    param.isSystemApp = false;
    param.appDistributionType = "";
    param.isRestore = false;
    param.tokenID = 0;
    param.isAtomicService = false;
}

void InitValidHapPolicy(HapPolicy& policy)
{
    policy.apl = APL_SYSTEM_CORE;
    policy.domain = "test_domain";
}

uint64_t EnsureValidFullTokenId()
{
    static uint64_t fullTokenIdValue = 0;
    if (fullTokenIdValue != 0) {
        return fullTokenIdValue;
    }

    HapInfoParcel hapInfoParcel;
    InitValidHapInfoParams(hapInfoParcel.hapInfoParameter);
    HapPolicyParcel hapPolicyParcel;
    InitValidHapPolicy(hapPolicyParcel.hapPolicy);

    int32_t ret = DelayedSingleton<AccessTokenManagerService>::GetInstance()->AllocHapToken(
        hapInfoParcel, hapPolicyParcel, fullTokenIdValue);
    if (ret != RET_SUCCESS) {
        return 0;
    }
    return fullTokenIdValue;
}

    void InitHapPolicy(FuzzedDataProvider& provider, HapPolicy& policy)
    {
        std::string permissionName = ConsumePermissionName(provider);
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

        PermissionStatus state = {
            .permissionName = permissionName,
            .grantStatus = static_cast<int32_t>(provider.ConsumeIntegralInRange<uint32_t>(
                0, static_cast<uint32_t>(PermissionState::PERMISSION_GRANTED))),
            .grantFlag = provider.ConsumeIntegralInRange<uint32_t>(
                0, static_cast<uint32_t>(PermissionFlag::PERMISSION_ALLOW_THIS_TIME)),
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

    bool UpdateHapTokenStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        uint64_t validFullTokenId = EnsureValidFullTokenId();
        if (validFullTokenId == 0) {
            return false;
        }
        uint64_t fullTokenId = provider.ConsumeBool() ? validFullTokenId : provider.ConsumeIntegral<uint64_t>();
        UpdateHapInfoParamsIdl infoIdl = {
            .appIDDesc = provider.ConsumeRandomLengthString(),
            .apiVersion = provider.ConsumeIntegral<int32_t>(),
            .isSystemApp = provider.ConsumeBool(),
            .appDistributionType = provider.ConsumeRandomLengthString(),
            .isAtomicService = provider.ConsumeBool(),
            .dataRefresh = provider.ConsumeBool(),
        };

        HapPolicyParcel hapPolicyParcel;
        InitHapPolicy(provider, hapPolicyParcel.hapPolicy);

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteUint32(fullTokenId)) {
            return false;
        }
        if (UpdateHapInfoParamsIdlBlockMarshalling(datas, infoIdl) != ERR_NONE) {
            return false;
        }
        if (!datas.WriteParcelable(&hapPolicyParcel)) {
            return false;
        }
        uint32_t code = static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_UPDATE_HAP_TOKEN);
        MessageParcel reply;
        MessageOption option;
        MockToken mock({ "ohos.permission.MANAGE_HAP_TOKENID" });
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }

void Initialize()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Initialize();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::UpdateHapTokenStubFuzzTest(data, size);
    return 0;
}
