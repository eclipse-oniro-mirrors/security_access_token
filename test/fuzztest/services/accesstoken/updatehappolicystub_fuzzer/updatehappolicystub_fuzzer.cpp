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

#include "updatehappolicystub_fuzzer.h"

#undef private
#include "accesstoken_fuzzdata.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "hap_token_info.h"
#include "iaccess_token_manager.h"
#include "mock_permission.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
constexpr uint32_t MAX_PRE_AUTH_COUNT = 5;
constexpr uint32_t IPC_CODE_UPDATE_HAP_POLICY = 84;
constexpr int32_t TEST_USER_ID = 0;
constexpr int32_t DEFAULT_API_VERSION = 8;
const std::string TEST_BUNDLE_NAME = "updatehappolicystub.fuzzer";
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

uint32_t EnsureValidTokenId()
{
    static uint32_t tokenIdValue = 0;
    if (tokenIdValue != 0) {
        return tokenIdValue;
    }

    HapInfoParcel hapInfoParcel;
    InitValidHapInfoParams(hapInfoParcel.hapInfoParameter);
    HapPolicyParcel hapPolicyParcel;
    InitValidHapPolicy(hapPolicyParcel.hapPolicy);

    uint64_t fullTokenIdValue = 0;
    int32_t ret = DelayedSingleton<AccessTokenManagerService>::GetInstance()->AllocHapToken(
        hapInfoParcel, hapPolicyParcel, fullTokenIdValue);
    if (ret != RET_SUCCESS) {
        return 0;
    }

    AccessTokenIDEx fullTokenId = { .tokenIDEx = fullTokenIdValue };
    tokenIdValue = fullTokenId.tokenIdExStruct.tokenID;
    return tokenIdValue;
}

void InitBundlePolicyParcel(FuzzedDataProvider& provider, MessageParcel& datas)
{
    uint32_t count = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_PRE_AUTH_COUNT);
    datas.WriteUint32(count);
    for (uint32_t i = 0; i < count; i++) {
        datas.WriteString(ConsumePermissionName(provider));
        datas.WriteBool(provider.ConsumeBool());
    }
    datas.WriteUint32(provider.ConsumeIntegralInRange<uint32_t>(0, static_cast<uint32_t>(DlpType::BUTT_DLP_TYPE)));
    datas.WriteBool(provider.ConsumeBool());
}

bool UpdateHapPolicyStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    uint32_t validTokenId = EnsureValidTokenId();
    if (validTokenId == 0) {
        return false;
    }

    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    datas.WriteInt32(provider.ConsumeBool() ? static_cast<int32_t>(validTokenId) : provider.ConsumeIntegral<int32_t>());
    datas.WriteUint32(provider.ConsumeIntegral<uint32_t>());
    InitBundlePolicyParcel(provider, datas);

    MessageParcel reply;
    MessageOption option;
    MockToken mock({ "ohos.permission.MANAGE_HAP_TOKENID" });
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        IPC_CODE_UPDATE_HAP_POLICY, datas, reply, option);

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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::UpdateHapPolicyStubFuzzTest(data, size);
    return 0;
}
