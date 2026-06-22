/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "verifyaccesstokenstub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#undef private
#include "accesstoken_fuzzdata.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

AccessTokenID g_hdcdTokenID = 0;
static const uint64_t SYSTEM_APP_MASK = (static_cast<uint64_t>(1) << 32);

namespace OHOS {
namespace {
constexpr int32_t TEST_USER_ID = 0;
constexpr int32_t DEFAULT_API_VERSION = 8;
const std::string TEST_BUNDLE_NAME = "verifyaccesstokenstub.fuzzer";
const std::string VALID_PERMISSION_NAME = "ohos.permission.INTERNET";
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
    PermissionStatus state = {
        .permissionName = VALID_PERMISSION_NAME,
        .grantStatus = PermissionState::PERMISSION_GRANTED,
        .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED
    };
    policy.apl = APL_SYSTEM_CORE;
    policy.domain = "test_domain";
    policy.permStateList = { state };
}

AccessTokenID EnsureValidTokenId()
{
    static AccessTokenID tokenIdValue = INVALID_TOKENID;
    if (tokenIdValue != INVALID_TOKENID) {
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
        return INVALID_TOKENID;
    }
    AccessTokenIDEx fullTokenId = { .tokenIDEx = fullTokenIdValue };
    tokenIdValue = fullTokenId.tokenIdExStruct.tokenID;
    return tokenIdValue;
}

    bool VerifyAccessTokenStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        AccessTokenID validTokenId = EnsureValidTokenId();
        if (validTokenId == INVALID_TOKENID) {
            return false;
        }
        AccessTokenID tokenId = provider.ConsumeBool() ? validTokenId : ConsumeTokenId(provider);
        std::string permissionName = provider.ConsumeBool() ? VALID_PERMISSION_NAME : ConsumePermissionName(provider);

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteUint32(tokenId) || !datas.WriteString(permissionName)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            IAccessTokenManagerIpcCode::COMMAND_VERIFY_ACCESS_TOKEN);

        MessageParcel reply;
        MessageOption option;
        uint64_t fulltokenId =
            static_cast<uint64_t>(ConsumeTokenId(provider)) | (provider.ConsumeBool() ? SYSTEM_APP_MASK : 0);
        SetSelfTokenID(fulltokenId);
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        SetSelfTokenID(g_hdcdTokenID);

        return true;
    }

void Initialize()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
    g_hdcdTokenID = AccessTokenKit::GetNativeTokenId("hdcd");
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
    OHOS::VerifyAccessTokenStubFuzzTest(data, size);
    return 0;
}
