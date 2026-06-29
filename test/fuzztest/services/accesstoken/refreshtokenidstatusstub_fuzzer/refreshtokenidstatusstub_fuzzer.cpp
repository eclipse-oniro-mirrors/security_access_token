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

#include "refreshtokenidstatusstub_fuzzer.h"

#undef private
#include "accesstoken_fuzzdata.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "mock_permission.h"

using namespace OHOS::Security::AccessToken;

namespace {
constexpr int32_t MIN_RESERVED_TYPE = -1;
constexpr int32_t MAX_RESERVED_TYPE = 4;
}

namespace OHOS {
bool RefreshTokenIdStatusStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    IdentityIdl identity = {
        .uid = provider.ConsumeIntegral<int32_t>(),
        .tokenId = ConsumeTokenId(provider),
    };
    ReservedTypeIdl reserved = static_cast<ReservedTypeIdl>(
        provider.ConsumeIntegralInRange<int32_t>(MIN_RESERVED_TYPE, MAX_RESERVED_TYPE));

    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if ((IdentityIdlBlockMarshalling(datas, identity) != ERR_NONE) ||
        !datas.WriteInt32(static_cast<int32_t>(reserved))) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_REFRESH_TOKEN_STATUS);
    MockToken mock({ "ohos.permission.MANAGE_HAP_TOKENID" }, true, true);
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::RefreshTokenIdStatusStubFuzzTest(data, size);
    return 0;
}
