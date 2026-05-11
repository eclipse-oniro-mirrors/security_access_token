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

#include "querystatusbytokenidstub_fuzzer.h"

#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <vector>
#undef private
#include "access_token.h"
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "mock_permission.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "securec.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
namespace {
std::unique_ptr<MockToken> g_mockToken;
}

bool QueryStatusByTokenIDStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);

    // Prepare IPC data parcel
    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());

    // Generate tokenID list with random size (0 to 1025 to test boundary)
    size_t tokenListSize = provider.ConsumeIntegralInRange<size_t>(0, 1025);
    if (!datas.WriteUint32(tokenListSize)) {
        return false;
    }

    for (size_t i = 0; i < tokenListSize; i++) {
        AccessTokenID tokenID = ConsumeTokenId(provider);
        if (!datas.WriteUint32(tokenID)) {
            return false;
        }
    }

    // Get IPC command code
    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_QUERY_STATUS_BY_TOKEN_I_D);

    MessageParcel reply;
    MessageOption option;

    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        code, datas, reply, option);

    return true;
}

void Initialize()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    g_mockToken.reset(new MockToken({ "ohos.permission.GET_SENSITIVE_PERMISSIONS" }, true, true));
    OHOS::Initialize();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::QueryStatusByTokenIDStubFuzzTest(data, size);
    return 0;
}
