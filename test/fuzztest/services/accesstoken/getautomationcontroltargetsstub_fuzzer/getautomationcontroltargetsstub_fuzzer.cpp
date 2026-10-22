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

#include "getautomationcontroltargetsstub_fuzzer.h"

#include <chrono>
#include <thread>
#include <vector>

#undef private
#include "accesstoken_fuzzdata.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "mock_permission.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
bool GetAutomationControlTargetsStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    uint32_t controllerTokenId = provider.ConsumeIntegral<uint32_t>();

    MessageParcel sendData;
    if (!sendData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor()) ||
        !sendData.WriteUint32(controllerTokenId)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_GET_AUTOMATION_CONTROL_TARGETS);

    MessageParcel reply;
    MessageOption option;
    MockToken mock({ "ohos.permission.GET_SENSITIVE_PERMISSIONS" }, true, true);
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, sendData, reply, option);

    return true;
}

void Initialize()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
}
} // namespace OHOS

static constexpr int32_t SLEEP_TIME = 5;

void BeforeExit()
{
    std::this_thread::sleep_for(std::chrono::seconds(SLEEP_TIME));
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Initialize();
    (void)atexit(BeforeExit);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::GetAutomationControlTargetsStubFuzzTest(data, size);
    return 0;
}
