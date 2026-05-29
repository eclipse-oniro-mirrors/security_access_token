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

#include "checkhapsigninfostub_fuzzer.h"

#include <string>
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
namespace {
constexpr uint32_t MAX_HAP_PATHS_COUNT = 128;
constexpr int32_t MAX_USER_ID = 1000;
constexpr uint32_t IPC_CODE_CHECK_HAP_SIGN_INFO = 82;
}

void InitBundleHapListParcel(FuzzedDataProvider& provider, MessageParcel& datas)
{
    uint32_t pathCount = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_HAP_PATHS_COUNT);
    datas.WriteUint32(pathCount);
    for (uint32_t i = 0; i < pathCount; i++) {
        datas.WriteString(provider.ConsumeRandomLengthString());
    }
    datas.WriteBool(provider.ConsumeBool());
    datas.WriteInt32(provider.ConsumeIntegralInRange<int32_t>(0, MAX_USER_ID));
}

bool CheckHapSignInfoStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);

    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    InitBundleHapListParcel(provider, datas);
    
    sptr<IRemoteObject> cb = nullptr;
    datas.WriteRemoteObject(cb);

    MessageParcel reply;
    MessageOption option;
    MockToken mock({ "ohos.permission.MANAGE_HAP_TOKENID" });
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        IPC_CODE_CHECK_HAP_SIGN_INFO, datas, reply, option);

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
    OHOS::CheckHapSignInfoStubFuzzTest(data, size);
    return 0;
}
