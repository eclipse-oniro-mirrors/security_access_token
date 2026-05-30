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

#include "gethapidentitystub_fuzzer.h"

#include <climits>

#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "hap_token_info_parcel.h"
#include "iaccess_token_manager.h"
#include "mock_permission.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
bool GetHapIdentityStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    HapBaseInfoParcel baseInfoParcel;
    baseInfoParcel.hapBaseInfo.userID = provider.ConsumeIntegralInRange<int32_t>(-1, INT_MAX);
    baseInfoParcel.hapBaseInfo.bundleName = provider.ConsumeRandomLengthString();
    baseInfoParcel.hapBaseInfo.instIndex = provider.ConsumeIntegral<int32_t>();

    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!datas.WriteParcelable(&baseInfoParcel)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_HAP_IDENTITY);
    MockToken mock({}, false);
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
    OHOS::GetHapIdentityStubFuzzTest(data, size);
    return 0;
}
