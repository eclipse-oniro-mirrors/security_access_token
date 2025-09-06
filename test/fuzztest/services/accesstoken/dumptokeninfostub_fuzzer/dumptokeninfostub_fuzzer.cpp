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

#include "dumptokeninfostub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#include "accesstoken_fuzzdata.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
static constexpr int32_t NUMBER_THREE = 3;
static constexpr int32_t NUMBER_FOUR = 4;

namespace OHOS {
bool DumpTokenInfoStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    AccessTokenID tokenId = provider.ConsumeIntegral<AccessTokenID>();
    
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return false;
    }

    AtmToolsParamInfo info;
    int32_t ranNum = provider.ConsumeIntegral<int32_t>();
    if ((ranNum % NUMBER_THREE) == 0) {
        info.bundleName = "ohos.global.systemres";
    } else if ((ranNum % NUMBER_FOUR) == 0) {
        info.processName = "accesstoken_service";
    } else {
        info.tokenId = tokenId;
    }
    AtmToolsParamInfoParcel infoParcel;
    infoParcel.info = info;
    if (!datas.WriteParcelable(&infoParcel)) {
        return false;
    }
    
    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_DUMP_TOKEN_INFO);

    MessageParcel reply;
    MessageOption option;
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
    OHOS::DumpTokenInfoStubFuzzTest(data, size);
    return 0;
}
