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

#include "gethaptokeninfofromremotestub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>
#undef private

#include "accesstoken_info_manager.h"
#include "accesstoken_kit.h"
#include "accesstoken_manager_service.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
#ifdef TOKEN_SYNC_ENABLE
const int CONSTANTS_NUMBER_TWO = 2;
#endif

namespace OHOS {
    bool GetHapTokenInfoFromRemoteStubFuzzTest(const uint8_t* data, size_t size)
    {
    #ifdef TOKEN_SYNC_ENABLE
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        AccessTokenID tokenId = provider.ConsumeIntegral<AccessTokenID>();

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteUint32(tokenId)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            IAccessTokenManagerIpcCode::COMMAND_GET_HAP_TOKEN_INFO_FROM_REMOTE);

        MessageParcel reply;
        MessageOption option;
        bool enable = ((size % CONSTANTS_NUMBER_TWO) == 0);
        if (enable) {
            AccessTokenID accesstoken = AccessTokenKit::GetNativeTokenId("token_sync_service");
            SetSelfTokenID(accesstoken);
            uint32_t hapSize = 0;
            uint32_t nativeSize = 0;
            uint32_t pefDefSize = 0;
            uint32_t dlpSize = 0;
            std::map<int32_t, int32_t> tokenIdAplMap;
            AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenIdAplMap);
        }
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        AccessTokenID hdcd = AccessTokenKit::GetNativeTokenId("hdcd");
        SetSelfTokenID(hdcd);

        return true;
    #else
        return true;
    #endif
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetHapTokenInfoFromRemoteStubFuzzTest(data, size);
    return 0;
}
