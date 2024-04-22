/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "getallnativetokeninfostub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>
#undef private
#include "accesstoken_info_manager.h"
#include "accesstoken_kit.h"
#include "i_accesstoken_manager.h"
#include "service/accesstoken_manager_service.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
const int CONSTANTS_NUMBER_TWO = 2;

namespace OHOS {
    bool GetAllNativeTokenInfoFuzzTest(const uint8_t* data, size_t size)
    {
#ifdef TOKEN_SYNC_ENABLE
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());

        uint32_t code = static_cast<uint32_t>(
            AccessTokenInterfaceCode::GET_ALL_NATIVE_TOKEN_FROM_REMOTE);

        MessageParcel reply;
        MessageOption option;
        bool enable = ((size % CONSTANTS_NUMBER_TWO) == 0);
        if (enable) {
            AccessTokenID accesstoken = AccessTokenKit::GetNativeTokenId("token_sync_service");
            SetSelfTokenID(accesstoken);
            AccessTokenInfoManager::GetInstance().Init();
        }
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        AccessTokenID hdcd = AccessTokenKit::GetNativeTokenId("hdcd");
        SetSelfTokenID(hdcd);

        return true;
#else
        return true;
#endif
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetAllNativeTokenInfoFuzzTest(data, size);
    return 0;
}
