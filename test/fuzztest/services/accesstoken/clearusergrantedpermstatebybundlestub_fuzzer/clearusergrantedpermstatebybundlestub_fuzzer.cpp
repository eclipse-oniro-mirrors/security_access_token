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

#include "clearusergrantedpermstatebybundlestub_fuzzer.h"

#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <vector>

#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

AccessTokenID g_hdcdTokenID = INVALID_TOKENID;

namespace OHOS {
    AccessTokenID GetShellTokenForFuzz()
    {
        AccessTokenID shellToken = g_hdcdTokenID;
        AccessTokenID selfToken = static_cast<AccessTokenID>(GetSelfTokenID());
        if ((shellToken == INVALID_TOKENID) && (AccessTokenKit::GetTokenTypeFlag(selfToken) == TOKEN_SHELL)) {
            shellToken = selfToken;
        }
        return shellToken;
    }

    bool ClearUserGrantedPermStateByBundleStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        std::string bundleName = provider.ConsumeRandomLengthString();
        MessageParcel sendData;
        sendData.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!sendData.WriteString(bundleName)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            IAccessTokenManagerIpcCode::COMMAND_CLEAR_USER_GRANTED_PERM_STATE_BY_BUNDLE);

        MessageParcel reply;
        MessageOption option;
        AccessTokenID shellToken = GetShellTokenForFuzz();
        if (shellToken == INVALID_TOKENID) {
            return false;
        }
        uint64_t selfTokenId = GetSelfTokenID();
        if (SetSelfTokenID(shellToken) != RET_SUCCESS) {
            return false;
        }
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, sendData, reply, option);
        (void)SetSelfTokenID(selfTokenId);

        return true;
    }

void Initialize()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->AccessTokenServiceParamSet();
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
    OHOS::ClearUserGrantedPermStateByBundleStubFuzzTest(data, size);
    return 0;
}
