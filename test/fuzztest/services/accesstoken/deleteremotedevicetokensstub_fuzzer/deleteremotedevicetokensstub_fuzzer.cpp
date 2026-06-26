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

#include "deleteremotedevicetokensstub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

#undef private
#include "accesstoken_info_manager.h"
#include "accesstoken_kit.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "mock_permission.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
#ifdef TOKEN_SYNC_ENABLE
namespace {
    AccessTokenID g_tokenSyncTokenId = INVALID_TOKENID;
    AccessTokenID g_hdcdTokenId = INVALID_TOKENID;

    bool SetTokenSyncToken()
    {
        if (g_tokenSyncTokenId == INVALID_TOKENID) {
            MockToken mock({}, false);
            g_tokenSyncTokenId = AccessTokenKit::GetNativeTokenId("token_sync_service");
            g_hdcdTokenId = AccessTokenKit::GetNativeTokenId("hdcd");
        }
        if (g_tokenSyncTokenId == INVALID_TOKENID) {
            return false;
        }
        return SetSelfTokenID(g_tokenSyncTokenId) == 0;
    }
}
#endif

    bool DeleteRemoteDeviceTokensStubFuzzTest(const uint8_t* data, size_t size)
    {
#ifdef TOKEN_SYNC_ENABLE
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
        if (!SetTokenSyncToken()) {
            return false;
        }

        FuzzedDataProvider provider(data, size);
        std::string deviceID = provider.ConsumeRandomLengthString();

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        if (!datas.WriteString(deviceID)) {
            return false;
        }

        uint32_t code = static_cast<uint32_t>(
            IAccessTokenManagerIpcCode::COMMAND_DELETE_REMOTE_DEVICE_TOKENS);

        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        if (g_hdcdTokenId != INVALID_TOKENID) {
            (void)SetSelfTokenID(g_hdcdTokenId);
        }
#endif
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
    OHOS::DeleteRemoteDeviceTokensStubFuzzTest(data, size);
    return 0;
}
