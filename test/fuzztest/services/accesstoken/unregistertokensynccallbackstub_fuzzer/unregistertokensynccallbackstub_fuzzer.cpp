/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "unregistertokensynccallbackstub_fuzzer.h"

#undef private
#include "accesstoken_callback_stubs.h"
#include "accesstoken_kit.h"
#include "accesstoken_manager_service.h"
#include "i_accesstoken_manager.h"
#include "token_setproc.h"
#include "token_sync_kit_interface.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
namespace {
class TokenSyncCallbackImpl : public TokenSyncCallbackStub {
public:
    TokenSyncCallbackImpl() = default;
    virtual ~TokenSyncCallbackImpl() = default;

    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) override
    {
        return TokenSyncError::TOKEN_SYNC_OPENSOURCE_DEVICE;
    };

    int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) override
    {
        return TokenSyncError::TOKEN_SYNC_SUCCESS;
    };

    int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) override
    {
        return TokenSyncError::TOKEN_SYNC_SUCCESS;
    };
};

bool NativeTokenGet()
{
    AccessTokenID token = AccessTokenKit::GetNativeTokenId("token_sync_service");
    if (token == 0) {
        return false;
    }
    SetSelfTokenID(token);
    return true;
}
};

namespace OHOS {
    bool RegisterTokenSyncCallbackStubFuzzTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return false;
        }
    #ifdef TOKEN_SYNC_ENABLE
        if (!NativeTokenGet()) {
            return false;
        }
        sptr<TokenSyncCallbackImpl> callback = new (std::nothrow) TokenSyncCallbackImpl();
        if (callback == nullptr) {
            return false;
        }

        MessageParcel datas;
        datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
        uint32_t code = static_cast<uint32_t>(
            AccessTokenInterfaceCode::UNREGISTER_TOKEN_SYNC_CALLBACK);
        
        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    #endif // TOKEN_SYNC_ENABLE
        return true;
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::RegisterTokenSyncCallbackStubFuzzTest(data, size);
    return 0;
}