/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "accesstokenstubcoverage_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include "accesstoken_callback_stubs.h"
#include "accesstoken_kit.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "iaccess_token_manager.h"
#include "token_setproc.h"
#include "token_sync_kit_interface.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
static bool g_reload = true;
static AccessTokenID g_selfTokenId = 0;
static uint64_t g_mockTokenId = 0;
static uint32_t g_executionNum = 0;

namespace OHOS {
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

void RegisterTokenSyncCallback()
{
#ifdef TOKEN_SYNC_ENABLE
    if (g_mockTokenId == 0) {
        g_mockTokenId = AccessTokenKit::GetNativeTokenId("token_sync_service");
    }
    (void)SetSelfTokenID(g_mockTokenId);
    sptr<TokenSyncCallbackImpl> callback = new (std::nothrow) TokenSyncCallbackImpl();
    if (callback == nullptr) {
        return;
    }

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    if (!datas.WriteRemoteObject(callback->AsObject())) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_REGISTER_TOKEN_SYNC_CALLBACK);
    
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
#endif // TOKEN_SYNC_ENABLE
}

void UnRegisterTokenSyncCallback()
{
#ifdef TOKEN_SYNC_ENABLE
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_UN_REGISTER_TOKEN_SYNC_CALLBACK),
        datas, reply, option);
#endif // TOKEN_SYNC_ENABLE
}

void GetVersion()
{
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_VERSION), datas, reply, option);
}

void ReloadNativeTokenInfo()
{
    if (!g_reload) {
        return;
    }
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_RELOAD_NATIVE_TOKEN_INFO), datas, reply, option);
    g_reload = false;
#endif
}

bool AccessTokenStubCoverageFuzzTest(FuzzedDataProvider &provider)
{
    if (g_selfTokenId == 0) {
        g_selfTokenId = GetSelfTokenID();
    }
    ReloadNativeTokenInfo();
    GetVersion();
    RegisterTokenSyncCallback();
    UnRegisterTokenSyncCallback();
    (void)SetSelfTokenID(g_selfTokenId);
    if (g_executionNum < 1) {
        g_executionNum++;
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
        DelayedSingleton<AccessTokenManagerService>::GetInstance()->AccessTokenServiceParamSet();
    }
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if ((data == nullptr) || (size == 0)) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    OHOS::AccessTokenStubCoverageFuzzTest(provider);
    return 0;
}
