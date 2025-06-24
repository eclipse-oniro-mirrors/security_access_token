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

#include "inituserpolicystub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>
#undef private
#include "access_token.h"
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "accesstoken_manager_service.h"
#include "iaccess_token_manager.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
static AccessTokenID g_selfTokenId = 0;
static uint64_t g_mockTokenId = 0;
const int32_t CONSTANTS_NUMBER_TWO = 2;
static bool g_reload = true;

namespace OHOS {
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
#endif
    g_reload = false;
}
void GetNativeToken()
{
    ReloadNativeTokenInfo();
    if (g_mockTokenId != 0) {
        (void)SetSelfTokenID(g_mockTokenId);
        return;
    }
    g_selfTokenId = GetSelfTokenID();
    g_mockTokenId = AccessTokenKit::GetNativeTokenId("foundation");
    if (g_mockTokenId == 0) {
        return;
    }
    (void)SetSelfTokenID(g_mockTokenId);
}

void ClearUserPolicy()
{
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_CLEAR_USER_POLICY), datas, reply, option);
}

void UpdateUserPolicy(AccessTokenFuzzData &fuzzData)
{
    UserState userList;
    userList.userId = fuzzData.GetData<int32_t>();
    userList.isActive = fuzzData.GenerateStochasticBool();

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    if (!datas.WriteUint32(1)) {
        return;
    }
    if (!datas.WriteInt32(userList.userId)) {
        return;
    }
    if (!datas.WriteBool(userList.isActive)) {
        return;
    }

    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_UPDATE_USER_POLICY), datas, reply, option);
}

bool InitUserPolicyStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    AccessTokenFuzzData fuzzData(data, size);
    std::string testName(fuzzData.GenerateStochasticString());

    UserState userList;
    userList.userId = fuzzData.GetData<int32_t>();
    userList.isActive = fuzzData.GenerateStochasticBool();

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return false;
    }
    if (!datas.WriteUint32(1)) {
        return false;
    }
    if (!datas.WriteUint32(1)) {
        return false;
    }
    if (!datas.WriteInt32(userList.userId)) {
        return false;
    }
    if (!datas.WriteBool(userList.isActive)) {
        return false;
    }
    if (!datas.WriteString(testName)) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_INIT_USER_POLICY);

    MessageParcel reply;
    MessageOption option;
    bool enable = ((size % CONSTANTS_NUMBER_TWO) == 0);
    if (enable) {
        GetNativeToken();
    } else {
        (void)SetSelfTokenID(g_selfTokenId);
    }
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    UpdateUserPolicy(fuzzData);
    ClearUserPolicy();

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::InitUserPolicyStubFuzzTest(data, size);
    return 0;
}
