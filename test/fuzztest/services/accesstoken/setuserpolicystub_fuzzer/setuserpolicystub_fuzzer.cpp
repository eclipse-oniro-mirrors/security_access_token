/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "setuserpolicystub_fuzzer.h"

#include <string>
#include <thread>
#include <vector>

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
void ClearUserPolicy(const string& permission)
{
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return;
    }
    if (!datas.WriteUint32(1)) {
        return;
    }
    if (!datas.WriteString(permission)) {
        return;
    }
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_CLEAR_USER_POLICY), datas, reply, option);
}

bool SetUserPolicyStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    std::string permission = ConsumePermissionName(provider);
    std::vector<std::string> permList = { permission };

    UserPermissionPolicyIdl dataBlock;
    dataBlock.permissionName = permission;
    UserPolicyIdl userPolicyIdl;
    userPolicyIdl.userId = provider.ConsumeIntegralInRange<int32_t>(-1, INT_MAX),
    userPolicyIdl.isRestricted = provider.ConsumeBool();
    dataBlock.userPolicyList.emplace_back(userPolicyIdl);

    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return false;
    }
    if (!datas.WriteUint32(1)) {
        return false;
    }
    if (UserPermissionPolicyIdlBlockMarshalling(datas, dataBlock) != ERR_NONE) {
        return false;
    }

    uint32_t code = static_cast<uint32_t>(
        IAccessTokenManagerIpcCode::COMMAND_SET_USER_POLICY);

    MessageParcel reply;
    MessageOption option;
    MockToken mock({ "ohos.permission.MANAGE_USER_POLICY" });
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, datas, reply, option);
    ClearUserPolicy(permission);
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
    OHOS::SetUserPolicyStubFuzzTest(data, size);
    return 0;
}
