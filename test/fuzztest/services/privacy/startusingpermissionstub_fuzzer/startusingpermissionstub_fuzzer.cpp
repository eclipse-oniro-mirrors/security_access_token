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

#include "startusingpermissionstub_fuzzer.h"

#include "constant.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iprivacy_manager.h"
#include "permission_used_type.h"
#include "privacy_manager_service.h"
#include "proxy_death_callback_stub.h"

using namespace std;
using namespace OHOS::Security::AccessToken;
static int32_t g_permSize = static_cast<int32_t>(Constant::PERMISSION_OPCODE_MAP.size());

namespace OHOS {
void StartUsingPermissionStub(AccessTokenID tokenID, int32_t pid, const std::string& permissionName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        return;
    }

    PermissionUsedTypeInfoParcel infoParcel;
    infoParcel.info.tokenId = tokenID;
    infoParcel.info.pid = pid;
    infoParcel.info.permissionName = permissionName;
    infoParcel.info.type = NORMAL_TYPE;

    auto anonyStub = sptr<ProxyDeathCallBackStub>::MakeSptr();
    if (!data.WriteParcelable(&infoParcel)) {
        return;
    }
    if (!data.WriteRemoteObject(anonyStub)) {
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_START_USING_PERMISSION), data, reply, option);
}

void StopUsingPermissionStub(AccessTokenID tokenID, int32_t pid, const std::string& permissionName)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        return;
    }
    if (!datas.WriteUint32(tokenID)) {
        return;
    }
    if (!datas.WriteInt32(pid)) {
        return;
    }
    if (!datas.WriteString(permissionName)) {
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_STOP_USING_PERMISSION), datas, reply, option);
}

bool StartUsingPermissionStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    AccessTokenID tokenID = provider.ConsumeIntegral<AccessTokenID>();
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    std::string permissionName;
    int32_t opCode = provider.ConsumeIntegral<int32_t>() % g_permSize;
    Constant::TransferOpcodeToPermission(opCode, permissionName);

    StartUsingPermissionStub(tokenID, pid, permissionName);
    StopUsingPermissionStub(tokenID, pid, permissionName);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::StartUsingPermissionStubFuzzTest(data, size);
    return 0;
}
