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

#include "startremoteusingpermissionstub_fuzzer.h"

#include "accesstoken_fuzzdata.h"
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
void StartRemoteUsingPermissionStub(const std::string& remoteDeviceId, const std::string& remoteDeviceName,
    const std::string& permissionName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        return;
    }

    RemotePermissionUsedInfo usedInfo;
    usedInfo.remoteDeviceId = remoteDeviceId;
    usedInfo.remoteDeviceName = remoteDeviceName;
    usedInfo.permissionName = permissionName;

    RemotePermissionUsedInfoParcel parcel;
    parcel.info = usedInfo;

    auto anonyStub = sptr<ProxyDeathCallBackStub>::MakeSptr();
    if (!data.WriteParcelable(&parcel)) {
        return;
    }
    if (!data.WriteRemoteObject(anonyStub)) {
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_START_REMOTE_USING_PERMISSION), data, reply, option);
}

void StopRemoteUsingPermissionStub(const std::string& remoteDeviceId, const std::string& remoteDeviceName,
    const std::string& permissionName)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(IPrivacyManager::GetDescriptor())) {
        return;
    }
    if (!datas.WriteString(remoteDeviceId)) {
        return;
    }
    if (!datas.WriteString(remoteDeviceName)) {
        return;
    }
    if (!datas.WriteString(permissionName)) {
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    DelayedSingleton<PrivacyManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IPrivacyManagerIpcCode::COMMAND_STOP_REMOTE_USING_PERMISSION), datas, reply, option);
}

bool StartRemoteUsingPermissionStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    std::string permissionName;
    int32_t opCode = provider.ConsumeIntegral<int32_t>() % g_permSize;
    (void)Constant::TransferOpcodeToPermission(opCode, permissionName);

    std::string remoteDeviceId = provider.ConsumeRandomLengthString();
    std::string remoteDeviceName = provider.ConsumeRandomLengthString();

    StartRemoteUsingPermissionStub(remoteDeviceId, remoteDeviceName, permissionName);
    StopRemoteUsingPermissionStub(remoteDeviceId, remoteDeviceName, permissionName);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::StartRemoteUsingPermissionStubFuzzTest(data, size);
    return 0;
}
