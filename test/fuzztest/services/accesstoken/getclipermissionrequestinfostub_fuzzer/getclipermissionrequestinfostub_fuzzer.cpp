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

#include "getclipermissionrequestinfostub_fuzzer.h"

#include <new>
#include <vector>

#include "access_token.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "accesstoken_kit.h"
#include "claw_permission_fuzzdata.h"
#include "cli_info_parcel.h"
#include "mock_permission.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "message_parcel.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
std::unique_ptr<MockToken> g_mockToken;

void InitializeClawPermissionStubFuzz()
{
    g_mockToken.reset(new MockToken({ "ohos.permission.QUERY_TOOL_PERMISSIONS" }, true, true));
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
}

bool WriteCliInfoParcelsToParcel(MessageParcel& data, FuzzedDataProvider& provider)
{
    std::vector<CliInfo> infos = ConsumeCliInfoList(provider);
    if (!data.WriteInt32(static_cast<int32_t>(infos.size()))) {
        return false;
    }
    for (const auto& info : infos) {
        CliInfoParcel parcel;
        parcel.cliInfo = info;
        if (!data.WriteParcelable(&parcel)) {
            return false;
        }
    }
    return true;
}
}

bool GetCliPermissionRequestInfoStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!datas.WriteString(ConsumeAgentID(provider))) {
        return false;
    }
    if (!WriteCliInfoParcelsToParcel(datas, provider)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_CLI_PERMISSION_REQUEST_INFO),
        datas, reply, option);
    return true;
}
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    OHOS::InitializeClawPermissionStubFuzz();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::GetCliPermissionRequestInfoStubFuzzTest(data, size);
    return 0;
}
