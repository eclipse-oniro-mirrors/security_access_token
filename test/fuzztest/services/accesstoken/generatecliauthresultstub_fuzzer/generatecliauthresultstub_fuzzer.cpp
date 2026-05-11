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

#include "generatecliauthresultstub_fuzzer.h"

#include <vector>

#include "accesstoken_fuzzdata.h"
#include "access_token.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "accesstoken_kit.h"
#include "claw_auth_info_parcel.h"
#include "claw_permission_fuzzdata.h"
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
    g_mockToken.reset(new MockToken({ "ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS" }, true, true));
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
}

bool WriteCliAuthInfoParcelsToParcel(MessageParcel& data, FuzzedDataProvider& provider)
{
    std::vector<CliAuthInfo> infos = ConsumeCliAuthInfoList(provider);
    if (!data.WriteInt32(static_cast<int32_t>(infos.size()))) {
        return false;
    }
    for (const auto& info : infos) {
        CliAuthInfoParcel parcel;
        parcel.info = info;
        if (!data.WriteParcelable(&parcel)) {
            return false;
        }
    }
    return true;
}
}

bool GenerateCliAuthResultStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!datas.WriteUint32(ConsumeTokenId(provider))) {
        return false;
    }
    if (!datas.WriteString(ConsumeAgentID(provider))) {
        return false;
    }
    if (!WriteCliAuthInfoParcelsToParcel(datas, provider)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GENERATE_CLI_AUTH_RESULT),
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
    OHOS::GenerateCliAuthResultStubFuzzTest(data, size);
    return 0;
}
