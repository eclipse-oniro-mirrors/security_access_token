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

#include "getclipermissionsstub_fuzzer.h"

#include <vector>

#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "claw_permission_fuzzdata.h"
#include "cli_info_parcel.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_service_context_helper.h"
#include "iaccess_token_manager.h"
#include "message_parcel.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
const std::string DEFAULT_AGENT_ID = "1001";
const std::string DEFAULT_CLI_NAME = "ohos-queryTime";
const std::string DEFAULT_SUB_CLI_NAME = "get-wall-time";
const std::string DEFAULT_CALLER_BUNDLE = "getclipermissionsstub.fuzzer";
const std::string MANAGE_TOOL_RUNTIME_PERMISSIONS = "ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS";
uint64_t g_callerFullTokenId = 0;

void InitializeClawPermissionStubFuzz()
{
    FuzzServiceContext::InitializeServiceCallerContext(
        g_callerFullTokenId, DEFAULT_CALLER_BUNDLE, MANAGE_TOOL_RUNTIME_PERMISSIONS);
}

bool WriteCliInfoParcelsToParcel(MessageParcel& data, FuzzedDataProvider& provider)
{
    std::vector<CliInfo> infos = ConsumeCliInfoList(provider);
    if (provider.ConsumeBool() && infos.empty()) {
        infos.push_back({ DEFAULT_CLI_NAME, DEFAULT_SUB_CLI_NAME });
    }
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

bool GetCliPermissionsStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzServiceContext::CallingContextGuard guard(g_callerFullTokenId);
    FuzzedDataProvider provider(data, size);
    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!datas.WriteUint32(provider.ConsumeBool() ?
        FuzzServiceContext::GetCallerTokenId(g_callerFullTokenId) : ConsumeTokenId(provider))) {
        return false;
    }
    std::string agentId = provider.ConsumeBool() ? DEFAULT_AGENT_ID : ConsumeAgentID(provider);
    if (!datas.WriteString(agentId)) {
        return false;
    }
    if (!WriteCliInfoParcelsToParcel(datas, provider)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_CLI_PERMISSIONS),
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
    OHOS::GetCliPermissionsStubFuzzTest(data, size);
    return 0;
}
