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

#include "claw_permission_fuzzdata.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_service_context_helper.h"
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "iaccess_token_manager.h"
#include "message_parcel.h"
#ifdef SAF_AGENT_FENCE_ENABLE
#include "saf_agent_fence.h"
#endif

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
const std::string DEFAULT_AGENT_ID = "1001";
const std::string DEFAULT_CALLER_BUNDLE = "getclipermissionrequestinfo.fuzzer";
const std::string QUERY_TOOL_PERMISSIONS = "ohos.permission.QUERY_TOOL_PERMISSIONS";
uint64_t g_callerFullTokenId = 0;

std::vector<PermissionStatus> BuildDefaultPermissionStates()
{
    return {
        FuzzServiceContext::BuildPermissionStatus(
            QUERY_TOOL_PERMISSIONS, PermissionState::PERMISSION_GRANTED, PermissionFlag::PERMISSION_SYSTEM_FIXED),
        FuzzServiceContext::BuildPermissionStatus("ohos.permission.APPROXIMATELY_LOCATION",
            PermissionState::PERMISSION_GRANTED, PermissionFlag::PERMISSION_ALLOW_THIS_TIME),
        FuzzServiceContext::BuildPermissionStatus(
            "ohos.permission.CAMERA", PermissionState::PERMISSION_GRANTED, PermissionFlag::PERMISSION_SYSTEM_FIXED),
        FuzzServiceContext::BuildPermissionStatus(
            "ohos.permission.LOCATION", PermissionState::PERMISSION_DENIED, PermissionFlag::PERMISSION_USER_FIXED),
    };
}

void InitializeClawPermissionStubFuzz()
{
    FuzzServiceContext::InitializeServiceCallerContext(
        g_callerFullTokenId, DEFAULT_CALLER_BUNDLE, BuildDefaultPermissionStates());
}

void ConfigureMockSafBehavior(FuzzedDataProvider& provider)
{
#ifdef SAF_AGENT_FENCE_ENABLE
    OHOS::Security::SAF::MockSafBehavior behavior;
    behavior.queryMode = static_cast<OHOS::Security::SAF::MockQueryMode>(provider.ConsumeIntegralInRange<uint8_t>(
        0, static_cast<uint8_t>(OHOS::Security::SAF::MockQueryMode::DUPLICATE_PERMISSIONS)));
    behavior.generateMode = OHOS::Security::SAF::MockGenerateMode::NORMAL;
    behavior.verifyMode = OHOS::Security::SAF::MockVerifyMode::NORMAL;
    OHOS::Security::SAF::SetMockSafBehavior(behavior);
#else
    (void)provider;
#endif
}

bool WriteCliInfoIdlsToParcel(MessageParcel& data, FuzzedDataProvider& provider)
{
    std::vector<CliInfo> infos = ConsumeCliInfoList(provider);
    if (provider.ConsumeBool() || infos.empty()) {
        AppendKnownCliInfos(provider, infos);
    }
    if (!data.WriteInt32(static_cast<int32_t>(infos.size()))) {
        return false;
    }
    for (const auto& info : infos) {
        CliInfoIdl infoIdl = {
            .cliName = info.cliName,
            .subCliName = info.subCliName,
        };
        if (CliInfoIdlBlockMarshalling(data, infoIdl) != ERR_NONE) {
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

    FuzzServiceContext::CallingContextGuard guard(g_callerFullTokenId);
    FuzzedDataProvider provider(data, size);
    ConfigureMockSafBehavior(provider);
    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    std::string agentId = provider.ConsumeBool() ? DEFAULT_AGENT_ID : ConsumeAgentID(provider);
    if (!datas.WriteString(agentId)) {
        return false;
    }
    if (!WriteCliInfoIdlsToParcel(datas, provider)) {
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
