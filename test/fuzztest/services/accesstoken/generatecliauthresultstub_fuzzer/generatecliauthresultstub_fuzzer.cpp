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
#define private public
#include "accesstoken_manager_service.h"
#undef private
#include "claw_permission_fuzzdata.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "fuzz_service_context_helper.h"
#include "idl_common.h"
#include "iaccess_token_manager.h"
#include "message_parcel.h"
#ifdef SAF_AGENT_FENCE_ENABLE
#include "saf_agent_fence.h"
#endif

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
const std::string DEFAULT_AGENT_ID = "1001";
const std::string DEFAULT_CALLER_BUNDLE = "generatecliauthresultstub.fuzzer";
const std::string DEFAULT_HOST_BUNDLE = "generatecliauthresultstub.host";
const std::string MANAGE_TOOL_RUNTIME_PERMISSIONS = "ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS";
uint64_t g_callerFullTokenId = 0;
uint64_t g_hostFullTokenId = 0;
AccessTokenID g_hostTokenId = INVALID_TOKENID;
const std::string DEFAULT_CLI_NAME = "tooltokenstub";
const std::string DEFAULT_SUB_CLI_NAME = "stubsubtool";

std::vector<PermissionStatus> BuildDefaultPermissionStates(const std::string& controlPermission)
{
    return {
        FuzzServiceContext::BuildPermissionStatus(
            controlPermission, PermissionState::PERMISSION_GRANTED, PermissionFlag::PERMISSION_SYSTEM_FIXED),
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
        g_callerFullTokenId, DEFAULT_CALLER_BUNDLE, BuildDefaultPermissionStates(MANAGE_TOOL_RUNTIME_PERMISSIONS));
    FuzzServiceContext::InitializeServiceCallerContext(
        g_hostFullTokenId, DEFAULT_HOST_BUNDLE, BuildDefaultPermissionStates(MANAGE_TOOL_RUNTIME_PERMISSIONS));
    g_hostTokenId = FuzzServiceContext::GetCallerTokenId(g_hostFullTokenId);
}

void ConfigureMockSafBehavior(FuzzedDataProvider& provider)
{
#ifdef SAF_AGENT_FENCE_ENABLE
    OHOS::Security::SAF::MockSafBehavior behavior;
    behavior.queryMode = static_cast<OHOS::Security::SAF::MockQueryMode>(provider.ConsumeIntegralInRange<uint8_t>(
        0, static_cast<uint8_t>(OHOS::Security::SAF::MockQueryMode::DUPLICATE_PERMISSIONS)));
    behavior.generateMode = static_cast<OHOS::Security::SAF::MockGenerateMode>(
        provider.ConsumeIntegralInRange<uint8_t>(
            0, static_cast<uint8_t>(OHOS::Security::SAF::MockGenerateMode::EMPTY_CHALLENGE)));
    behavior.verifyMode = static_cast<OHOS::Security::SAF::MockVerifyMode>(
        provider.ConsumeIntegralInRange<uint8_t>(
            0, static_cast<uint8_t>(OHOS::Security::SAF::MockVerifyMode::EMPTY_PERMISSION_LIST)));
    OHOS::Security::SAF::SetMockSafBehavior(behavior);
#else
    (void)provider;
#endif
}

bool ReadReplyErrCode(MessageParcel& reply, int32_t& errCode)
{
    errCode = reply.ReadInt32();
    return true;
}

bool WriteInitCliTokenToParcel(MessageParcel& data, AccessTokenID hostTokenId, const std::string& challenge)
{
    if (!data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor())) {
        return false;
    }
    CliInitInfoIdl initInfoIdl = {
        .hostTokenId = hostTokenId,
        .challenge = challenge,
        .cliInfo = {
            .cliName = DEFAULT_CLI_NAME,
            .subCliName = DEFAULT_SUB_CLI_NAME,
        },
    };
    return CliInitInfoIdlBlockMarshalling(data, initInfoIdl) == ERR_NONE;
}

void ExerciseInitCliTokenByStub(AccessTokenID hostTokenId, const std::string& challenge)
{
    if (challenge.empty()) {
        return;
    }
    MessageParcel data;
    if (!WriteInitCliTokenToParcel(data, hostTokenId, challenge)) {
        return;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_INIT_CLI_TOKEN), data, reply, option);
}

bool WriteCliAuthInfosToParcel(MessageParcel& data, FuzzedDataProvider& provider)
{
    std::vector<CliAuthInfo> infos = ConsumeCliAuthInfoList(provider);
    if (provider.ConsumeBool() || infos.empty()) {
        AppendKnownCliAuthInfos(provider, infos);
    }
    if (!data.WriteInt32(static_cast<int32_t>(infos.size()))) {
        return false;
    }
    for (const auto& info : infos) {
        CliAuthInfoIdl infoIdl;
        infoIdl.cliInfo = {
            .cliName = info.cliInfo.cliName,
            .subCliName = info.cliInfo.subCliName,
        };
        infoIdl.permissionNames = info.permissionNames;
        infoIdl.authorizationResults.assign(info.authorizationResults.begin(), info.authorizationResults.end());
        if (CliAuthInfoIdlBlockMarshalling(data, infoIdl) != ERR_NONE) {
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

    FuzzServiceContext::CallingContextGuard guard(g_callerFullTokenId);
    FuzzedDataProvider provider(data, size);
    ConfigureMockSafBehavior(provider);
    MessageParcel datas;
    datas.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
    if (!datas.WriteUint32(provider.ConsumeBool() ?
        g_hostTokenId : ConsumeTokenId(provider))) {
        return false;
    }
    std::string agentId = provider.ConsumeBool() ? DEFAULT_AGENT_ID : ConsumeAgentID(provider);
    if (!datas.WriteString(agentId)) {
        return false;
    }
    if (!WriteCliAuthInfosToParcel(datas, provider)) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GENERATE_CLI_AUTH_RESULT),
        datas, reply, option);
    int32_t errCode = RET_FAILED;
    if (!ReadReplyErrCode(reply, errCode) || errCode != RET_SUCCESS) {
        return false;
    }
    std::vector<std::string> authResults;
    if (!reply.ReadStringVector(&authResults)) {
        return false;
    }
    if (provider.ConsumeBool() && !authResults.empty()) {
        ExerciseInitCliTokenByStub(g_hostTokenId, authResults[0]);
    }
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
