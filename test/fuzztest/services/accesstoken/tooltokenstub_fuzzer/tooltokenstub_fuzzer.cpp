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

#include "tooltokenstub_fuzzer.h"

#include <string>
#include <unistd.h>
#include <vector>

#include "access_token.h"
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
#include "mock_permission.h"
#ifdef SAF_AGENT_FENCE_ENABLE
#include "saf_agent_fence.h"
#endif
#include "token_setproc.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
constexpr int32_t ROOT_UID = 0;
constexpr int32_t MAX_PID_OFFSET = 4096;
constexpr int32_t MAX_STUB_ROUND = 4;
const std::string MANAGE_TOOL_TOKENID = "ohos.permission.MANAGE_TOOL_TOKENID";
const std::string MANAGE_TOOL_RUNTIME_PERMISSIONS = "ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS";
const std::string DEFAULT_AGENT_ID = "1001";
const std::string DEFAULT_CLI_NAME = "tooltokenstub";
const std::string DEFAULT_SUB_CLI_NAME = "stubsubtool";
const std::string DEFAULT_HOST_BUNDLE = "tooltokenstub.fuzzer.host";
uint64_t g_hostFullTokenId = 0;
AccessTokenID g_hostTokenId = INVALID_TOKENID;
enum class StubCommandChoice : uint8_t {
    INIT_CLI_TOKEN,
    DELETE_TOOL_TOKEN_BY_PID,
    GET_HOST_TOKEN_ID,
    END,
};

enum class QueryTokenChoice : uint8_t {
    CLI_TOKEN,
    HOST_TOKEN,
    FUZZ_TOKEN,
    END,
};

enum class CallerChoice : uint8_t {
    CURRENT_CALLER,
    PRIVILEGED_HAP_CALLER,
    UNPRIVILEGED_HAP_CALLER,
    PRIVILEGED_NATIVE_CALLER,
    UNPRIVILEGED_NATIVE_CALLER,
    END,
};

class CallingContextGuard final {
public:
    CallingContextGuard() : tokenId_(GetSelfTokenID()), uid_(getuid()) {}

    ~CallingContextGuard()
    {
        (void)setuid(uid_);
        (void)SetSelfTokenID(tokenId_);
    }

    CallingContextGuard(const CallingContextGuard&) = delete;
    CallingContextGuard& operator=(const CallingContextGuard&) = delete;

private:
    uint64_t tokenId_;
    uid_t uid_;
};

void SwitchToUid(uid_t uid)
{
    (void)setuid(uid);
}

bool WriteCommonHeader(MessageParcel& data);
void SendStubRequest(uint32_t code, MessageParcel& data);
void SendStubRequest(uint32_t code, MessageParcel& data, MessageParcel& reply);

void InitializeToolTokenStubFuzz()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
    if (g_hostFullTokenId == 0) {
        std::vector<PermissionStatus> permissionStates = {
            FuzzServiceContext::BuildPermissionStatus(MANAGE_TOOL_RUNTIME_PERMISSIONS,
                PermissionState::PERMISSION_GRANTED, PermissionFlag::PERMISSION_SYSTEM_FIXED),
            FuzzServiceContext::BuildPermissionStatus("ohos.permission.APPROXIMATELY_LOCATION",
                PermissionState::PERMISSION_GRANTED, PermissionFlag::PERMISSION_ALLOW_THIS_TIME),
            FuzzServiceContext::BuildPermissionStatus("ohos.permission.CAMERA", PermissionState::PERMISSION_GRANTED,
                PermissionFlag::PERMISSION_SYSTEM_FIXED),
            FuzzServiceContext::BuildPermissionStatus(
                "ohos.permission.LOCATION", PermissionState::PERMISSION_DENIED, PermissionFlag::PERMISSION_USER_FIXED),
        };
        FuzzServiceContext::InitializeServiceCallerContext(g_hostFullTokenId, DEFAULT_HOST_BUNDLE, permissionStates);
        g_hostTokenId = FuzzServiceContext::GetCallerTokenId(g_hostFullTokenId);
    }
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

void SetStableMockSafBehavior()
{
#ifdef SAF_AGENT_FENCE_ENABLE
    OHOS::Security::SAF::MockSafBehavior behavior;
    OHOS::Security::SAF::SetMockSafBehavior(behavior);
#endif
}

CliInfo BuildDefaultCliInfo()
{
    CliInfo info;
    info.cliName = DEFAULT_CLI_NAME;
    info.subCliName = DEFAULT_SUB_CLI_NAME;
    return info;
}

std::vector<CliAuthInfo> BuildDefaultCliAuthInfos()
{
    CliAuthInfo info;
    info.cliInfo = BuildDefaultCliInfo();
    info.permissionNames = { "ohos.permission.APPROXIMATELY_LOCATION", "ohos.permission.cli.POWER_MANAGER" };
    info.authorizationResults = { true, true };
    return { info };
}

std::string ConsumeValidOrDefault(FuzzedDataProvider& provider, const std::string& defaultValue)
{
    std::string value = ConsumeClawString(provider);
    return value.empty() ? defaultValue : value;
}

CliInfo ConsumeStubCliInfo(FuzzedDataProvider& provider)
{
    CliInfo info;
    info.cliName = ConsumeValidOrDefault(provider, DEFAULT_CLI_NAME);
    info.subCliName = provider.ConsumeBool() ? ConsumeClawString(provider) : DEFAULT_SUB_CLI_NAME;
    return info;
}

bool ReadReplyErrCode(MessageParcel& reply, int32_t& errCode)
{
    errCode = reply.ReadInt32();
    return true;
}

bool GenerateCliChallengeByStub(AccessTokenID hostTokenId, std::string& challenge)
{
    CallingContextGuard guard;
    MockToken caller({ MANAGE_TOOL_RUNTIME_PERMISSIONS }, true, true);
    MessageParcel data;
    if (!WriteCommonHeader(data) || !data.WriteUint32(hostTokenId) || !data.WriteString(DEFAULT_AGENT_ID)) {
        return false;
    }
    const auto authInfos = BuildDefaultCliAuthInfos();
    if (!data.WriteInt32(static_cast<int32_t>(authInfos.size()))) {
        return false;
    }
    for (const auto& info : authInfos) {
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
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GENERATE_CLI_AUTH_RESULT), data, reply, option);
    int32_t errCode = RET_FAILED;
    if (!ReadReplyErrCode(reply, errCode) || errCode != RET_SUCCESS) {
        return false;
    }
    std::vector<std::string> authResults;
    if (!reply.ReadStringVector(&authResults) || authResults.empty()) {
        return false;
    }
    challenge = authResults[0];
    return true;
}

bool WriteCommonHeader(MessageParcel& data)
{
    return data.WriteInterfaceToken(IAccessTokenManager::GetDescriptor());
}

void SendStubRequest(uint32_t code, MessageParcel& data)
{
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, data, reply, option);
}

void SendStubRequest(uint32_t code, MessageParcel& data, MessageParcel& reply)
{
    MessageOption option;
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->OnRemoteRequest(code, data, reply, option);
}

void SendStubRequestWithCaller(FuzzedDataProvider& provider, uint32_t code, MessageParcel& data)
{
    auto choice = static_cast<CallerChoice>(provider.ConsumeIntegralInRange<uint8_t>(
        0, static_cast<uint8_t>(CallerChoice::END) - 1));
    CallingContextGuard guard;
    switch (choice) {
        case CallerChoice::CURRENT_CALLER:
            SendStubRequest(code, data);
            break;
        case CallerChoice::PRIVILEGED_HAP_CALLER: {
            MockToken caller({ MANAGE_TOOL_RUNTIME_PERMISSIONS, MANAGE_TOOL_TOKENID }, true, true);
            SendStubRequest(code, data);
            break;
        }
        case CallerChoice::UNPRIVILEGED_HAP_CALLER: {
            MockToken caller({}, true, false);
            SendStubRequest(code, data);
            break;
        }
        case CallerChoice::PRIVILEGED_NATIVE_CALLER: {
            MockToken caller({ MANAGE_TOOL_TOKENID }, false);
            SendStubRequest(code, data);
            break;
        }
        case CallerChoice::UNPRIVILEGED_NATIVE_CALLER: {
            MockToken caller({}, false);
            SendStubRequest(code, data);
            break;
        }
        default:
            break;
    }
}

void SendInitCliToken(const CliInitInfo& initInfo, uid_t uid)
{
    CallingContextGuard guard;
    SwitchToUid(uid);
    MessageParcel data;
    if (!WriteCommonHeader(data)) {
        return;
    }
    CliInitInfoIdl initInfoIdl = {
        .hostTokenId = initInfo.hostTokenId,
        .challenge = initInfo.challenge,
        .cliInfo = {
            .cliName = initInfo.cliInfo.cliName,
            .subCliName = initInfo.cliInfo.subCliName,
        },
    };
    if (CliInitInfoIdlBlockMarshalling(data, initInfoIdl) != ERR_NONE) {
        return;
    }
    SendStubRequest(static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_INIT_CLI_TOKEN), data);
}

void CleanupCurrentToolTokenByStub()
{
    CallingContextGuard guard;
    MockToken caller({ MANAGE_TOOL_TOKENID }, false);
    MessageParcel data;
    if (!WriteCommonHeader(data) || !data.WriteInt32(getpid())) {
        return;
    }
    SendStubRequest(static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_DELETE_TOOL_TOKEN_BY_PID), data);
}

CliInitInfo BuildCliInitInfo(FuzzedDataProvider& provider, AccessTokenID hostTokenId)
{
    CliInitInfo initInfo;
    initInfo.hostTokenId = provider.ConsumeBool() ? hostTokenId : ConsumeTokenId(provider);
    if (provider.ConsumeBool()) {
        std::string challenge;
        initInfo.challenge = GenerateCliChallengeByStub(hostTokenId, challenge) ? challenge : "";
    } else if (provider.ConsumeBool()) {
        initInfo.challenge = "";
    } else {
        initInfo.challenge = ConsumeClawString(provider);
    }
    initInfo.cliInfo = provider.ConsumeBool() ? BuildDefaultCliInfo() : ConsumeStubCliInfo(provider);
    return initInfo;
}

AccessTokenID ConsumeQueryTokenId(
    FuzzedDataProvider& provider, AccessTokenID hostTokenId, AccessTokenID cliTokenId)
{
    auto choice = static_cast<QueryTokenChoice>(provider.ConsumeIntegralInRange<uint8_t>(
        0, static_cast<uint8_t>(QueryTokenChoice::END) - 1));
    switch (choice) {
        case QueryTokenChoice::CLI_TOKEN:
            return cliTokenId;
        case QueryTokenChoice::HOST_TOKEN:
            return hostTokenId;
        case QueryTokenChoice::FUZZ_TOKEN:
            return ConsumeTokenId(provider);
        default:
            return INVALID_TOKENID;
    }
}

AccessTokenID SendInitCliTokenAndReadTokenId(const CliInitInfo& initInfo, uid_t uid)
{
    CallingContextGuard guard;
    SwitchToUid(uid);
    MessageParcel data;
    if (!WriteCommonHeader(data)) {
        return INVALID_TOKENID;
    }
    CliInitInfoIdl initInfoIdl = {
        .hostTokenId = initInfo.hostTokenId,
        .challenge = initInfo.challenge,
        .cliInfo = {
            .cliName = initInfo.cliInfo.cliName,
            .subCliName = initInfo.cliInfo.subCliName,
        },
    };
    if (CliInitInfoIdlBlockMarshalling(data, initInfoIdl) != ERR_NONE) {
        return INVALID_TOKENID;
    }
    MessageParcel reply;
    SendStubRequest(static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_INIT_CLI_TOKEN), data, reply);
    int32_t errCode = RET_FAILED;
    if (!ReadReplyErrCode(reply, errCode) || errCode != RET_SUCCESS) {
        return INVALID_TOKENID;
    }
    uint64_t fullTokenId = reply.ReadUint64();
    AccessTokenIDEx tokenIdEx = { .tokenIDEx = fullTokenId };
    return tokenIdEx.tokenIdExStruct.tokenID;
}

int32_t ConsumeDeletePid(FuzzedDataProvider& provider)
{
    int32_t inputPid = provider.ConsumeIntegral<int32_t>();
    if (!provider.ConsumeBool()) {
        return inputPid;
    }
    return getpid() + provider.ConsumeIntegralInRange<int32_t>(-MAX_PID_OFFSET, MAX_PID_OFFSET);
}

void SendTokenQuery(FuzzedDataProvider& provider, uint32_t code, AccessTokenID tokenId)
{
    MessageParcel data;
    if (!WriteCommonHeader(data) || !data.WriteUint32(tokenId)) {
        return;
    }
    SendStubRequestWithCaller(provider, code, data);
}

void SendDeleteToolTokenByPid(FuzzedDataProvider& provider, int32_t pid)
{
    MessageParcel data;
    if (!WriteCommonHeader(data) || !data.WriteInt32(pid)) {
        return;
    }
    SendStubRequestWithCaller(
        provider, static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_DELETE_TOOL_TOKEN_BY_PID), data);
}

void ExerciseSpecificStubCases(FuzzedDataProvider& provider, AccessTokenID hostTokenId)
{
    SetStableMockSafBehavior();
    CliInitInfo cliInitInfo;
    cliInitInfo.hostTokenId = hostTokenId;
    std::string challenge;
    cliInitInfo.challenge = GenerateCliChallengeByStub(hostTokenId, challenge) ? challenge : "";
    cliInitInfo.cliInfo = BuildDefaultCliInfo();
    SendInitCliToken(cliInitInfo, ROOT_UID);
    CleanupCurrentToolTokenByStub();
    AccessTokenID cliTokenId = SendInitCliTokenAndReadTokenId(cliInitInfo, ROOT_UID);

    SendTokenQuery(provider, static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_HOST_TOKEN_ID),
        ConsumeQueryTokenId(provider, hostTokenId, cliTokenId));
    SendTokenQuery(provider, static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_HOST_TOKEN_ID), cliTokenId);
    if (provider.ConsumeBool()) {
        SendInitCliToken(cliInitInfo, ROOT_UID);
    }
    if (provider.ConsumeBool()) {
        (void)SendInitCliTokenAndReadTokenId(cliInitInfo, ROOT_UID);
    }
    SendDeleteToolTokenByPid(provider, ConsumeDeletePid(provider));
    SendDeleteToolTokenByPid(provider, getpid());
    SendTokenQuery(provider, static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_HOST_TOKEN_ID), cliTokenId);
    if (provider.ConsumeBool()) {
        SendDeleteToolTokenByPid(provider, getpid());
    }
}

void ExerciseConsumedStubCase(FuzzedDataProvider& provider, AccessTokenID hostTokenId)
{
    auto choice = static_cast<StubCommandChoice>(provider.ConsumeIntegralInRange<uint8_t>(
        0, static_cast<uint8_t>(StubCommandChoice::END) - 1));
    switch (choice) {
        case StubCommandChoice::INIT_CLI_TOKEN:
            SendInitCliToken(BuildCliInitInfo(provider, hostTokenId), provider.ConsumeBool() ? ROOT_UID : getuid());
            break;
        case StubCommandChoice::DELETE_TOOL_TOKEN_BY_PID:
            SendDeleteToolTokenByPid(provider, ConsumeDeletePid(provider));
            break;
        case StubCommandChoice::GET_HOST_TOKEN_ID:
            SendTokenQuery(provider, static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_HOST_TOKEN_ID),
                ConsumeTokenId(provider));
            break;
        default:
            break;
    }
}
}

bool ToolTokenStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    AccessTokenID hostTokenId = provider.ConsumeBool() ? g_hostTokenId : ConsumeTokenId(provider);
    ExerciseSpecificStubCases(provider, hostTokenId);
    ConfigureMockSafBehavior(provider);
    int32_t rounds = provider.ConsumeIntegralInRange<int32_t>(1, MAX_STUB_ROUND);
    for (int32_t i = 0; i < rounds; ++i) {
        ExerciseConsumedStubCase(provider, hostTokenId);
    }
    return true;
}
}

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    OHOS::InitializeToolTokenStubFuzz();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::ToolTokenStubFuzzTest(data, size);
    return 0;
}
