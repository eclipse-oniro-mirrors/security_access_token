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
#include "accesstoken_kit.h"
#include "claw_permission_fuzzdata.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "idl_common.h"
#include "iaccess_token_manager.h"
#include "message_parcel.h"
#include "mock_permission.h"
#include "token_setproc.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
constexpr int32_t AIMGR_UID = 3092;
constexpr int32_t ROOT_UID = 0;
constexpr int32_t MAX_PID_OFFSET = 4096;
constexpr int32_t MAX_STUB_ROUND = 4;
const std::string MANAGE_TOOL_TOKENID = "ohos.permission.MANAGE_TOOL_TOKENID";
const std::string MANAGE_TOOL_RUNTIME_PERMISSIONS = "ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS";
const std::string DEFAULT_AGENT_ID = "1001";
const std::string DEFAULT_CLI_NAME = "tooltokenstub";
const std::string DEFAULT_SUB_CLI_NAME = "stubsubtool";
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

void InitializeToolTokenStubFuzz()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
}

CliInfo BuildDefaultCliInfo()
{
    CliInfo info;
    info.cliName = DEFAULT_CLI_NAME;
    info.subCliName = DEFAULT_SUB_CLI_NAME;
    return info;
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

std::string GenerateCliChallenge(AccessTokenID hostTokenId)
{
    MockToken runtimeCaller({ MANAGE_TOOL_RUNTIME_PERMISSIONS }, true, true);
    CliAuthInfo authInfo;
    authInfo.cliInfo = BuildDefaultCliInfo();
    ToolAuthResult result;
    (void)AccessTokenKit::GenerateCliAuthResult(hostTokenId, DEFAULT_AGENT_ID, { authInfo }, result);
    return result.authResults.empty() ? "" : result.authResults[0];
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

void CleanupCurrentToolToken()
{
    CallingContextGuard guard;
    SwitchToUid(AIMGR_UID);
    MockToken caller({ MANAGE_TOOL_TOKENID }, false);
    (void)AccessTokenKit::DeleteToolTokenByPid(getpid());
}

AccessTokenID InitCliTokenByKit(const CliInitInfo& initInfo)
{
    CallingContextGuard guard;
    SwitchToUid(ROOT_UID);
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    (void)AccessTokenKit::InitCliToken(initInfo, tokenIdEx, kernelPermList);
    return tokenIdEx.tokenIdExStruct.tokenID;
}

CliInitInfo BuildCliInitInfo(FuzzedDataProvider& provider, AccessTokenID hostTokenId)
{
    CliInitInfo initInfo;
    initInfo.hostTokenId = provider.ConsumeBool() ? hostTokenId : ConsumeTokenId(provider);
    initInfo.challenge = provider.ConsumeBool() ? GenerateCliChallenge(hostTokenId) : ConsumeClawString(provider);
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
    CliInitInfo cliInitInfo = BuildCliInitInfo(provider, hostTokenId);
    SendInitCliToken(cliInitInfo, ROOT_UID);
    CleanupCurrentToolToken();
    AccessTokenID cliTokenId = InitCliTokenByKit(cliInitInfo);

    SendTokenQuery(provider, static_cast<uint32_t>(IAccessTokenManagerIpcCode::COMMAND_GET_HOST_TOKEN_ID),
        ConsumeQueryTokenId(provider, hostTokenId, cliTokenId));
    SendDeleteToolTokenByPid(provider, ConsumeDeletePid(provider));
    SendDeleteToolTokenByPid(provider, getpid());
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
    MockToken hostMock({}, true, true);
    AccessTokenID hostTokenId = hostMock.GetTokenId();
    ExerciseSpecificStubCases(provider, hostTokenId);
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
