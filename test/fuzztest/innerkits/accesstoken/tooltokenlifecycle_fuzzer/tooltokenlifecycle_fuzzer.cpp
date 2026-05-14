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

#include "tooltokenlifecycle_fuzzer.h"

#include <string>
#include <unistd.h>
#include <vector>

#include "access_token_error.h"
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "claw_permission_fuzzdata.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "mock_permission.h"
#include "token_setproc.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
constexpr int32_t AIMGR_UID = 3092;
constexpr int32_t ROOT_UID = 0;
constexpr int32_t MAX_PID_OFFSET = 4096;
constexpr int32_t MAX_DELETE_ROUND = 4;
const std::string MANAGE_TOOL_TOKENID = "ohos.permission.MANAGE_TOOL_TOKENID";
const std::string MANAGE_TOOL_RUNTIME_PERMISSIONS = "ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS";
const std::string DEFAULT_AGENT_ID = "1001";
const std::string DEFAULT_CLI_NAME = "tooltoken";
const std::string DEFAULT_SUB_CLI_NAME = "subtool";
const std::string DEFAULT_BUNDLE_NAME = "com.ohos.tooltoken";
const std::string DEFAULT_MODULE_NAME = "entry";
const std::string DEFAULT_SKILL_NAME = "defaultSkill";

enum class QueryTokenChoice : uint8_t {
    TOOL_TOKEN,
    HOST_TOKEN,
    FUZZ_TOKEN,
    END,
};

enum class UidChoice : uint8_t {
    ROOT,
    AIMGR,
    SELF,
    FUZZ_UID,
    END,
};

enum class CallerChoice : uint8_t {
    CURRENT_CALLER,
    HAP_CALLER,
    NATIVE_CALLER,
    PRIVILEGED_NATIVE_CALLER,
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

CliInfo BuildDefaultCliInfo();
SkillInfo BuildDefaultSkillInfo();
std::vector<CliAuthInfo> BuildDefaultCliAuthInfos();
std::vector<SkillAuthInfo> BuildDefaultSkillAuthInfos();
std::vector<std::string> ConsumeDeletePermissions(FuzzedDataProvider& provider);
std::vector<std::string> ConsumePermissionList(FuzzedDataProvider& provider, const std::string& permissionName);

std::string ConsumeValidOrDefault(FuzzedDataProvider& provider, const std::string& defaultValue)
{
    std::string value = ConsumeClawString(provider);
    return value.empty() ? defaultValue : value;
}

CliInfo ConsumeLifecycleCliInfo(FuzzedDataProvider& provider)
{
    CliInfo info;
    info.cliName = ConsumeValidOrDefault(provider, DEFAULT_CLI_NAME);
    info.subCliName = provider.ConsumeBool() ? ConsumeClawString(provider) : DEFAULT_SUB_CLI_NAME;
    return info;
}

SkillInfo ConsumeLifecycleSkillInfo(FuzzedDataProvider& provider)
{
    SkillInfo info;
    info.bundleName = ConsumeValidOrDefault(provider, DEFAULT_BUNDLE_NAME);
    info.moduleName = ConsumeValidOrDefault(provider, DEFAULT_MODULE_NAME);
    info.skillName = ConsumeValidOrDefault(provider, DEFAULT_SKILL_NAME);
    return info;
}

std::string ConsumeAgentId(FuzzedDataProvider& provider)
{
    if (provider.ConsumeBool()) {
        return DEFAULT_AGENT_ID;
    }
    return ConsumeClawString(provider);
}

AccessTokenID ConsumeHostTokenId(FuzzedDataProvider& provider, AccessTokenID hostTokenId)
{
    return provider.ConsumeBool() ? hostTokenId : ConsumeTokenId(provider);
}

AccessTokenID ConsumeQueryTokenId(FuzzedDataProvider& provider, AccessTokenID toolTokenId, AccessTokenID hostTokenId)
{
    auto choice = static_cast<QueryTokenChoice>(provider.ConsumeIntegralInRange<uint8_t>(
        0, static_cast<uint8_t>(QueryTokenChoice::END) - 1));
    switch (choice) {
        case QueryTokenChoice::TOOL_TOKEN:
            return toolTokenId;
        case QueryTokenChoice::HOST_TOKEN:
            return hostTokenId;
        case QueryTokenChoice::FUZZ_TOKEN:
            return ConsumeTokenId(provider);
        default:
            return INVALID_TOKENID;
    }
}

CliInfo BuildDefaultCliInfo()
{
    CliInfo info;
    info.cliName = DEFAULT_CLI_NAME;
    info.subCliName = DEFAULT_SUB_CLI_NAME;
    return info;
}

SkillInfo BuildDefaultSkillInfo()
{
    SkillInfo info;
    info.skillName = DEFAULT_SKILL_NAME;
    info.bundleName = DEFAULT_BUNDLE_NAME;
    info.moduleName = DEFAULT_MODULE_NAME;
    return info;
}

std::vector<CliAuthInfo> BuildDefaultCliAuthInfos()
{
    CliAuthInfo authInfo;
    authInfo.cliInfo = BuildDefaultCliInfo();
    return { authInfo };
}

std::vector<SkillAuthInfo> BuildDefaultSkillAuthInfos()
{
    SkillAuthInfo authInfo;
    authInfo.skillInfo = BuildDefaultSkillInfo();
    return { authInfo };
}

std::string GenerateCliChallenge(AccessTokenID hostTokenId)
{
    MockToken runtimeCaller({ MANAGE_TOOL_RUNTIME_PERMISSIONS }, true, true);
    ToolAuthResult result;
    (void)AccessTokenKit::GenerateCliAuthResult(hostTokenId, DEFAULT_AGENT_ID, BuildDefaultCliAuthInfos(), result);
    if (result.authResults.empty()) {
        return "";
    }
    return result.authResults[0];
}

std::string GenerateSkillChallenge(AccessTokenID hostTokenId)
{
    MockToken runtimeCaller({ MANAGE_TOOL_RUNTIME_PERMISSIONS }, true, true);
    ToolAuthResult result;
    (void)AccessTokenKit::GenerateSkillAuthResult(hostTokenId, DEFAULT_AGENT_ID, BuildDefaultSkillAuthInfos(), result);
    if (result.authResults.empty()) {
        return "";
    }
    return result.authResults[0];
}

void ExerciseAuthResultApi(FuzzedDataProvider& provider, AccessTokenID hostTokenId)
{
    ToolAuthResult result;
    (void)AccessTokenKit::GenerateCliAuthResult(
        ConsumeHostTokenId(provider, hostTokenId), ConsumeAgentId(provider), ConsumeCliAuthInfoList(provider), result);
    {
        MockToken caller(
            ConsumePermissionList(provider, MANAGE_TOOL_RUNTIME_PERMISSIONS), true, provider.ConsumeBool());
        (void)AccessTokenKit::GenerateCliAuthResult(ConsumeHostTokenId(provider, hostTokenId),
            ConsumeAgentId(provider), ConsumeCliAuthInfoList(provider), result);
    }
    {
        MockToken runtimeCaller({ MANAGE_TOOL_RUNTIME_PERMISSIONS }, true, true);
        (void)AccessTokenKit::GenerateCliAuthResult(hostTokenId, DEFAULT_AGENT_ID, BuildDefaultCliAuthInfos(), result);
        (void)AccessTokenKit::GenerateCliAuthResult(ConsumeHostTokenId(provider, hostTokenId),
            ConsumeAgentId(provider), ConsumeCliAuthInfoList(provider), result);
    }

    (void)AccessTokenKit::GenerateSkillAuthResult(ConsumeHostTokenId(provider, hostTokenId),
        ConsumeAgentId(provider), ConsumeSkillAuthInfoList(provider), result);
    {
        MockToken caller(
            ConsumePermissionList(provider, MANAGE_TOOL_RUNTIME_PERMISSIONS), true, provider.ConsumeBool());
        (void)AccessTokenKit::GenerateSkillAuthResult(ConsumeHostTokenId(provider, hostTokenId),
            ConsumeAgentId(provider), ConsumeSkillAuthInfoList(provider), result);
    }
    {
        MockToken runtimeCaller({ MANAGE_TOOL_RUNTIME_PERMISSIONS }, true, true);
        (void)AccessTokenKit::GenerateSkillAuthResult(
            hostTokenId, DEFAULT_AGENT_ID, BuildDefaultSkillAuthInfos(), result);
        (void)AccessTokenKit::GenerateSkillAuthResult(ConsumeHostTokenId(provider, hostTokenId),
            ConsumeAgentId(provider), ConsumeSkillAuthInfoList(provider), result);
    }
}

AccessTokenID TryInitCliToken(const CliInitInfo& initInfo)
{
    CallingContextGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    SwitchToUid(ROOT_UID);
    (void)AccessTokenKit::InitCliToken(initInfo, tokenIdEx, kernelPermList);
    return tokenIdEx.tokenIdExStruct.tokenID;
}

AccessTokenID TryInitCliTokenWithUid(const CliInitInfo& initInfo, uid_t uid)
{
    CallingContextGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    SwitchToUid(uid);
    (void)AccessTokenKit::InitCliToken(initInfo, tokenIdEx, kernelPermList);
    return tokenIdEx.tokenIdExStruct.tokenID;
}

AccessTokenID TryInitSkillToken(const SkillInitInfo& initInfo)
{
    CallingContextGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    SwitchToUid(AIMGR_UID);
    (void)AccessTokenKit::InitSkillToken(initInfo, tokenIdEx, kernelPermList);
    return tokenIdEx.tokenIdExStruct.tokenID;
}

AccessTokenID TryInitSkillTokenWithUid(const SkillInitInfo& initInfo, uid_t uid)
{
    CallingContextGuard guard;
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    SwitchToUid(uid);
    (void)AccessTokenKit::InitSkillToken(initInfo, tokenIdEx, kernelPermList);
    return tokenIdEx.tokenIdExStruct.tokenID;
}

uid_t ConsumeUid(FuzzedDataProvider& provider)
{
    auto choice = static_cast<UidChoice>(provider.ConsumeIntegralInRange<uint8_t>(
        0, static_cast<uint8_t>(UidChoice::END) - 1));
    switch (choice) {
        case UidChoice::ROOT:
            return ROOT_UID;
        case UidChoice::AIMGR:
            return AIMGR_UID;
        case UidChoice::SELF:
            return getuid();
        case UidChoice::FUZZ_UID:
            return provider.ConsumeIntegral<uid_t>();
        default:
            return static_cast<uid_t>(getuid());
    }
}

int32_t ConsumeDeletePid(FuzzedDataProvider& provider)
{
    int32_t inputPid = provider.ConsumeIntegral<int32_t>();
    if (!provider.ConsumeBool()) {
        return inputPid;
    }
    int32_t offset = provider.ConsumeIntegralInRange<int32_t>(-MAX_PID_OFFSET, MAX_PID_OFFSET);
    if (provider.ConsumeBool()) {
        return getpid() + offset;
    }
    return inputPid + offset;
}

std::vector<std::string> ConsumeDeletePermissions(FuzzedDataProvider& provider)
{
    if (!provider.ConsumeBool()) {
        return {};
    }
    return { MANAGE_TOOL_TOKENID };
}

std::vector<std::string> ConsumePermissionList(FuzzedDataProvider& provider, const std::string& permissionName)
{
    if (!provider.ConsumeBool()) {
        return {};
    }
    return { permissionName };
}

void DeleteToolTokenByPidWithConsumedCaller(FuzzedDataProvider& provider, int32_t pid)
{
    CallingContextGuard guard;
    SwitchToUid(ConsumeUid(provider));
    auto choice = static_cast<CallerChoice>(provider.ConsumeIntegralInRange<uint8_t>(
        0, static_cast<uint8_t>(CallerChoice::END) - 1));
    switch (choice) {
        case CallerChoice::CURRENT_CALLER:
            (void)AccessTokenKit::DeleteToolTokenByPid(pid);
            break;
        case CallerChoice::HAP_CALLER: {
            MockToken hapCaller(ConsumeDeletePermissions(provider), true, provider.ConsumeBool());
            (void)AccessTokenKit::DeleteToolTokenByPid(pid);
            break;
        }
        case CallerChoice::NATIVE_CALLER: {
            MockToken nativeCaller(ConsumeDeletePermissions(provider), false);
            (void)AccessTokenKit::DeleteToolTokenByPid(pid);
            break;
        }
        case CallerChoice::PRIVILEGED_NATIVE_CALLER: {
            MockToken nativeCaller({ MANAGE_TOOL_TOKENID }, false);
            (void)AccessTokenKit::DeleteToolTokenByPid(pid);
            break;
        }
        default:
            break;
    }
}

void CleanupCurrentToolToken()
{
    CallingContextGuard guard;
    SwitchToUid(AIMGR_UID);
    MockToken nativeCaller({ MANAGE_TOOL_TOKENID }, false);
    (void)AccessTokenKit::DeleteToolTokenByPid(getpid());
}

AccessTokenID TryInitConsumedToolToken(FuzzedDataProvider& provider, AccessTokenID hostTokenId)
{
    if (!provider.ConsumeBool()) {
        return INVALID_TOKENID;
    }
    if (provider.ConsumeBool()) {
        CliInitInfo initInfo;
        initInfo.hostTokenId = provider.ConsumeBool() ? hostTokenId : ConsumeTokenId(provider);
        initInfo.challenge = provider.ConsumeBool() ? GenerateCliChallenge(hostTokenId) : ConsumeClawString(provider);
        initInfo.cliInfo = provider.ConsumeBool() ? BuildDefaultCliInfo() : ConsumeLifecycleCliInfo(provider);
        return TryInitCliTokenWithUid(initInfo, ConsumeUid(provider));
    }

    SkillInitInfo initInfo;
    initInfo.hostTokenId = provider.ConsumeBool() ? hostTokenId : ConsumeTokenId(provider);
    initInfo.challenge = provider.ConsumeBool() ? GenerateSkillChallenge(hostTokenId) : ConsumeClawString(provider);
    initInfo.skillInfo = provider.ConsumeBool() ? BuildDefaultSkillInfo() : ConsumeLifecycleSkillInfo(provider);
    return TryInitSkillTokenWithUid(initInfo, ConsumeUid(provider));
}

void ExerciseDeleteToolTokenByPid(FuzzedDataProvider& provider, AccessTokenID toolTokenId)
{
    int32_t round = provider.ConsumeIntegralInRange<int32_t>(1, MAX_DELETE_ROUND);
    for (int32_t i = 0; i < round; ++i) {
        DeleteToolTokenByPidWithConsumedCaller(provider, ConsumeDeletePid(provider));
    }
    if (toolTokenId != INVALID_TOKENID) {
        CleanupCurrentToolToken();
    }
}

void ExerciseConsumedDeleteToolTokenByPid(FuzzedDataProvider& provider, AccessTokenID hostTokenId)
{
    AccessTokenID toolTokenId = TryInitConsumedToolToken(provider, hostTokenId);
    ExerciseDeleteToolTokenByPid(provider, toolTokenId);
}

void ExerciseCliLifecycle(FuzzedDataProvider& provider, AccessTokenID hostTokenId)
{
    CliInitInfo initInfo;
    initInfo.hostTokenId = provider.ConsumeBool() ? hostTokenId : ConsumeTokenId(provider);
    initInfo.challenge = provider.ConsumeBool() ? "" : ConsumeClawString(provider);
    initInfo.cliInfo = ConsumeLifecycleCliInfo(provider);

    AccessTokenID toolTokenId = TryInitCliTokenWithUid(initInfo, ConsumeUid(provider));
    (void)AccessTokenKit::IsCliToolToken(toolTokenId);

    CliTokenInfo cliTokenInfo;
    AccessTokenID hostTokenIdOut = INVALID_TOKENID;
    (void)AccessTokenKit::GetCliTokenInfo(ConsumeQueryTokenId(provider, toolTokenId, hostTokenId), cliTokenInfo);
    (void)AccessTokenKit::GetHostTokenId(ConsumeQueryTokenId(provider, toolTokenId, hostTokenId), hostTokenIdOut);
    {
        MockToken caller(ConsumeDeletePermissions(provider), true, provider.ConsumeBool());
        (void)AccessTokenKit::GetCliTokenInfo(ConsumeQueryTokenId(provider, toolTokenId, hostTokenId), cliTokenInfo);
        (void)AccessTokenKit::GetHostTokenId(ConsumeQueryTokenId(provider, toolTokenId, hostTokenId), hostTokenIdOut);
    }

    ExerciseDeleteToolTokenByPid(provider, toolTokenId);
    (void)AccessTokenKit::GetCliTokenInfo(toolTokenId, cliTokenInfo);
    (void)AccessTokenKit::GetHostTokenId(toolTokenId, hostTokenIdOut);
}

void ExerciseSkillLifecycle(FuzzedDataProvider& provider, AccessTokenID hostTokenId)
{
    SkillInitInfo initInfo;
    initInfo.hostTokenId = provider.ConsumeBool() ? hostTokenId : ConsumeTokenId(provider);
    initInfo.challenge = provider.ConsumeBool() ? "" : ConsumeClawString(provider);
    initInfo.skillInfo = ConsumeLifecycleSkillInfo(provider);

    AccessTokenID toolTokenId = TryInitSkillTokenWithUid(initInfo, ConsumeUid(provider));
    (void)AccessTokenKit::IsCliToolToken(toolTokenId);

    SkillTokenInfo skillTokenInfo;
    AccessTokenID hostTokenIdOut = INVALID_TOKENID;
    (void)AccessTokenKit::GetSkillTokenInfo(ConsumeQueryTokenId(provider, toolTokenId, hostTokenId), skillTokenInfo);
    (void)AccessTokenKit::GetHostTokenId(ConsumeQueryTokenId(provider, toolTokenId, hostTokenId), hostTokenIdOut);
    {
        MockToken caller(ConsumeDeletePermissions(provider), true, provider.ConsumeBool());
        (void)AccessTokenKit::GetSkillTokenInfo(
            ConsumeQueryTokenId(provider, toolTokenId, hostTokenId), skillTokenInfo);
        (void)AccessTokenKit::GetHostTokenId(ConsumeQueryTokenId(provider, toolTokenId, hostTokenId), hostTokenIdOut);
    }

    ExerciseDeleteToolTokenByPid(provider, toolTokenId);
    (void)AccessTokenKit::GetSkillTokenInfo(toolTokenId, skillTokenInfo);
    (void)AccessTokenKit::GetHostTokenId(toolTokenId, hostTokenIdOut);
}

void ExerciseDefaultLifecycle(FuzzedDataProvider& provider, AccessTokenID hostTokenId)
{
    AccessTokenID hostTokenIdOut = INVALID_TOKENID;
    CliTokenInfo cliTokenInfo;
    SkillTokenInfo skillTokenInfo;
    auto queryCliToken = [&cliTokenInfo, &hostTokenIdOut](AccessTokenID tokenId) {
        MockToken unprivilegedCaller({}, true, false);
        (void)AccessTokenKit::GetCliTokenInfo(tokenId, cliTokenInfo);
        (void)AccessTokenKit::GetHostTokenId(tokenId, hostTokenIdOut);
    };
    auto querySkillToken = [&skillTokenInfo, &hostTokenIdOut](AccessTokenID tokenId) {
        MockToken unprivilegedCaller({}, true, false);
        (void)AccessTokenKit::GetSkillTokenInfo(tokenId, skillTokenInfo);
        (void)AccessTokenKit::GetHostTokenId(tokenId, hostTokenIdOut);
    };

    CliInitInfo cliInitInfo;
    cliInitInfo.hostTokenId = hostTokenId;
    cliInitInfo.challenge = GenerateCliChallenge(hostTokenId);
    cliInitInfo.cliInfo = BuildDefaultCliInfo();
    AccessTokenID cliTokenId = TryInitCliToken(cliInitInfo);
    queryCliToken(cliTokenId);
    ExerciseDeleteToolTokenByPid(provider, cliTokenId);
    queryCliToken(cliTokenId);

    SkillInitInfo skillInitInfo;
    skillInitInfo.hostTokenId = hostTokenId;
    skillInitInfo.challenge = GenerateSkillChallenge(hostTokenId);
    skillInitInfo.skillInfo = BuildDefaultSkillInfo();
    AccessTokenID skillTokenId = TryInitSkillToken(skillInitInfo);
    querySkillToken(skillTokenId);
    ExerciseDeleteToolTokenByPid(provider, skillTokenId);
    querySkillToken(skillTokenId);

    cliInitInfo.challenge = "";
    AccessTokenID emptyCliTokenId = TryInitCliToken(cliInitInfo);
    ExerciseDeleteToolTokenByPid(provider, emptyCliTokenId);

    skillInitInfo.challenge = "";
    AccessTokenID emptySkillTokenId = TryInitSkillToken(skillInitInfo);
    ExerciseDeleteToolTokenByPid(provider, emptySkillTokenId);

    CliInitInfo invalidCliInfo = cliInitInfo;
    invalidCliInfo.hostTokenId = INVALID_TOKENID;
    (void)TryInitCliToken(invalidCliInfo);

    SkillInitInfo invalidSkillInfo = skillInitInfo;
    invalidSkillInfo.skillInfo.skillName.clear();
    (void)TryInitSkillToken(invalidSkillInfo);
}
}

bool ToolTokenLifecycleFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    MockToken hostMock({}, true, true);
    AccessTokenID hostTokenId = hostMock.GetTokenId();
    ExerciseAuthResultApi(provider, hostTokenId);
    ExerciseConsumedDeleteToolTokenByPid(provider, hostTokenId);
    ExerciseDefaultLifecycle(provider, hostTokenId);
    ExerciseCliLifecycle(provider, hostTokenId);
    ExerciseSkillLifecycle(provider, hostTokenId);
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::ToolTokenLifecycleFuzzTest(data, size);
    return 0;
}
