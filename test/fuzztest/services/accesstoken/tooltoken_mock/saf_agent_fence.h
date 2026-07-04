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

#ifndef FUZZ_MOCK_SAF_AGENT_FENCE_H
#define FUZZ_MOCK_SAF_AGENT_FENCE_H

#include <cstdint>
#include <string>
#include <vector>

namespace OHOS {
namespace Security {
namespace SAF {
enum class MockQueryMode : uint8_t {
    NORMAL = 0,
    EMPTY_RESULT,
    EMPTY_PERMISSIONS,
    SIZE_MISMATCH,
    QUERY_RET_INVALID,
    QUERY_RET_ABNORMAL,
    DUPLICATE_PERMISSIONS,
};

enum class MockGenerateMode : uint8_t {
    NORMAL = 0,
    EMPTY_CHALLENGE,
};

enum class MockVerifyMode : uint8_t {
    NORMAL = 0,
    ALL_DENIED,
    MIXED_RESULT,
    VERIFY_RET_FAILED,
    EMPTY_CLI_INFOS,
    CLI_INFO_MISMATCH,
    EMPTY_PERMISSION_LIST,
};

struct MockSafBehavior {
    MockQueryMode queryMode = MockQueryMode::NORMAL;
    MockGenerateMode generateMode = MockGenerateMode::NORMAL;
    MockVerifyMode verifyMode = MockVerifyMode::NORMAL;
};

struct CommandInfo {
    std::string cmdName;
    std::string subCmd;
};

struct CommandPermissionInfo {
    CommandInfo cmd;
    std::vector<std::string> permissions;
    int32_t queryRet = 0;
};

struct VerifyTicketInfo {
    std::string message;
    std::string challenge;
    std::string ticket;
};

struct CliInfo {
    std::string callerTokenId;
    std::string cliCmdName;
    std::string subCliCmdName;
    std::vector<std::string> permissionList;
};

class SafAgentFence {
public:
    SafAgentFence() = default;
    ~SafAgentFence() = default;

    int32_t BatchQueryCommandPermission(
        const std::vector<CommandInfo>& cmds, std::vector<CommandPermissionInfo>& permissionInfos);

    int32_t BatchGenerateTicket(int32_t userId, const std::string& callerId,
        const std::vector<std::string>& messages, std::vector<VerifyTicketInfo>& tickets);

    int32_t BatchVerifyTicket(int32_t userId, const std::string& callerId,
        const std::vector<VerifyTicketInfo>& verifyInfos, std::vector<int32_t>& verifyRes);

    int32_t VerifyTicket(int32_t osAccountId, const std::string& callerId,
        const std::string& verifyInfo, std::vector<CliInfo>& cliInfos);
};

void ResetMockSafBehavior();
void SetMockSafBehavior(const MockSafBehavior& behavior);
} // namespace SAF
} // namespace Security
} // namespace OHOS

#endif // FUZZ_MOCK_SAF_AGENT_FENCE_H
