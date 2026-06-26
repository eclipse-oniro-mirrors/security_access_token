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

#ifndef MOCK_SAF_AGENT_FENCE_H
#define MOCK_SAF_AGENT_FENCE_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace Security {
namespace SAF {
#ifndef ACCESS_TOKEN_SAF_AGENT_FENCE_H
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
#endif
} // namespace SAF

namespace AccessToken {
void SetMockCommandPermissionsForTest(
    const std::map<std::string, std::vector<std::string>>& commandPermissions);
void ClearMockCommandPermissionsForTest();
void SetMockGenerateTicketResult(const std::vector<SAF::VerifyTicketInfo>& tickets, int32_t ret);
void ClearMockGenerateTicketResult();
void SetMockVerifyTicketResult(std::vector<int32_t> verifyRes, int32_t ret);
void SetMockVerifyTicketV2Result(const std::vector<SAF::CliInfo>& cliInfos, int32_t ret);
void ClearMockVerifyTicketResult();
void ResetMockCounter();
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // MOCK_SAF_AGENT_FENCE_H
