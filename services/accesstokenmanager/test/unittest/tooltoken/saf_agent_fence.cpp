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

#include "saf_agent_fence.h"

#include <map>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "constant_common.h"

namespace OHOS {
namespace Security {
namespace {
int g_generateCounter = 0;
int g_verifyCounter = 0;

std::map<std::string, std::vector<std::string>> g_commandPermissions;
bool g_commandPermissionsConfigured = false;

std::vector<SAF::VerifyTicketInfo> g_generateTickets;
int32_t g_generateRet = 0;
bool g_generateConfigured = false;

std::vector<int32_t> g_verifyRes;
int32_t g_verifyRet = 0;
bool g_verifyConfigured = false;

constexpr int32_t MOCK_ABNORMAL_QUERY_RET = -20260426;

const std::map<std::string, std::vector<std::string>> MOCK_CLI_REQUIRED_PERMISSIONS = {
    {"abnormal:run", {"ohos.permission.CAMERA"}},
    {"camera:capture", {"ohos.permission.POWER_MANAGER"}},
    {"duplicate:run", {"ohos.permission.APPROXIMATELY_LOCATION", "ohos.permission.APPROXIMATELY_LOCATION"}},
    {"empty:run", {}},
    {"missingmap:run", {"ohos.permission.cli.no_mapping"}},
    {"mixed:run", {"ohos.permission.APPROXIMATELY_LOCATION", "ohos.permission.CAMERA"}},
    {"multi:run", {"ohos.permission.APPROXIMATELY_LOCATION", "ohos.permission.POWER_MANAGER"}},
    {"location:query", {"ohos.permission.APPROXIMATELY_LOCATION"}},
    {"resolved:run", {"ohos.permission.cli.resolved"}},
};
} // namespace

namespace SAF {
int32_t SafAgentFence::BatchQueryCommandPermission(
    const std::vector<CommandInfo>& cmds, std::vector<CommandPermissionInfo>& permissionInfos)
{
    const auto& permissionMap =
        g_commandPermissionsConfigured ? g_commandPermissions : MOCK_CLI_REQUIRED_PERMISSIONS;
    permissionInfos.clear();
    permissionInfos.reserve(cmds.size());
    for (size_t index = 0; index < cmds.size(); ++index) {
        const auto& cmd = cmds[index];
        CommandPermissionInfo permissionInfo;
        permissionInfo.cmd = cmd;
        if (cmd.cmdName.empty() || cmd.subCmd.empty()) {
            permissionInfo.queryRet = AccessToken::AccessTokenError::ERR_PARAM_INVALID;
            LOGE(ATM_DOMAIN, ATM_TAG, "Mock query command permission invalid cmd, index=%{public}zu.", index);
            permissionInfos.emplace_back(permissionInfo);
            continue;
        }

        const std::string key = cmd.cmdName + ":" + cmd.subCmd;
        if (key == "abnormal:run") {
            permissionInfo.queryRet = MOCK_ABNORMAL_QUERY_RET;
            LOGW(ATM_DOMAIN, ATM_TAG,
                "Mock query command permission abnormal, index=%{public}zu, cmd=%{public}s/%{public}s, "
                "ret=%{public}d.", index, cmd.cmdName.c_str(), cmd.subCmd.c_str(), permissionInfo.queryRet);
            permissionInfos.emplace_back(permissionInfo);
            continue;
        }
        auto iter = permissionMap.find(key);
        if (iter == permissionMap.end()) {
            permissionInfo.queryRet = AccessToken::AccessTokenError::ERR_PERMISSION_NOT_EXIST;
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Mock query command permission missing, index=%{public}zu, cmd=%{public}s/%{public}s.",
                index, cmd.cmdName.c_str(), cmd.subCmd.c_str());
            permissionInfos.emplace_back(permissionInfo);
            continue;
        }
        permissionInfo.permissions = iter->second;
        permissionInfo.queryRet = AccessToken::RET_SUCCESS;
        permissionInfos.emplace_back(permissionInfo);
    }
    return AccessToken::RET_SUCCESS;
}

int32_t SafAgentFence::BatchGenerateTicket(int32_t userId, const std::string& callerId,
    const std::vector<std::string>& messages, std::vector<VerifyTicketInfo>& tickets)
{
    tickets.clear();
    if (g_generateConfigured) {
        tickets = g_generateTickets;
        return g_generateRet;
    }

    for (size_t i = 0; i < messages.size(); ++i) {
        ++g_generateCounter;
        VerifyTicketInfo info;
        info.message = messages[i];
        info.challenge = "mock_challenge_" + std::to_string(g_generateCounter);
        info.ticket = "mock_ticket_" + std::to_string(g_generateCounter);
        tickets.emplace_back(info);
    }

    return 0;
}

int32_t SafAgentFence::BatchVerifyTicket(int32_t userId, const std::string& callerId,
    const std::vector<VerifyTicketInfo>& verifyInfos, std::vector<int32_t>& verifyRes)
{
    if (g_verifyConfigured) {
        verifyRes = g_verifyRes;
        g_verifyConfigured = false;
        return g_verifyRet;
    }

    for (size_t i = 0; i < verifyInfos.size(); ++i) {
        ++g_verifyCounter;
        verifyRes.emplace_back(0);
    }

    return 0;
}
} // namespace SAF

namespace AccessToken {
void SetMockVerifyTicketResult(std::vector<int32_t> verifyRes, int32_t ret)
{
    g_verifyRes = verifyRes;
    g_verifyRet = ret;
    g_verifyConfigured = true;
}

void SetMockCommandPermissionsForTest(
    const std::map<std::string, std::vector<std::string>>& commandPermissions)
{
    g_commandPermissions = commandPermissions;
    g_commandPermissionsConfigured = true;
}

void ClearMockCommandPermissionsForTest()
{
    g_commandPermissions.clear();
    g_commandPermissionsConfigured = false;
}

void SetMockGenerateTicketResult(const std::vector<SAF::VerifyTicketInfo>& tickets, int32_t ret)
{
    g_generateTickets = tickets;
    g_generateRet = ret;
    g_generateConfigured = true;
}

void ClearMockGenerateTicketResult()
{
    g_generateTickets.clear();
    g_generateRet = 0;
    g_generateConfigured = false;
}

void ClearMockVerifyTicketResult()
{
    g_verifyRes.clear();
    g_verifyRet = 0;
    g_verifyConfigured = false;
}

void ResetMockCounter()
{
    g_generateCounter = 0;
    g_verifyCounter = 0;
    ClearMockCommandPermissionsForTest();
    ClearMockGenerateTicketResult();
    ClearMockVerifyTicketResult();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
