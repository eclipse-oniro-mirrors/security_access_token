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

#include "access_token.h"
#include "access_token_error.h"

namespace OHOS {
namespace Security {
namespace SAF {
namespace {
constexpr int32_t QUERY_RET_ABNORMAL = -20260426;
constexpr size_t VERIFY_RESULT_PATTERN_MOD = 2;
const std::string LOCATION_PERMISSION = "ohos.permission.APPROXIMATELY_LOCATION";
const std::string POWER_MANAGER_CLI_PERMISSION = "ohos.permission.cli.POWER_MANAGER";
const std::string CAMERA_PERMISSION = "ohos.permission.CAMERA";
const std::string LOCATION_SWITCH_PERMISSION = "ohos.permission.cli.CONTROL_LOCATION_SWITCH";

const std::map<std::string, std::vector<std::string>> DEFAULT_COMMAND_PERMISSIONS = {
    {"ohos-queryTime:get-wall-time", {LOCATION_PERMISSION, POWER_MANAGER_CLI_PERMISSION}},
    {"tooltokenstub:stubsubtool", {LOCATION_PERMISSION, POWER_MANAGER_CLI_PERMISSION}},
    {"camera:capture", {CAMERA_PERMISSION, POWER_MANAGER_CLI_PERMISSION}},
    {"location:query", {LOCATION_PERMISSION, LOCATION_SWITCH_PERMISSION}},
    {"resolved:run", {POWER_MANAGER_CLI_PERMISSION, CAMERA_PERMISSION, POWER_MANAGER_CLI_PERMISSION}},
};

const std::vector<std::string> DEFAULT_FALLBACK_PERMISSIONS = {
    LOCATION_PERMISSION,
    POWER_MANAGER_CLI_PERMISSION,
};

MockSafBehavior g_mockBehavior;

std::vector<std::string> GetCommandPermissions(const CommandInfo& cmd)
{
    const std::string key = cmd.cmdName + ":" + cmd.subCmd;
    auto iter = DEFAULT_COMMAND_PERMISSIONS.find(key);
    if (iter != DEFAULT_COMMAND_PERMISSIONS.end()) {
        return iter->second;
    }
    return DEFAULT_FALLBACK_PERMISSIONS;
}

std::vector<CliInfo> BuildDefaultVerifiedCliInfos(const std::string& callerId)
{
    std::vector<CliInfo> cliInfos;
    CliInfo queryTimeInfo;
    queryTimeInfo.callerTokenId = callerId;
    queryTimeInfo.cliCmdName = "ohos-queryTime";
    queryTimeInfo.subCliCmdName = "get-wall-time";
    queryTimeInfo.permissionList = { LOCATION_PERMISSION, POWER_MANAGER_CLI_PERMISSION };
    cliInfos.emplace_back(queryTimeInfo);

    CliInfo stubInfo;
    stubInfo.callerTokenId = callerId;
    stubInfo.cliCmdName = "tooltokenstub";
    stubInfo.subCliCmdName = "stubsubtool";
    stubInfo.permissionList = { LOCATION_PERMISSION, POWER_MANAGER_CLI_PERMISSION };
    cliInfos.emplace_back(stubInfo);

    CliInfo cameraInfo;
    cameraInfo.callerTokenId = callerId;
    cameraInfo.cliCmdName = "camera";
    cameraInfo.subCliCmdName = "capture";
    cameraInfo.permissionList = { CAMERA_PERMISSION, POWER_MANAGER_CLI_PERMISSION };
    cliInfos.emplace_back(cameraInfo);

    CliInfo resolvedInfo;
    resolvedInfo.callerTokenId = callerId;
    resolvedInfo.cliCmdName = "resolved";
    resolvedInfo.subCliCmdName = "run";
    resolvedInfo.permissionList = { POWER_MANAGER_CLI_PERMISSION, CAMERA_PERMISSION, POWER_MANAGER_CLI_PERMISSION };
    cliInfos.emplace_back(resolvedInfo);
    return cliInfos;
}

void TrimCliInfoPermissions(std::vector<CliInfo>& cliInfos)
{
    for (auto& cliInfo : cliInfos) {
        cliInfo.permissionList.clear();
    }
}

void MismatchCliInfos(std::vector<CliInfo>& cliInfos)
{
    for (auto& cliInfo : cliInfos) {
        cliInfo.callerTokenId += "_mismatch";
        cliInfo.cliCmdName += "_mismatch";
        cliInfo.subCliCmdName += "_mismatch";
    }
}
} // namespace

void ResetMockSafBehavior()
{
    g_mockBehavior = {};
}

void SetMockSafBehavior(const MockSafBehavior& behavior)
{
    g_mockBehavior = behavior;
}

int32_t SafAgentFence::BatchQueryCommandPermission(
    const std::vector<CommandInfo>& cmds, std::vector<CommandPermissionInfo>& permissionInfos)
{
    if (g_mockBehavior.queryMode == MockQueryMode::EMPTY_RESULT) {
        permissionInfos.clear();
        return OHOS::Security::AccessToken::RET_SUCCESS;
    }

    permissionInfos.clear();
    permissionInfos.reserve(cmds.size());
    for (const auto& cmd : cmds) {
        CommandPermissionInfo permissionInfo;
        permissionInfo.cmd = cmd;
        if (cmd.cmdName.empty() || cmd.subCmd.empty()) {
            permissionInfo.queryRet = AccessToken::AccessTokenError::ERR_PARAM_INVALID;
            permissionInfos.emplace_back(permissionInfo);
            continue;
        }

        if ((cmd.cmdName == "abnormal") && (cmd.subCmd == "run")) {
            permissionInfo.queryRet = QUERY_RET_ABNORMAL;
            permissionInfos.emplace_back(permissionInfo);
            continue;
        }

        permissionInfo.permissions = GetCommandPermissions(cmd);
        if (g_mockBehavior.queryMode == MockQueryMode::EMPTY_PERMISSIONS) {
            permissionInfo.permissions.clear();
        }
        if (g_mockBehavior.queryMode == MockQueryMode::DUPLICATE_PERMISSIONS &&
            !permissionInfo.permissions.empty()) {
            permissionInfo.permissions.emplace_back(permissionInfo.permissions.front());
        }
        if (g_mockBehavior.queryMode == MockQueryMode::QUERY_RET_INVALID) {
            permissionInfo.queryRet = 1;
            permissionInfos.emplace_back(permissionInfo);
            continue;
        }
        if (g_mockBehavior.queryMode == MockQueryMode::QUERY_RET_ABNORMAL) {
            permissionInfo.queryRet = QUERY_RET_ABNORMAL;
            permissionInfos.emplace_back(permissionInfo);
            continue;
        }
        permissionInfo.queryRet = OHOS::Security::AccessToken::RET_SUCCESS;
        permissionInfos.emplace_back(permissionInfo);
    }
    if (g_mockBehavior.queryMode == MockQueryMode::SIZE_MISMATCH && !permissionInfos.empty()) {
        permissionInfos.pop_back();
    }
    return OHOS::Security::AccessToken::RET_SUCCESS;
}

int32_t SafAgentFence::BatchGenerateTicket(int32_t userId, const std::string& callerId,
    const std::vector<std::string>& messages, std::vector<VerifyTicketInfo>& tickets)
{
    (void)userId;
    (void)callerId;

    tickets.clear();
    tickets.reserve(messages.size());
    for (size_t i = 0; i < messages.size(); ++i) {
        VerifyTicketInfo info;
        info.message = messages[i];
        if ((g_mockBehavior.generateMode == MockGenerateMode::EMPTY_CHALLENGE) || messages[i].empty()) {
            info.challenge = "";
            info.ticket = "";
        } else {
            info.challenge = "fuzz_challenge_" + std::to_string(i);
            info.ticket = "fuzz_ticket_" + std::to_string(i);
        }
        tickets.emplace_back(info);
    }
    return OHOS::Security::AccessToken::RET_SUCCESS;
}

int32_t SafAgentFence::BatchVerifyTicket(int32_t userId, const std::string& callerId,
    const std::vector<VerifyTicketInfo>& verifyInfos, std::vector<int32_t>& verifyRes)
{
    (void)userId;
    (void)callerId;

    if (g_mockBehavior.verifyMode == MockVerifyMode::VERIFY_RET_FAILED) {
        return AccessToken::AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    verifyRes.clear();
    verifyRes.reserve(verifyInfos.size());
    for (size_t index = 0; index < verifyInfos.size(); ++index) {
        const auto& verifyInfo = verifyInfos[index];
        if (verifyInfo.challenge.empty() || verifyInfo.ticket.empty()) {
            verifyRes.emplace_back(AccessToken::AccessTokenError::ERR_PARAM_INVALID);
            continue;
        }
        if (g_mockBehavior.verifyMode == MockVerifyMode::ALL_DENIED) {
            verifyRes.emplace_back(AccessToken::AccessTokenError::ERR_PERMISSION_DENIED);
            continue;
        }
        if (g_mockBehavior.verifyMode == MockVerifyMode::MIXED_RESULT) {
            verifyRes.emplace_back((index % VERIFY_RESULT_PATTERN_MOD == 0) ?
                OHOS::Security::AccessToken::RET_SUCCESS :
                AccessToken::AccessTokenError::ERR_PERMISSION_DENIED);
            continue;
        }
        if (verifyInfo.message.find("false") != std::string::npos) {
            verifyRes.emplace_back(AccessToken::AccessTokenError::ERR_PERMISSION_DENIED);
            continue;
        }
        verifyRes.emplace_back(OHOS::Security::AccessToken::RET_SUCCESS);
    }
    return OHOS::Security::AccessToken::RET_SUCCESS;
}

int32_t SafAgentFence::VerifyTicket(int32_t osAccountId, const std::string& callerId,
    const std::string& verifyInfo, std::vector<CliInfo>& cliInfos)
{
    (void)osAccountId;
    if (g_mockBehavior.verifyMode == MockVerifyMode::VERIFY_RET_FAILED) {
        return AccessToken::AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    if (g_mockBehavior.verifyMode == MockVerifyMode::EMPTY_CLI_INFOS ||
        verifyInfo.find("empty") != std::string::npos) {
        cliInfos.clear();
        return OHOS::Security::AccessToken::RET_SUCCESS;
    }

    cliInfos = BuildDefaultVerifiedCliInfos(callerId);
    if (g_mockBehavior.verifyMode == MockVerifyMode::CLI_INFO_MISMATCH ||
        verifyInfo.find("mismatch") != std::string::npos) {
        MismatchCliInfos(cliInfos);
        return OHOS::Security::AccessToken::RET_SUCCESS;
    }
    if (g_mockBehavior.verifyMode == MockVerifyMode::EMPTY_PERMISSION_LIST ||
        verifyInfo.find("empty_permission") != std::string::npos) {
        TrimCliInfoPermissions(cliInfos);
        return OHOS::Security::AccessToken::RET_SUCCESS;
    }
    return OHOS::Security::AccessToken::RET_SUCCESS;
}
} // namespace SAF
} // namespace Security
} // namespace OHOS
