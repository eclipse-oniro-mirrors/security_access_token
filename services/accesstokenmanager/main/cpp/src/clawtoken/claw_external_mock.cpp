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

#include "claw_external_mock.h"

#include <map>
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "constant_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
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

const std::map<std::string, std::vector<std::string>> MOCK_SKILL_REQUEST_PERMISSIONS = {
    {"cameraSkill:com.ohos.claw.demo:entry", {"ohos.permission.CAMERA"}},
    {"emptySkill:com.ohos.claw.demo:entry", {}},
    {"locationSkill:com.ohos.claw.demo:entry", {"ohos.permission.LOCATION"}},
    {"multiSkill:com.ohos.claw.demo:entry", {"ohos.permission.LOCATION", "ohos.permission.CAMERA"}},
};

const std::map<std::string, std::vector<std::string>>& GetMockSkillRequestPermissions()
{
    return MOCK_SKILL_REQUEST_PERMISSIONS;
}

const std::map<std::string, std::vector<std::string>>& GetMockCliRequiredPermissions()
{
    return MOCK_CLI_REQUIRED_PERMISSIONS;
}
} // namespace
} // namespace AccessToken
} // namespace Security

namespace Security {
namespace SAF {
int32_t SafAgentFence::BatchQueryCommandPermission(
    const std::vector<CommandInfo>& cmds, std::vector<CommandPermissionInfo>& permissionInfos)
{
    permissionInfos.clear();
    permissionInfos.reserve(cmds.size());
    const auto& mockCliRequiredPermissions = Security::AccessToken::GetMockCliRequiredPermissions();
    for (size_t index = 0; index < cmds.size(); ++index) {
        const auto& cmd = cmds[index];
        CommandPermissionInfo permissionInfo;
        permissionInfo.cmd = cmd;
        if (cmd.cmdName.empty() || cmd.subCmd.empty()) {
            permissionInfo.queryRet = Security::AccessToken::AccessTokenError::ERR_PARAM_INVALID;
            LOGE(ATM_DOMAIN, ATM_TAG, "Mock query command permission invalid cmd, index=%{public}zu.", index);
            permissionInfos.emplace_back(permissionInfo);
            continue;
        }

        const std::string key = cmd.cmdName + ":" + cmd.subCmd;
        if (key == "abnormal:run") {
            permissionInfo.queryRet = Security::AccessToken::MOCK_ABNORMAL_QUERY_RET;
            LOGW(ATM_DOMAIN, ATM_TAG,
                "Mock query command permission abnormal, index=%{public}zu, cmd=%{public}s/%{public}s, "
                "ret=%{public}d.", index, cmd.cmdName.c_str(), cmd.subCmd.c_str(), permissionInfo.queryRet);
            permissionInfos.emplace_back(permissionInfo);
            continue;
        }
        auto iter = mockCliRequiredPermissions.find(key);
        if (iter == mockCliRequiredPermissions.end()) {
            permissionInfo.queryRet = Security::AccessToken::AccessTokenError::ERR_PERMISSION_NOT_EXIST;
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Mock query command permission missing, index=%{public}zu, cmd=%{public}s/%{public}s.",
                index, cmd.cmdName.c_str(), cmd.subCmd.c_str());
            permissionInfos.emplace_back(permissionInfo);
            continue;
        }
        permissionInfo.permissions = iter->second;
        permissionInfo.queryRet = Security::AccessToken::RET_SUCCESS;
        permissionInfos.emplace_back(permissionInfo);
    }
    return Security::AccessToken::RET_SUCCESS;
}
} // namespace SAF

namespace AccessToken {
int32_t BatchGenerateTicket(uint32_t osAccountId, AccessTokenID callerId,
    const std::vector<std::string>& messages, std::vector<VerifyTicketInfo>& tickets)
{
    (void)osAccountId;
    tickets.clear();
    if (callerId == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Mock batch generate ticket failed, invalid caller token.");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    tickets.reserve(messages.size());
    for (size_t index = 0; index < messages.size(); ++index) {
        VerifyTicketInfo ticket;
        ticket.message = messages[index];
        ticket.challenge = "authResult_" + std::to_string(callerId) + "_" + std::to_string(index);
        ticket.ticket = "ticket_" + std::to_string(callerId) + "_" + std::to_string(index);
        tickets.emplace_back(ticket);
    }
    return RET_SUCCESS;
}

int32_t BatchVerifyTicket(uint32_t osAccountId, AccessTokenID callerId,
    const std::vector<VerifyTicketInfo>& verifyInfos, std::vector<int32_t>& verifyRes)
{
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security

namespace AppExecFwk {
ErrCode SkillManager::GetSkillInfo(const std::string& bundleName, const std::string& moduleName,
    const std::string& skillName, uint32_t flags, int32_t userId, SkillInfo& skillInfo)
{
    (void)flags;
    (void)userId;
    skillInfo.bundleName = bundleName;
    skillInfo.moduleName = moduleName;
    skillInfo.skillName = skillName;

    const std::string key = skillName + ":" + bundleName + ":" + moduleName;
    const auto& requestPermissions = Security::AccessToken::GetMockSkillRequestPermissions();
    auto iter = requestPermissions.find(key);
    if (iter == requestPermissions.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Mock get skill info missing, skill=%{public}s/%{public}s/%{public}s.",
            bundleName.c_str(), moduleName.c_str(), skillName.c_str());
        return Security::AccessToken::AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    skillInfo.requestPermissions = iter->second;
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
