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
#include <mutex>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "constant_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
const std::map<std::string, std::vector<std::string>> MOCK_CLI_REQUIRED_PERMISSIONS = {
    {"camera:capture", {"ohos.permission.cli.camera"}},
    {"duplicate:run", {"ohos.permission.cli.location", "ohos.permission.cli.location"}},
    {"empty:run", {}},
    {"missingmap:run", {"ohos.permission.cli.no_mapping"}},
    {"mixed:run", {"ohos.permission.cli.location", "ohos.permission.CAMERA"}},
    {"multi:run", {"ohos.permission.cli.location", "ohos.permission.cli.camera"}},
    {"location:query", {"ohos.permission.cli.location"}},
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
} // namespace

int32_t BatchQueryCommandPermission(
    const std::vector<CommandInfo>& cmds, std::vector<CommandPermissionInfo>& permissionInfos)
{
    permissionInfos.clear();
    permissionInfos.reserve(cmds.size());
    for (size_t index = 0; index < cmds.size(); ++index) {
        const auto& cmd = cmds[index];
        CommandPermissionInfo permissionInfo;
        permissionInfo.cmd = cmd;
        if (cmd.cmdName.empty() || cmd.subCmd.empty()) {
            permissionInfo.queryRet = AccessTokenError::ERR_PARAM_INVALID;
            LOGE(ATM_DOMAIN, ATM_TAG, "Mock query command permission invalid cmd, index=%{public}zu.", index);
            permissionInfos.emplace_back(permissionInfo);
            continue;
        }

        const std::string key = cmd.cmdName + ":" + cmd.subCmd;
        auto iter = MOCK_CLI_REQUIRED_PERMISSIONS.find(key);
        if (iter == MOCK_CLI_REQUIRED_PERMISSIONS.end()) {
            permissionInfo.queryRet = AccessTokenError::ERR_PERMISSION_NOT_EXIST;
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Mock query command permission missing, index=%{public}zu, cmd=%{public}s/%{public}s.",
                index, cmd.cmdName.c_str(), cmd.subCmd.c_str());
            permissionInfos.emplace_back(permissionInfo);
            continue;
        }
        permissionInfo.permissions = iter->second;
        permissionInfo.queryRet = RET_SUCCESS;
        permissionInfos.emplace_back(permissionInfo);
    }
    return RET_SUCCESS;
}

int32_t BatchGenerateTicket(uint32_t osAccountId, AccessTokenID callerId,
    const std::vector<std::string>& messages, std::vector<VerifyTicketInfo>& tickets)
{
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
