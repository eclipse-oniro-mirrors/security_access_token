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

#include "claw_permission_metadata_provider.h"

#include <unordered_set>
#include <utility>

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "constant_common.h"
#include "permission_map.h"
#include "saf_agent_fence.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
void StableUnique(std::vector<std::string>& values)
{
    std::unordered_set<std::string> seen;
    std::vector<std::string> uniqueValues;
    uniqueValues.reserve(values.size());
    for (const auto& value : values) {
        if (seen.insert(value).second) {
            uniqueValues.emplace_back(value);
        }
    }
    values = std::move(uniqueValues);
}
}

ClawPermissionMetadataProvider& ClawPermissionMetadataProvider::GetInstance()
{
    static ClawPermissionMetadataProvider instance;
    return instance;
}

int32_t ClawPermissionMetadataProvider::CheckClawCliControlPermission(AccessTokenID clawTokenId)
{
    if (clawTokenId == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Check claw cli control permission failed, invalid token.");
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }
    return RET_SUCCESS;
}

int32_t ClawPermissionMetadataProvider::GetCliCallablePermissions(
    const std::vector<CliInfo>& cliInfoList, std::vector<std::vector<std::string>>& cliPermissions)
{
    cliPermissions.clear();
    cliPermissions.reserve(cliInfoList.size());

    std::vector<SAF::CommandInfo> cmds;
    cmds.reserve(cliInfoList.size());
    for (const auto& cliInfo : cliInfoList) {
        SAF::CommandInfo cmd;
        cmd.cmdName = cliInfo.cliName;
        cmd.subCmd = cliInfo.subCliName;
        cmds.emplace_back(cmd);
    }

    std::vector<SAF::CommandPermissionInfo> permissionInfos;
    SAF::SafAgentFence agentFence;
    int32_t ret = agentFence.BatchQueryCommandPermission(cmds, permissionInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Query cli callable permissions failed, cliSize=%{public}zu, ret=%{public}d.",
            cliInfoList.size(), ret);
        return ret;
    }
    if (permissionInfos.size() != cliInfoList.size()) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Query cli callable permissions size mismatch, input=%{public}zu, output=%{public}zu.",
            cliInfoList.size(), permissionInfos.size());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }

    for (size_t index = 0; index < permissionInfos.size(); ++index) {
        const auto& permissionInfo = permissionInfos[index];
        if (permissionInfo.queryRet != RET_SUCCESS) {
            LOGW(ATM_DOMAIN, ATM_TAG,
                "Query cli callable permission queryRet is not success, skip cli, index=%{public}zu, "
                "cli=%{public}s/%{public}s, ret=%{public}d.",
                index, cliInfoList[index].cliName.c_str(), cliInfoList[index].subCliName.c_str(),
                permissionInfo.queryRet);
            cliPermissions.emplace_back();
            continue;
        }
        std::vector<std::string> permissions = permissionInfo.permissions;
        StableUnique(permissions);
        cliPermissions.emplace_back(permissions);
    }
    return RET_SUCCESS;
}

int32_t ClawPermissionMetadataProvider::GetRequiredCliPermissions(
    const CliInfo& cliInfo, std::vector<std::string>& requiredCliPermissions)
{
    requiredCliPermissions.clear();

    SAF::CommandInfo cmd;
    cmd.cmdName = cliInfo.cliName;
    cmd.subCmd = cliInfo.subCliName;

    std::vector<SAF::CommandPermissionInfo> permissionInfos;
    SAF::SafAgentFence agentFence;
    int32_t ret = agentFence.BatchQueryCommandPermission({cmd}, permissionInfos);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Get required cli permissions failed, cli=%{public}s/%{public}s, ret=%{public}d.",
            cliInfo.cliName.c_str(), cliInfo.subCliName.c_str(), ret);
        return ret;
    }
    if (permissionInfos.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Get required cli permissions empty result, cli=%{public}s/%{public}s.",
            cliInfo.cliName.c_str(), cliInfo.subCliName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }
    if (permissionInfos[0].queryRet != RET_SUCCESS) {
        LOGW(ATM_DOMAIN, ATM_TAG,
            "Get required cli permissions queryRet is not success, skip cli, cli=%{public}s/%{public}s, "
            "ret=%{public}d.",
            cliInfo.cliName.c_str(), cliInfo.subCliName.c_str(), permissionInfos[0].queryRet);
        return RET_SUCCESS;
    }
    requiredCliPermissions = permissionInfos[0].permissions;
    StableUnique(requiredCliPermissions);
    return RET_SUCCESS;
}

int32_t ClawPermissionMetadataProvider::GetUsedPermissionsByCliPermission(
    const std::string& requiredCliPermission, std::vector<std::string>& usedPermissions)
{
    usedPermissions.clear();
    if (requiredCliPermission.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get used permissions failed, cli permission is empty.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (!QueryRequredPermissions(requiredCliPermission, usedPermissions)) {
        if (!IsDefinedPermission(requiredCliPermission)) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Get used permissions failed, permission=%{public}s has no mapping and no definition.",
                requiredCliPermission.c_str());
            return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
        }
        usedPermissions.emplace_back(requiredCliPermission);
        return RET_SUCCESS;
    }
    StableUnique(usedPermissions);
    return RET_SUCCESS;
}

int32_t ClawPermissionMetadataProvider::GetSkillUsedPermissions(
    const SkillInfo& skillInfo, std::vector<std::string>& usedPermissions)
{
    usedPermissions.clear();
    if (skillInfo.skillName.empty() || skillInfo.bundleName.empty() || skillInfo.moduleName.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Get skill used permissions failed, invalid skill info, bundle=%{public}s, module=%{public}s, "
            "skill=%{public}s.",
            skillInfo.bundleName.c_str(), skillInfo.moduleName.c_str(), skillInfo.skillName.c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
