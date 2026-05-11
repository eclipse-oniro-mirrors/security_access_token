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

    // Mock implementation for minimal system without saf_agent_fence
    // Return empty permission lists for each CLI
    for (size_t index = 0; index < cliInfoList.size(); ++index) {
        std::vector<std::string> emptyPermissions;
        cliPermissions.emplace_back(emptyPermissions);
        LOGI(ATM_DOMAIN, ATM_TAG,
            "Mock: Query cli callable permissions, cli=%{public}s/%{public}s, returning empty list.",
            cliInfoList[index].cliName.c_str(), cliInfoList[index].subCliName.c_str());
    }
    return RET_SUCCESS;
}

int32_t ClawPermissionMetadataProvider::GetRequiredCliPermissions(
    const CliInfo& cliInfo, std::vector<std::string>& requiredCliPermissions)
{
    requiredCliPermissions.clear();

    // Mock implementation for minimal system without saf_agent_fence
    // Return empty permission list
    LOGI(ATM_DOMAIN, ATM_TAG,
        "Mock: Get required cli permissions, cli=%{public}s/%{public}s, returning empty list.",
        cliInfo.cliName.c_str(), cliInfo.subCliName.c_str());
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
