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

#ifndef SERVICES_ACCESSTOKENMANAGER_CLAW_PERMISSION_METADATA_PROVIDER_H
#define SERVICES_ACCESSTOKENMANAGER_CLAW_PERMISSION_METADATA_PROVIDER_H

#include <string>
#include <vector>

#include "access_token.h"
#include "claw_permission_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class ClawPermissionMetadataProvider final {
public:
    static ClawPermissionMetadataProvider& GetInstance();

    int32_t CheckClawCliControlPermission(AccessTokenID clawTokenId);
    int32_t GetCliCallablePermissions(
        const std::vector<CliInfo>& cliInfoList, std::vector<std::vector<std::string>>& cliPermissions);
    int32_t GetRequiredCliPermissions(const CliInfo& cliInfo, std::vector<std::string>& requiredCliPermissions);
    int32_t GetUsedPermissionsByCliPermission(
        const std::string& requiredCliPermission, std::vector<std::string>& usedPermissions);
    int32_t GetSkillUsedPermissions(const SkillInfo& skillInfo, std::vector<std::string>& usedPermissions);

private:
    ClawPermissionMetadataProvider() = default;
    ~ClawPermissionMetadataProvider() = default;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // SERVICES_ACCESSTOKENMANAGER_CLAW_PERMISSION_METADATA_PROVIDER_H
