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

#ifndef SERVICES_ACCESSTOKENMANAGER_CLAW_PERMISSION_DECISION_ENGINE_H
#define SERVICES_ACCESSTOKENMANAGER_CLAW_PERMISSION_DECISION_ENGINE_H

#include <unordered_map>
#include <string>
#include <vector>

#include "access_token.h"
#include "claw_permission_info.h"
#include "permission_status.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class ClawPermissionDecisionEngine final {
public:
    static ClawPermissionDecisionEngine& GetInstance();

    int32_t BuildCliPermissionDialogInfo(
        AccessTokenID clawTokenId, const std::vector<CliInfo>& cliInfoList, PermissionDialogResult& result);
    int32_t BuildSkillPermissionDialogInfo(
        AccessTokenID clawTokenId, const std::vector<SkillInfo>& skillInfoList, PermissionDialogResult& result);
    int32_t BuildCliPermissions(
        AccessTokenID clawTokenId, const std::vector<CliInfo>& cliInfoList, CliPermissionsResult& result);
    int32_t BuildSkillPermissions(
        AccessTokenID clawTokenId, const std::vector<SkillInfo>& skillInfoList, SkillPermissionsResult& result);
    int32_t ValidateClawCliAccess(AccessTokenID clawTokenId, const std::vector<CliInfo>& cliInfoList);

private:
    class DecisionContext final {
    public:
        explicit DecisionContext(AccessTokenID clawTokenId);
        int32_t Init();
        PermissionDecisionStatus GetPermissionDecisionStatus(
            const std::string& permissionName, PermissionDecisionStatus notDeclaredStatus) const;
        bool HasDialogPermission(
            const std::vector<std::string>& permissions, PermissionDecisionStatus notDeclaredStatus) const;

    private:
        AccessTokenID clawTokenId_;
        std::unordered_map<std::string, PermissionStatus> permissionStatusMap_;
    };

    static int32_t BuildCliDialogDetailByRequiredPermission(
        const DecisionContext& context, const std::string& requiredCliPermission, PermissionDialogDetail& detail);
    static int32_t BuildCliPermissionDialogDetail(
        const DecisionContext& context, const CliInfo& cliInfo, PermissionDialogDetail& detail);
    static PermissionDecisionStatus GetCliPermissionResolvedStatus(
        const DecisionContext& context, const std::vector<std::string>& usedPermissions);
    static int32_t BuildCliPermissionDetailByRequiredPermission(
        const DecisionContext& context, const std::string& requiredCliPermission, CliPermissionDetail& detail);

    ClawPermissionDecisionEngine() = default;
    ~ClawPermissionDecisionEngine() = default;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // SERVICES_ACCESSTOKENMANAGER_CLAW_PERMISSION_DECISION_ENGINE_H
