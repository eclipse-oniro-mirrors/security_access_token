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

#include "claw_permission_decision_engine.h"

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "claw_permission_metadata_provider.h"
#include "claw_permission_status_helper.h"
#include "constant_common.h"
#include "permission_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
void AppendDialogDetailStatus(
    PermissionDialogDetail& detail, const std::string& permissionName, PermissionDecisionStatus status)
{
    for (const auto& item : detail.permissionNameList) {
        if (item == permissionName) {
            return;
        }
    }
    detail.permissionNameList.emplace_back(permissionName);
    detail.statusList.emplace_back(status);
}

bool ShouldReturnDialogDetailStatus(PermissionDecisionStatus status)
{
    return (status == PermissionDecisionStatus::NO_DIALOG_DENIED) ||
        (status == PermissionDecisionStatus::NO_DIALOG_RESTRICTED) ||
        (status == PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED);
}

bool HasNotDeclaredStatus(const PermissionDialogDetail& detail)
{
    for (const auto& status : detail.statusList) {
        if (status == PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED) {
            return true;
        }
    }
    return false;
}

} // namespace

int32_t ClawPermissionDecisionEngine::BuildCliDialogDetailByRequiredPermission(
    const ClawPermissionDecisionEngine::DecisionContext& context, const std::string& requiredCliPermission,
    PermissionDialogDetail& detail)
{
    std::vector<std::string> usedPermissions;
    int32_t ret = ClawPermissionMetadataProvider::GetInstance().GetUsedPermissionsByCliPermission(
        requiredCliPermission, usedPermissions);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    PermissionDecisionStatus notDeclaredStatus = PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED;
    PermissionDecisionStatus cliPermissionStatus = context.GetPermissionDecisionStatus(
        requiredCliPermission, notDeclaredStatus);
    if (cliPermissionStatus == PermissionDecisionStatus::NEED_PERMISSION_DIALOG) {
        PermissionDecisionStatus resolvedStatus = GetCliPermissionResolvedStatus(context, usedPermissions);
        detail.needPermissionDialog = (resolvedStatus == PermissionDecisionStatus::NEED_PERMISSION_DIALOG);
    }
    if (ShouldReturnDialogDetailStatus(cliPermissionStatus)) {
        AppendDialogDetailStatus(detail, requiredCliPermission, cliPermissionStatus);
    }
    if (cliPermissionStatus == PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED) {
        return RET_SUCCESS;
    }

    for (const auto& usedPermission : usedPermissions) {
        PermissionDecisionStatus usedPermissionStatus = context.GetPermissionDecisionStatus(
            usedPermission, PermissionDecisionStatus::NEED_PERMISSION_DIALOG);
        if (usedPermissionStatus == PermissionDecisionStatus::NEED_PERMISSION_DIALOG) {
            continue;
        }
        if (ShouldReturnDialogDetailStatus(usedPermissionStatus)) {
            AppendDialogDetailStatus(detail, usedPermission, usedPermissionStatus);
        }
    }
    return RET_SUCCESS;
}

int32_t ClawPermissionDecisionEngine::BuildCliPermissionDialogDetail(
    const ClawPermissionDecisionEngine::DecisionContext& context, const CliInfo& cliInfo,
    PermissionDialogDetail& detail)
{
    std::vector<std::string> requiredCliPermissions;
    int32_t ret = ClawPermissionMetadataProvider::GetInstance().GetRequiredCliPermissions(
        cliInfo, requiredCliPermissions);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    detail.permissionNameList.reserve(requiredCliPermissions.size());
    detail.statusList.reserve(requiredCliPermissions.size());
    bool hasNotDeclaredRequiredPermission = false;
    for (const auto& requiredCliPermission : requiredCliPermissions) {
        std::vector<std::string> usedPermissions;
        ret = ClawPermissionMetadataProvider::GetInstance().GetUsedPermissionsByCliPermission(
            requiredCliPermission, usedPermissions);
        if (ret != RET_SUCCESS) {
            return ret;
        }
        PermissionDecisionStatus cliPermissionStatus = context.GetPermissionDecisionStatus(
            requiredCliPermission, PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED);
        if (cliPermissionStatus == PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED) {
            hasNotDeclaredRequiredPermission = true;
            detail.needPermissionDialog = false;
            AppendDialogDetailStatus(detail, requiredCliPermission, cliPermissionStatus);
            continue;
        }
        if (hasNotDeclaredRequiredPermission) {
            continue;
        }
        ret = BuildCliDialogDetailByRequiredPermission(context, requiredCliPermission, detail);
        if (ret != RET_SUCCESS) {
            return ret;
        }
    }
    if (hasNotDeclaredRequiredPermission && HasNotDeclaredStatus(detail)) {
        detail.needPermissionDialog = false;
    }
    return RET_SUCCESS;
}

PermissionDecisionStatus ClawPermissionDecisionEngine::GetCliPermissionResolvedStatus(
    const ClawPermissionDecisionEngine::DecisionContext& context, const std::vector<std::string>& usedPermissions)
{
    for (const auto& usedPermission : usedPermissions) {
        if (context.GetPermissionDecisionStatus(
            usedPermission, PermissionDecisionStatus::NEED_PERMISSION_DIALOG) ==
            PermissionDecisionStatus::NEED_PERMISSION_DIALOG) {
            return PermissionDecisionStatus::NEED_PERMISSION_DIALOG;
        }
    }
    return PermissionDecisionStatus::NO_DIALOG_CLI_PERMISSION_RESOLVED;
}

int32_t ClawPermissionDecisionEngine::BuildCliPermissionDetailByRequiredPermission(
    const ClawPermissionDecisionEngine::DecisionContext& context, const std::string& requiredCliPermission,
    CliPermissionDetail& detail)
{
    detail.requiredCliPermission = requiredCliPermission;
    int32_t ret = ClawPermissionMetadataProvider::GetInstance().GetUsedPermissionsByCliPermission(
        requiredCliPermission, detail.usedPermissions);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    PermissionDecisionStatus notDeclaredStatus = PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED;
    detail.cliPermissionStatus = context.GetPermissionDecisionStatus(requiredCliPermission, notDeclaredStatus);
    if (detail.cliPermissionStatus == PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED) {
        detail.usedPermissions.clear();
        return RET_SUCCESS;
    }
    if (detail.cliPermissionStatus == PermissionDecisionStatus::NEED_PERMISSION_DIALOG) {
        detail.cliPermissionStatus = GetCliPermissionResolvedStatus(context, detail.usedPermissions);
    }
    return RET_SUCCESS;
}

ClawPermissionDecisionEngine::DecisionContext::DecisionContext(AccessTokenID clawTokenId)
    : clawTokenId_(clawTokenId)
{
}

int32_t ClawPermissionDecisionEngine::DecisionContext::Init()
{
    return BuildPermissionStatusMap(clawTokenId_, permissionStatusMap_);
}

PermissionDecisionStatus ClawPermissionDecisionEngine::DecisionContext::GetPermissionDecisionStatus(
    const std::string& permissionName, PermissionDecisionStatus notDeclaredStatus) const
{
    auto iter = permissionStatusMap_.find(permissionName);
    if (iter == permissionStatusMap_.end()) {
        return notDeclaredStatus;
    }

    const PermissionStatus& status = iter->second;
    PermissionDecisionStatus decision = PermissionDecisionStatus::NEED_PERMISSION_DIALOG;
    if (IsGrantedWithoutDialog(status)) {
        decision = PermissionDecisionStatus::NO_DIALOG_GRANTED;
    } else if ((status.grantStatus == PERMISSION_GRANTED) && IsAllowThisTimeFlag(status.grantFlag)) {
        decision = PermissionDecisionStatus::NEED_PERMISSION_DIALOG;
    } else if (IsRestrictedFlag(status.grantFlag)) {
        decision = PermissionDecisionStatus::NO_DIALOG_RESTRICTED;
    } else if (IsUserDeniedFlag(status.grantFlag)) {
        decision = PermissionDecisionStatus::NO_DIALOG_DENIED;
    }
    return decision;
}

bool ClawPermissionDecisionEngine::DecisionContext::HasDialogPermission(
    const std::vector<std::string>& permissions, PermissionDecisionStatus notDeclaredStatus) const
{
    for (const auto& permission : permissions) {
        if (GetPermissionDecisionStatus(permission, notDeclaredStatus) ==
            PermissionDecisionStatus::NEED_PERMISSION_DIALOG) {
            return true;
        }
    }
    return false;
}

ClawPermissionDecisionEngine& ClawPermissionDecisionEngine::GetInstance()
{
    static ClawPermissionDecisionEngine instance;
    return instance;
}

int32_t ClawPermissionDecisionEngine::ValidateClawCliAccess(
    AccessTokenID clawTokenId, const std::vector<CliInfo>& cliInfoList)
{
    int32_t ret = ClawPermissionMetadataProvider::GetInstance().CheckClawCliControlPermission(clawTokenId);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Claw cli control permission check failed, tokenId=%{public}u, ret=%{public}d.",
            clawTokenId, ret);
        return AccessTokenError::ERR_PERMISSION_DENIED;
    }

    std::vector<std::vector<std::string>> cliPermissions;
    ret = ClawPermissionMetadataProvider::GetInstance().GetCliCallablePermissions(cliInfoList, cliPermissions);
    return ret;
}

int32_t ClawPermissionDecisionEngine::BuildCliPermissionDialogInfo(
    AccessTokenID clawTokenId, const std::vector<CliInfo>& cliInfoList, PermissionDialogResult& result)
{
    result.detailList.clear();
    result.detailList.reserve(cliInfoList.size());
    DecisionContext context(clawTokenId);
    int32_t ret = context.Init();
    if (ret != RET_SUCCESS) {
        return ret;
    }

    for (const auto& cliInfo : cliInfoList) {
        PermissionDialogDetail detail;
        ret = BuildCliPermissionDialogDetail(context, cliInfo, detail);
        if (ret != RET_SUCCESS) {
            return ret;
        }
        result.detailList.emplace_back(detail);
    }
    return RET_SUCCESS;
}

int32_t ClawPermissionDecisionEngine::BuildCliPermissions(
    AccessTokenID clawTokenId, const std::vector<CliInfo>& cliInfoList, CliPermissionsResult& result)
{
    result.permList.clear();
    result.permList.reserve(cliInfoList.size());
    DecisionContext context(clawTokenId);
    int32_t ret = context.Init();
    if (ret != RET_SUCCESS) {
        return ret;
    }

    for (const auto& cliInfo : cliInfoList) {
        std::vector<std::string> requiredCliPermissions;
        ret = ClawPermissionMetadataProvider::GetInstance().GetRequiredCliPermissions(
            cliInfo, requiredCliPermissions);
        if (ret != RET_SUCCESS) {
            return ret;
        }

        CliCommandPermissionResult commandResult;
        commandResult.requiredCliPermissions.reserve(requiredCliPermissions.size());
        for (const auto& requiredCliPermission : requiredCliPermissions) {
            CliPermissionDetail detail;
            ret = BuildCliPermissionDetailByRequiredPermission(context, requiredCliPermission, detail);
            if (ret != RET_SUCCESS) {
                return ret;
            }
            commandResult.requiredCliPermissions.emplace_back(detail);
        }
        result.permList.emplace_back(commandResult);
    }
    return RET_SUCCESS;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
