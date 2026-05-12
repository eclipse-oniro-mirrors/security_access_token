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

#include "permission_constraint_check.h"

#include <algorithm>
#include <unordered_set>

#include "accesstoken_common_log.h"
#include "dlp_permission_set_manager.h"
#include "hisysevent_adapter.h"
#include "parameters.h"
#include "permission_feature_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* ENTERPRISE_NORMAL_CHECK = "accesstoken.enterprise_normal_check";
constexpr const char* TEMP_JIT_ALLOW_PERMISSION = "TEMPJITALLOW";
constexpr uint32_t PROCESS_OWNERID_APP = 2;
constexpr uint32_t PROCESS_OWNERID_DEBUG = 3;
constexpr uint32_t PROCESS_OWNERID_COMPAT = 5;
constexpr uint32_t PROCESS_OWNERID_APP_TEMP_ALLOW = 10;
}

bool PermissionConstraintCheck::IsAclSatisfied(const PermissionBriefDef& briefDef, const HapPolicy& policy)
{
#ifdef X86_EMULATOR_MODE
    if (policy.checkIgnore == HapPolicyCheckIgnore::ACL_IGNORE_CHECK) {
        LOGI(ATM_DOMAIN, ATM_TAG, "%{public}s ignore acl check.", briefDef.permissionName);
        return true;
    }
#endif
    if (policy.apl < briefDef.availableLevel) {
        if (!briefDef.provisionEnable) {
            LOGC(ATM_DOMAIN, ATM_TAG, "The provisionEnable of %{public}s is false.", briefDef.permissionName);
            return false;
        }
        bool isAclExist = false;
        if (briefDef.hasValue) {
            isAclExist = std::any_of(policy.aclExtendedMap.begin(), policy.aclExtendedMap.end(),
                [briefDef](const auto& perm) {
                    return std::string(briefDef.permissionName) == perm.first;
                });
        } else {
            isAclExist = std::any_of(policy.aclRequestedList.begin(), policy.aclRequestedList.end(),
                [briefDef](const auto& perm) {
                    return std::string(briefDef.permissionName) == perm;
                });
        }

        if (!isAclExist) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Perm(%{public}s) need acl.", briefDef.permissionName);
            return false;
        }
    }
    return true;
}

bool PermissionConstraintCheck::IsPermAvailableRangeSatisfied(const BundleParam& param,
    const PermissionBriefDef& briefDef, PermissionRulesEnum& rule)
{
    if (briefDef.availableType == ATokenAvailableTypeEnum::MDM) {
        if (param.isDebug) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Debug app use permission: %{public}s.", briefDef.permissionName);
            return true;
        }
#ifdef IS_SUPPORT_HAP_RUNNING
        if (param.distributionType != Verify::AppDistType::ENTERPRISE_MDM) {
            LOGE(ATM_DOMAIN, ATM_TAG, "%{public}s is a mdm permission, the hap is not a mdm application.",
                briefDef.permissionName);
            rule = PERMISSION_EDM_RULE;
            return false;
        }
#endif
    }
    if (briefDef.availableType == ATokenAvailableTypeEnum::ENTERPRISE_NORMAL) {
#ifdef IS_SUPPORT_HAP_RUNNING
        if (param.distributionType == Verify::AppDistType::ENTERPRISE_MDM ||
            param.distributionType == Verify::AppDistType::ENTERPRISE_NORMAL ||
            param.isSystem || param.isDebug) {
            return true;
        }
#endif
        LOGE(ATM_DOMAIN, ATM_TAG,
            "EnterpriseRuleCheck permission = %{public}s bundleName = %{public}s, apiVersion = %{public}d.",
            briefDef.permissionName, param.bundleName.c_str(), param.apiVersion);
        rule = PERMISSION_ENTERPRISE_NORMAL_RULE;
        ReportPermissionVerifyEvent(0, briefDef.permissionName, param.bundleName);

        bool isEnterpriseNormal = OHOS::system::GetBoolParameter(ENTERPRISE_NORMAL_CHECK, false);
        if (isEnterpriseNormal) {
            return false;
        }
    }
    return true;
}

bool PermissionConstraintCheck::AclAndEdmCheck(const BundleParam& param, const PermissionBriefDef& briefDef,
    const HapPolicy& policy, HapInfoCheckResult& result)
{
    if (!IsAclSatisfied(briefDef, policy)) {
        result.permCheckResult.permissionName = briefDef.permissionName;
        result.permCheckResult.rule = PERMISSION_ACL_RULE;
        LOGC(ATM_DOMAIN, ATM_TAG, "Acl of %{public}s is invalid.", briefDef.permissionName);
        return false;
    }

    PermissionRulesEnum rule = PERMISSION_ACL_RULE;
    if (IsPermAvailableRangeSatisfied(param, briefDef, rule)) {
        return true;
    }

    result.permCheckResult.permissionName = briefDef.permissionName;
    result.permCheckResult.rule = rule;
    LOGC(ATM_DOMAIN, ATM_TAG, "Available range of %{public}s is invalid, bundle: %{public}s.",
        briefDef.permissionName, param.bundleName.c_str());
    return false;
}

int PermissionConstraintCheck::BuildIdType(const BundleParam& param, const HapPolicy& policy)
{
    int idType = PROCESS_OWNERID_APP;
    if (param.isDebug) {
        idType = PROCESS_OWNERID_DEBUG;
    } else if (param.appIdentifier == 0) {
        idType = PROCESS_OWNERID_COMPAT;
    } else if (std::any_of(policy.permStateList.begin(), policy.permStateList.end(),
        [](const PermissionStatus& status) {
            return status.permissionName == TEMP_JIT_ALLOW_PERMISSION;
        })) {
        idType = PROCESS_OWNERID_APP_TEMP_ALLOW;
    }
    return idType;
}

void PermissionConstraintCheck::FixBriefPermData(
    const BundleInfoInner& infoInner, int32_t dlpType, std::vector<BriefPermData>& data, bool& isFixed)
{
    isFixed = false;
    std::unordered_set<uint16_t> expectedPermCodes;
    expectedPermCodes.reserve(infoInner.permCodeList.size());
    for (const auto permCode : infoInner.permCodeList) {
        if (dlpType != DLP_COMMON) {
            if (!DlpPermissionSetManager::GetInstance().IsPermissionAvailableToDlpHap(dlpType, permCode)) {
                continue;
            }
        }
        expectedPermCodes.emplace(permCode);
    }
    size_t oldSize = data.size();
    data.erase(std::remove_if(data.begin(), data.end(), [&expectedPermCodes](const BriefPermData& item) {
        return expectedPermCodes.find(item.permCode) == expectedPermCodes.end();
        }), data.end());
    if (data.size() != oldSize) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Remove perms, database maybe untrusted.");
        isFixed = true;
    }

    std::unordered_set<uint16_t> currentPermCodes;
    currentPermCodes.reserve(data.size());
    for (const auto& item : data) {
        currentPermCodes.emplace(item.permCode);
    }

    for (const auto permCode : infoInner.permCodeList) {
        if (expectedPermCodes.find(permCode) == expectedPermCodes.end()) {
            continue;
        }
        if (currentPermCodes.find(permCode) != currentPermCodes.end()) {
            continue;
        }
        BriefPermData initPermData = {0};
        PermissionBriefDef briefDef;
        (void) GetPermissionBriefDef(permCode, briefDef);
        initPermData.permCode = static_cast<uint16_t>(permCode);
        if (briefDef.grantMode == GrantMode::SYSTEM_GRANT) {
            initPermData.status = PERMISSION_GRANTED;
            initPermData.flag = PERMISSION_SYSTEM_FIXED;
        } else {
            initPermData.status = PERMISSION_DENIED;
            initPermData.flag = PERMISSION_DEFAULT_FLAG;
        }
        data.emplace_back(initPermData);
        isFixed = true;
        LOGI(ATM_DOMAIN, ATM_TAG, "Add perm %{public}s, maybe undefined.", briefDef.permissionName);
    }
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
