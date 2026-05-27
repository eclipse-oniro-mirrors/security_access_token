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

#include "hap_sign_verify_helper.h"

#include <cstdlib>
#include <unordered_set>

#include "accesstoken_common_log.h"
#include "cjson_utils.h"
#include "interfaces/hap_verify.h"
#include "permission_data_brief.h"
#include "permission_map.h"
#include "provision/provision_info.h"
#include "spm_module_parser.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* AVAILABLE_LEVEL_SYSTEM_BASIC = "system_basic";
constexpr const char* AVAILABLE_LEVEL_SYSTEM_CORE = "system_core";
constexpr const char* GRANT_MODE_SYSTEM_GRANT = "system_grant";
constexpr const char* GRANT_MODE_MANUAL_SETTINGS = "manual_settings";
constexpr const char* AVAILABLE_TYPE_MDM = "mdm";
static constexpr uint64_t TOKEN_ID_MASK = 0xffffffff;
constexpr const int BASE_10 = 10;
const uint32_t IS_KERNEL_EFFECT = (0x1 << 0);
const uint32_t HAS_VALUE = (0x1 << 1);
}

std::map<std::string, std::string> HapSignVerifyHelper::ParseAclExtendedMap(
    const std::string& appServiceCapabilities)
{
    std::map<std::string, std::string> aclExtendedMap;
    if (appServiceCapabilities.empty()) {
        return aclExtendedMap;
    }

    CJsonUnique jsonBuf = CreateJsonFromString(appServiceCapabilities);
    if (jsonBuf == nullptr || !cJSON_IsObject(jsonBuf.get())) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Parse appServiceCapabilities failed.");
        return aclExtendedMap;
    }

    for (cJSON* child = jsonBuf->child; child != nullptr; child = child->next) {
        if (child->string == nullptr) {
            continue;
        }

        PermissionBriefDef briefDef;
        uint32_t opCode;
        if (!GetPermissionBriefDef(child->string, briefDef, opCode) || !briefDef.isEnable) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Permission %{public}s is invalid or disabled, skip.", child->string);
            continue;
        }

        if (cJSON_IsString(child)) {
            aclExtendedMap[child->string] = child->valuestring;
            continue;
        }

        char* unformattedValue = cJSON_PrintUnformatted(child);
        if (unformattedValue == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to print unformatted JSON for permission %{public}s.", child->string);
            continue;
        }
        aclExtendedMap[child->string] = unformattedValue;
        cJSON_free(unformattedValue);
    }

    return aclExtendedMap;
}

uint64_t HapSignVerifyHelper::BuildOwnerId(const std::string& appIdentifier)
{
    if (appIdentifier.empty()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Build ownerId failed, appIdentifier is empty.");
        return 0;
    }

    char* end = nullptr;
    uint64_t ownerId = std::strtoull(appIdentifier.c_str(), &end, BASE_10);
    if ((end == nullptr) || (*end != '\0')) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build ownerId failed, invalid appIdentifier=%{public}s.",
            appIdentifier.c_str());
        return 0;
    }
    return ownerId;
}

AccessTokenID HapSignVerifyHelper::GetTokenId(uint64_t tokenIdEx)
{
    return static_cast<AccessTokenID>(tokenIdEx & TOKEN_ID_MASK);
}

ATokenAplEnum HapSignVerifyHelper::ConvertApl(const std::string& apl)
{
    if (apl == AVAILABLE_LEVEL_SYSTEM_CORE) {
        return APL_SYSTEM_CORE;
    }
    if (apl == AVAILABLE_LEVEL_SYSTEM_BASIC) {
        return APL_SYSTEM_BASIC;
    }
    return APL_NORMAL;
}

int HapSignVerifyHelper::ConvertGrantMode(const std::string& grantMode)
{
    if (grantMode == GRANT_MODE_SYSTEM_GRANT) {
        return GrantMode::SYSTEM_GRANT;
    }
    if (grantMode == GRANT_MODE_MANUAL_SETTINGS) {
        return GrantMode::MANUAL_SETTINGS;
    }
    return GrantMode::USER_GRANT;
}

ATokenAvailableTypeEnum HapSignVerifyHelper::ConvertAvailableType(const std::string& availableType)
{
    return availableType == AVAILABLE_TYPE_MDM ? ATokenAvailableTypeEnum::MDM : ATokenAvailableTypeEnum::NORMAL;
}

void HapSignVerifyHelper::FillPermissionDefList(const std::vector<TrustedBundleInfoInner>& sortedInfos,
    std::vector<PermissionDef>& permList)
{
    permList.clear();
    if (sortedInfos.empty()) {
        return;
    }

    const std::string bundleName = sortedInfos.front().GetBundleName();
    std::unordered_set<std::string> dedupPermissionNames;
    for (const auto& info : sortedInfos) {
        for (const auto& definePermission : info.moduleData.definePermission) {
            if (definePermission.name.empty() || !dedupPermissionNames.emplace(definePermission.name).second) {
                continue;
            }
            PermissionDef permissionDef;
            permissionDef.permissionName = definePermission.name;
            permissionDef.bundleName = bundleName;
            permissionDef.grantMode = ConvertGrantMode(definePermission.grantMode);
            permissionDef.availableLevel = ConvertApl(definePermission.availableLevel);
            permissionDef.provisionEnable = definePermission.provisionEnable;
            permissionDef.distributedSceneEnable = definePermission.distributedSceneEnable;
            permissionDef.isKernelEffect = definePermission.isKernelEffect;
            permissionDef.hasValue = definePermission.hasValue;
            permissionDef.label = definePermission.label;
            permissionDef.labelId = static_cast<int>(definePermission.labelId);
            permissionDef.description = definePermission.description;
            permissionDef.descriptionId = static_cast<int>(definePermission.descriptionId);
            permissionDef.availableType = ConvertAvailableType(definePermission.availableType);
            permList.emplace_back(permissionDef);
        }
    }
}

void HapSignVerifyHelper::FillAclRequestedList(const std::vector<TrustedBundleInfoInner>& sortedInfos,
    std::vector<std::string>& aclRequestedList)
{
    aclRequestedList.clear();
    std::unordered_set<std::string> dedupAclNames;
    for (const auto& info : sortedInfos) {
        for (const auto& aclName : info.provisionInfo.acls.allowedAcls) {
            if (aclName.empty() || !dedupAclNames.emplace(aclName).second) {
                continue;
            }
            aclRequestedList.emplace_back(aclName);
        }
    }
}

void HapSignVerifyHelper::FillAclExtendedMap(const std::vector<TrustedBundleInfoInner>& sortedInfos,
    std::map<std::string, std::string>& aclExtendedMap)
{
    aclExtendedMap.clear();
    if (sortedInfos.empty()) {
        return;
    }
    aclExtendedMap = ParseAclExtendedMap(sortedInfos.front().provisionInfo.appServiceCapabilities);
}

void HapSignVerifyHelper::FillPermissionStateList(const std::vector<TrustedBundleInfoInner>& sortedInfos,
    std::vector<PermissionStatus>& permStateList)
{
    permStateList.clear();
    std::unordered_set<std::string> dedupPermissionNames;
    for (const auto& info : sortedInfos) {
        for (const auto& requestPermission : info.moduleData.requestPermission) {
            if (requestPermission.name.empty() || !dedupPermissionNames.emplace(requestPermission.name).second) {
                continue;
            }
            PermissionStatus state;
            state.permissionName = requestPermission.name;
            state.grantStatus = PERMISSION_DENIED;
            state.grantFlag = PERMISSION_DEFAULT_FLAG;
            state.feature = requestPermission.requiredFeature;
            permStateList.emplace_back(state);
        }
    }
}

void HapSignVerifyHelper::BuildPermBriefDataListFromPolicy(const HapPolicy& policy,
    std::vector<BriefPermData>& permBriefDataList)
{
    for (const auto& permState : policy.permStateList) {
        uint32_t opCode;
        PermissionBriefDef briefDef;
        if (!GetPermissionBriefDef(permState.permissionName, briefDef, opCode) || !briefDef.isEnable) {
            continue;
        }

        BriefPermData data = {};
        data.permCode = static_cast<uint16_t>(opCode);
        data.status = static_cast<int8_t>(permState.grantStatus);
        data.flag = permState.grantFlag;
        if (briefDef.isKernelEffect) {
            data.type = IS_KERNEL_EFFECT;
        }
        if (briefDef.hasValue) {
            data.type |= HAS_VALUE;
        }
        permBriefDataList.emplace_back(data);
    }
}

void HapSignVerifyHelper::BuildExtendPermListFromPolicy(const HapPolicy& policy,
    std::vector<PermissionWithValue>& extendPermList)
{
    for (const auto& [permName, value] : policy.aclExtendedMap) {
        PermissionWithValue perm;
        perm.permissionName = permName;
        perm.value = value;
        extendPermList.emplace_back(perm);
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
