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

#include "accesstoken_info_utils.h"

#include <unordered_set>

#include "permission_constraint_check.h"
#include "permission_feature_manager.h"
#include "permission_map.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const char* SYSTEM_RESOURCE_BUNDLE_NAME = "ohos.global.systemres";
static const uint32_t SYSTEM_APP_FLAG = 0x0001;
static const uint32_t ATOMIC_SERVICE_FLAG = 0x0002;
static const uint32_t DEBUG_APP_FLAG = 0x0008;
static constexpr int32_t BASE_USER_RANGE = 200000;
}

bool AccessTokenInfoUtils::IsSystemResource(const std::string& bundleName)
{
    return std::string(SYSTEM_RESOURCE_BUNDLE_NAME) == bundleName;
}

bool AccessTokenInfoUtils::CheckSpecifiedFlag(uint32_t tokenAttr, uint32_t flag)
{
    return (tokenAttr & flag) != 0;
}

std::string AccessTokenInfoUtils::GetHapUniqueStr(
    int32_t userID, const std::string& bundleName, int32_t instIndex)
{
    return bundleName + "&" + std::to_string(userID) + "&" + std::to_string(instIndex);
}

std::string AccessTokenInfoUtils::GetHapUniqueStr(const std::shared_ptr<HapTokenInfoInner>& info)
{
    if (info == nullptr) {
        return std::string("");
    }
    return GetHapUniqueStr(info->GetUserID(), info->GetBundleName(), info->GetInstIndex());
}

void AccessTokenInfoUtils::GenerateAddInfoToVec(
    AtmDataType type, const std::vector<GenericValues>& addValues, std::vector<AddInfo>& addInfoVec)
{
    AddInfo addInfo;
    addInfo.addType = type;
    addInfo.addValues = addValues;
    addInfoVec.emplace_back(addInfo);
}

void AccessTokenInfoUtils::GenerateDelInfoToVec(
    AtmDataType type, const GenericValues& delValue, std::vector<DelInfo>& delInfoVec)
{
    DelInfo delInfo;
    delInfo.delType = type;
    delInfo.delValue = delValue;
    delInfoVec.emplace_back(delInfo);
}

void AccessTokenInfoUtils::AddTokenIdToUndefValues(AccessTokenID tokenId, std::vector<GenericValues>& undefValues)
{
    for (auto& value : undefValues) {
        value.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    }
}

void AccessTokenInfoUtils::BuildHapTokenInfo(const Identity& id, const BundleParam& param, HapTokenInfo& info)
{
    uint32_t apiSize = 3; // 3: api version length
    std::string apiStr = std::to_string(param.apiVersion);
    uint32_t inputSize = apiStr.length();

    info = {};
    info.tokenID = static_cast<AccessTokenID>(id.tokenId & 0xffffffff);
    info.userID = id.uid / BASE_USER_RANGE;
    info.ver = DEFAULT_TOKEN_VERSION;
    info.tokenAttr = 0;
    if (param.isSystem) {
        info.tokenAttr |= SYSTEM_APP_FLAG;
    }
    if (param.isAtomicService) {
        info.tokenAttr |= ATOMIC_SERVICE_FLAG;
    }
    if (param.isDebug) {
        info.tokenAttr |= DEBUG_APP_FLAG;
    }
    info.bundleName = param.bundleName;
    info.apiVersion = (inputSize <= apiSize) ? param.apiVersion : std::atoi(apiStr.substr(inputSize - apiSize).c_str());
    info.instIndex = 0;
    info.dlpType = DLP_COMMON;
    info.uid = id.uid;
}

void AccessTokenInfoUtils::BuildBundleFullInfo(const BundleParam& param, const HapPolicy& policy,
    std::shared_ptr<BundleInfoInner>& innerInfo, BundleNoCachedInfo& noCached)
{
    if (innerInfo == nullptr) {
        innerInfo = std::make_shared<BundleInfoInner>();
    }
    innerInfo->permCodeList.clear();
    innerInfo->tokenIds.clear();
    noCached.apl = policy.apl;
    noCached.distributionType = param.distributionType;
    noCached.idType = static_cast<uint32_t>(PermissionConstraintCheck::BuildIdType(param, policy));
    noCached.ownerid = param.appIdentifier;

    std::unordered_set<uint32_t> permCodeSet;
    for (const auto& status : policy.permStateList) {
        if (param.isSystem && !PermissionFeatureManager::GetInstance().IsSupportFeature(status)) {
            continue;
        }
        PermissionBriefDef briefDef;
        if (!GetPermissionBriefDef(status.permissionName, briefDef)) {
            continue;
        }
        if (!PermissionConstraintCheck::IsAclSatisfied(briefDef, policy)) {
            continue;
        }

        PermissionRulesEnum rule = PERMISSION_ACL_RULE;
        if (!PermissionConstraintCheck::IsPermAvailableRangeSatisfied(param, briefDef, rule)) {
            continue;
        }

        uint32_t permCode = 0;
        if (!TransferPermissionToOpcode(status.permissionName, permCode)) {
            continue;
        }
        uint16_t shortPermCode = static_cast<uint16_t>(permCode);
        if (permCodeSet.insert(permCode).second) {
            innerInfo->permCodeList.emplace_back(shortPermCode);
        }
    }
}

ReservedType AccessTokenInfoUtils::GetReservedTokenTypeDBValue(const GenericValues& values)
{
#ifdef SPM_DATA_ENABLE
    return static_cast<ReservedType>(values.GetInt(TokenFiledConst::FIELD_RESERVED));
#else
    if (AccessTokenInfoUtils::CheckSpecifiedFlag(
        values.GetInt(TokenFiledConst::FIELD_TOKEN_ATTR), 0x0004)) { // 0x0004: reserved
        return ReservedType::RESERVED_IDENTITY;
    }
    return ReservedType::NONE;
#endif
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
