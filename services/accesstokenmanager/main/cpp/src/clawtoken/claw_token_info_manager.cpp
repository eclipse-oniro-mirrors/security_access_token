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

#include "claw_token_info_manager.h"

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "cli_token_info_inner.h"
#include "claw_ticket_manager.h"
#include "data_validator.h"
#include "hap_token_info.h"
#include "permission_map.h"
#include "permission_manager.h"
#include "permission_validator.h"
#include "skill_token_info_inner.h"
#include "tokenid_attributes.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
const static int MAX_CHALLENGE_LENGTH = 40960;
ATokenTypeEnum GetTokenTypeByToolType(ToolTokenType toolType)
{
    return (toolType == ToolTokenType::CLI) ? TOKEN_SHELL : TOKEN_HAP;
}

void BuildGrantedKernelPermList(ToolTokenType toolType, const std::vector<PermissionStatus>& permStateList,
    std::vector<std::string>& kernelPermList)
{
    kernelPermList.clear();
    const auto tokenType = GetTokenTypeByToolType(toolType);
    std::vector<PermissionStatus> validPermStateList;
    PermissionValidator::FilterInvalidPermissionState(tokenType, true, permStateList, validPermStateList);
    for (const auto& permState : validPermStateList) {
        if (permState.grantStatus != PERMISSION_GRANTED) {
            continue;
        }
        PermissionBriefDef briefDef;
        if (!GetPermissionBriefDef(permState.permissionName, briefDef) || !briefDef.isKernelEffect) {
            continue;
        }
        kernelPermList.emplace_back(permState.permissionName);
    }
}

void BuildPermStatusList(ToolTokenType toolType, const std::vector<PermissionStatus>& permStateList,
    std::vector<uint32_t>& opCodeList, std::vector<bool>& statusList)
{
    opCodeList.clear();
    statusList.clear();
    const auto tokenType = GetTokenTypeByToolType(toolType);
    std::vector<PermissionStatus> validPermStateList;
    PermissionValidator::FilterInvalidPermissionState(tokenType, true, permStateList, validPermStateList);
    for (const auto& permState : validPermStateList) {
        uint32_t opCode = 0;
        if (!TransferPermissionToOpcode(permState.permissionName, opCode)) {
            continue;
        }
        opCodeList.emplace_back(opCode);
        statusList.emplace_back(permState.grantStatus == PERMISSION_GRANTED);
    }
}
}

ToolTokenInfoManager& ToolTokenInfoManager::GetInstance()
{
    static ToolTokenInfoManager instance;
    return instance;
}

bool ToolTokenInfoManager::CheckCliInfo(const CliInfo& info) const
{
    if (!DataValidator::IsProcessNameValid(info.cliName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid cliName, cliName=%{public}s.", info.cliName.c_str());
        return false;
    }
    if (!info.subCliName.empty() && info.subCliName.length() > MAX_CHALLENGE_LENGTH) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Invalid subCliName, cliName=%{public}s, subCliName=%{public}s, info.subCliName.length()=%{public}d.",
            info.cliName.c_str(), info.subCliName.c_str(), info.subCliName.length());
        return false;
    }
    return true;
}

bool ToolTokenInfoManager::CheckSkillInfo(const SkillInfo& info) const
{
    if (!DataValidator::IsBundleNameValid(info.bundleName) ||
        !DataValidator::IsBundleNameValid(info.moduleName) ||
        !DataValidator::IsBundleNameValid(info.skillName)) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Invalid skill info, bundleName=%{public}s, moduleName=%{public}s, skillName=%{public}s.",
            info.bundleName.c_str(), info.moduleName.c_str(), info.skillName.c_str());
        return false;
    }
    return true;
}

bool CheckToolInitCommonInput(AccessTokenID hostTokenId, const std::string& challenge)
{
    if (hostTokenId == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid hostTokenId, hostTokenId=%{public}u.", hostTokenId);
        return false;
    }
    if (!challenge.empty() && !DataValidator::IsProcessNameValid(challenge)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid challenge, hostTokenId=%{public}u, challenge=%{public}s.",
            hostTokenId, challenge.c_str());
        return false;
    }
    return true;
}

int32_t ToolTokenInfoManager::GetUserIdByHostTokenId(AccessTokenID hostTokenId, int32_t& userId) const
{
    HapTokenInfo hapTokenInfo;
    int32_t ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(hostTokenId, hapTokenInfo);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetHapTokenInfo failed, hostTokenId=%{public}u, ret=%{public}d.",
            hostTokenId, ret);
        return ret;
    }
    userId = hapTokenInfo.userID;
    return RET_SUCCESS;
}

AccessTokenIDEx ToolTokenInfoManager::CreateToolTokenId(ToolTokenType type) const
{
    AccessTokenIDEx tokenIdEx = {0};
    const auto tokenType = (type == ToolTokenType::CLI) ? TOKEN_SHELL : TOKEN_HAP;
    AccessTokenID tokenId = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(tokenType, 0, 0, 1);
    if (tokenId == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG, "CreateAndRegisterTokenId failed, toolType=%{public}u, tokenType=%{public}u.",
            static_cast<uint32_t>(type), static_cast<uint32_t>(tokenType));
        return tokenIdEx;
    }
    tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    tokenIdEx.tokenIdExStruct.tokenAttr = 0;
    return tokenIdEx;
}

int32_t ToolTokenInfoManager::AddToolTokenInfoLocked(const std::shared_ptr<ClawTokenInfoInnerBase>& inner)
{
    if (inner == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Inner is nullptr when add tool token info.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    const int32_t callerPid = inner->GetCallerPid();
    if (callerPid < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Invalid callerPid, callerPid=%{public}d.", callerPid);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (pidToolTokenMap_.count(callerPid) > 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Tool token already exists, callerPid=%{public}d, existTokenId=%{public}u.",
            callerPid, pidToolTokenMap_[callerPid]);
        return AccessTokenError::ERR_TOOL_TOKEN_ALREADY_EXIST;
    }
    const AccessTokenID tokenId = inner->GetTokenId();
    const AccessTokenID hostTokenId = inner->GetHostTokenId();
    toolTokenInfoMap_[tokenId] = inner;
    hostToolTokenMap_[hostTokenId].insert(tokenId);
    pidToolTokenMap_[callerPid] = tokenId;
    return RET_SUCCESS;
}

std::shared_ptr<ClawTokenInfoInnerBase> ToolTokenInfoManager::RemoveToolTokenInfoLocked(AccessTokenID tokenId)
{
    auto iter = toolTokenInfoMap_.find(tokenId);
    if (iter == toolTokenInfoMap_.end()) {
        return nullptr;
    }

    std::shared_ptr<ClawTokenInfoInnerBase> inner = iter->second;
    toolTokenInfoMap_.erase(iter);
    if (inner == nullptr) {
        return inner;
    }

    const AccessTokenID hostTokenId = inner->GetHostTokenId();
    auto ownerIter = hostToolTokenMap_.find(hostTokenId);
    if (ownerIter != hostToolTokenMap_.end()) {
        ownerIter->second.erase(tokenId);
        if (ownerIter->second.empty()) {
            hostToolTokenMap_.erase(ownerIter);
        }
    }
    const int32_t callerPid = inner->GetCallerPid();
    auto pidIter = pidToolTokenMap_.find(callerPid);
    if (pidIter != pidToolTokenMap_.end() && pidIter->second == tokenId) {
        pidToolTokenMap_.erase(pidIter);
    }
    return inner;
}

std::shared_ptr<ClawTokenInfoInnerBase> ToolTokenInfoManager::RemoveToolTokenInfoByPidLocked(int32_t pid)
{
    auto iter = pidToolTokenMap_.find(pid);
    if (iter == pidToolTokenMap_.end()) {
        return nullptr;
    }
    return RemoveToolTokenInfoLocked(iter->second);
}

int32_t ToolTokenInfoManager::InitCliToken(const CliInitInfo& info, int32_t callerPid, AccessTokenIDEx& tokenIdEx,
    std::vector<std::string>& kernelPermList)
{
    std::vector<PermissionStatus> permStateList;
    int32_t ret = VerifyCliInitInputAndTicket(info, callerPid, permStateList);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    ClawTokenBaseInfo baseInfo;
    ret = BuildToolTokenBaseInfo(
        info.hostTokenId, callerPid, ToolTokenType::CLI, info.challenge, tokenIdEx, baseInfo);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    auto inner = std::make_shared<CliTokenInfoInner>();
    ret = inner->Init(baseInfo, info.cliInfo, permStateList);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "CliTokenInfoInner init failed, hostTokenId=%{public}u, callerPid=%{public}d, tokenId=%{public}u.",
            info.hostTokenId, callerPid, baseInfo.tokenId);
        AccessTokenIDManager::GetInstance().ReleaseTokenId(baseInfo.tokenId);
        return ret;
    }
    return FinalizeToolTokenInit(inner, baseInfo, permStateList, kernelPermList);
}

int32_t ToolTokenInfoManager::InitSkillToken(const SkillInitInfo& info, int32_t callerPid,
    AccessTokenIDEx& tokenIdEx, std::vector<std::string>& kernelPermList)
{
    std::vector<PermissionStatus> permStateList;
    int32_t ret = VerifySkillInitInputAndTicket(info, callerPid, permStateList);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    ClawTokenBaseInfo baseInfo;
    ret = BuildToolTokenBaseInfo(
        info.hostTokenId, callerPid, ToolTokenType::SKILL, info.challenge, tokenIdEx, baseInfo);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    auto inner = std::make_shared<SkillTokenInfoInner>();
    ret = inner->Init(baseInfo, info.skillInfo, permStateList);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "SkillTokenInfoInner init failed, hostTokenId=%{public}u, callerPid=%{public}d, tokenId=%{public}u.",
            info.hostTokenId, callerPid, baseInfo.tokenId);
        AccessTokenIDManager::GetInstance().ReleaseTokenId(baseInfo.tokenId);
        return ret;
    }
    return FinalizeToolTokenInit(inner, baseInfo, permStateList, kernelPermList);
}

int32_t ToolTokenInfoManager::VerifyCliInitInputAndTicket(const CliInitInfo& info, int32_t callerPid,
    std::vector<PermissionStatus>& permStateList) const
{
    if (!CheckCliInfo(info.cliInfo) || !CheckToolInitCommonInput(info.hostTokenId, info.challenge)) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "InitCliToken input invalid, hostTokenId=%{public}u, callerPid=%{public}d, challenge=%{public}s, "
            "cliName=%{public}s, subCliName=%{public}s.",
            info.hostTokenId, callerPid, info.challenge.c_str(), info.cliInfo.cliName.c_str(),
            info.cliInfo.subCliName.c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(
        info.hostTokenId, info.challenge, info.cliInfo, permStateList);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "VerifyCliClawTicket failed, hostTokenId=%{public}u, callerPid=%{public}d, challenge=%{public}s, "
            "cliName=%{public}s, subCliName=%{public}s, ret=%{public}d.",
            info.hostTokenId, callerPid, info.challenge.c_str(), info.cliInfo.cliName.c_str(),
            info.cliInfo.subCliName.c_str(), ret);
    }
    return ret;
}

int32_t ToolTokenInfoManager::VerifySkillInitInputAndTicket(const SkillInitInfo& info, int32_t callerPid,
    std::vector<PermissionStatus>& permStateList) const
{
    if (!CheckSkillInfo(info.skillInfo) || !CheckToolInitCommonInput(info.hostTokenId, info.challenge)) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "InitSkillToken input invalid, hostTokenId=%{public}u, callerPid=%{public}d, challenge=%{public}s, "
            "bundleName=%{public}s, moduleName=%{public}s, skillName=%{public}s.",
            info.hostTokenId, callerPid, info.challenge.c_str(), info.skillInfo.bundleName.c_str(),
            info.skillInfo.moduleName.c_str(), info.skillInfo.skillName.c_str());
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    int32_t ret = ClawTicketManager::GetInstance().VerifySkillClawTicket(
        info.hostTokenId, info.challenge, info.skillInfo, permStateList);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "VerifySkillClawTicket failed, hostTokenId=%{public}u, callerPid=%{public}d, challenge=%{public}s, "
            "bundleName=%{public}s, moduleName=%{public}s, skillName=%{public}s, ret=%{public}d.",
            info.hostTokenId, callerPid, info.challenge.c_str(), info.skillInfo.bundleName.c_str(),
            info.skillInfo.moduleName.c_str(), info.skillInfo.skillName.c_str(), ret);
    }
    return ret;
}

int32_t ToolTokenInfoManager::BuildToolTokenBaseInfo(AccessTokenID hostTokenId, int32_t callerPid, ToolTokenType type,
    const std::string& challenge, AccessTokenIDEx& tokenIdEx, ClawTokenBaseInfo& baseInfo) const
{
    int32_t userId = 0;
    int32_t ret = GetUserIdByHostTokenId(hostTokenId, userId);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetUserIdByHostTokenId failed, hostTokenId=%{public}u, toolType=%{public}u, ret=%{public}d.",
            hostTokenId, static_cast<uint32_t>(type), ret);
        return ret;
    }
    tokenIdEx = CreateToolTokenId(type);
    if (tokenIdEx.tokenIdExStruct.tokenID == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "CreateToolTokenId failed, hostTokenId=%{public}u, callerPid=%{public}d, toolType=%{public}u.",
            hostTokenId, callerPid, static_cast<uint32_t>(type));
        return AccessTokenError::ERR_TOKENID_CREATE_FAILED;
    }
    baseInfo = { type, hostTokenId, userId, callerPid, tokenIdEx.tokenIdExStruct.tokenID,
        tokenIdEx.tokenIdExStruct.tokenAttr, challenge };
    return RET_SUCCESS;
}

int32_t ToolTokenInfoManager::FinalizeToolTokenInit(const std::shared_ptr<ClawTokenInfoInnerBase>& inner,
    const ClawTokenBaseInfo& baseInfo, const std::vector<PermissionStatus>& permStateList,
    std::vector<std::string>& kernelPermList)
{
    int32_t ret = RET_SUCCESS;
    {
        std::unique_lock<std::shared_mutex> lock(lock_);
        ret = AddToolTokenInfoLocked(inner);
    }
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AddToolTokenInfoLocked failed, hostTokenId=%{public}u, callerPid=%{public}d, "
            "tokenId=%{public}u, toolType=%{public}u, ret=%{public}d.", baseInfo.hostTokenId, baseInfo.callerPid,
            baseInfo.tokenId, static_cast<uint32_t>(baseInfo.toolType), ret);
        AccessTokenIDManager::GetInstance().ReleaseTokenId(baseInfo.tokenId);
        return ret;
    }
    (void)ClawTicketManager::GetInstance().DeleteClawTicket(baseInfo.challenge);
    std::vector<uint32_t> opCodeList;
    std::vector<bool> statusList;
    BuildGrantedKernelPermList(baseInfo.toolType, permStateList, kernelPermList);
    BuildPermStatusList(baseInfo.toolType, permStateList, opCodeList, statusList);
    PermissionManager::GetInstance().AddNativePermToKernel(baseInfo.tokenId, opCodeList, statusList);
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenId=%{public}u, hostTokenId=%{public}u.",
        baseInfo.tokenId, baseInfo.hostTokenId);
    for (size_t i = 0; i < permStateList.size(); ++i) {
        LOGI(ATM_DOMAIN, ATM_TAG,
            "AddToolTokenInfoLocked permStateList[%{public}zu]: permissionName=%{public}s, grantStatus=%{public}d.",
            i, permStateList[i].permissionName.c_str(), permStateList[i].grantStatus);
    }
    return RET_SUCCESS;
}

int32_t ToolTokenInfoManager::DeleteToolTokenByPid(int32_t pid)
{
    std::shared_ptr<ClawTokenInfoInnerBase> inner;
    AccessTokenID tokenId = INVALID_TOKENID;
    {
        std::unique_lock<std::shared_mutex> lock(lock_);
        inner = RemoveToolTokenInfoByPidLocked(pid);
        if (inner == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Tool token not exist when delete, pid=%{public}d.", pid);
            return AccessTokenError::ERR_TOKENID_NOT_EXIST;
        }
        tokenId = inner->GetTokenId();
    }
    PermissionManager::GetInstance().RemovePermFromKernel(tokenId);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
    return RET_SUCCESS;
}

bool ToolTokenInfoManager::IsToolToken(AccessTokenID tokenId) const
{
    std::shared_lock<std::shared_mutex> lock(lock_);
    return toolTokenInfoMap_.count(tokenId) > 0;
}

int32_t ToolTokenInfoManager::GetHostTokenId(AccessTokenID toolTokenId, AccessTokenID& hostTokenId) const
{
    if (!TokenIDAttributes::IsToolTokenId(toolTokenId)) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Token is not a tool token when get host token, toolTokenId=%{public}u, tokenType=%{public}u.",
            toolTokenId, static_cast<uint32_t>(TokenIDAttributes::GetTokenIdTypeEnum(toolTokenId)));
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    std::shared_lock<std::shared_mutex> lock(lock_);
    auto iter = toolTokenInfoMap_.find(toolTokenId);
    if (iter == toolTokenInfoMap_.end() || iter->second == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Tool token info not found when get host token, toolTokenId=%{public}u, mapSize=%{public}zu.",
            toolTokenId, toolTokenInfoMap_.size());
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    hostTokenId = iter->second->GetHostTokenId();
    if (hostTokenId == INVALID_TOKENID) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Host token invalid when get host token, toolTokenId=%{public}u, hostTokenId=%{public}u.",
            toolTokenId, hostTokenId);
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    return RET_SUCCESS;
}

int32_t ToolTokenInfoManager::VerifyToolAccessToken(AccessTokenID tokenId, const std::string& permissionName) const
{
    std::shared_ptr<ClawTokenInfoInnerBase> inner;
    {
        std::shared_lock<std::shared_mutex> lock(lock_);
        auto iter = toolTokenInfoMap_.find(tokenId);
        if (iter == toolTokenInfoMap_.end()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Tool token not found, tokenId=%{public}u, permissionName=%{public}s.",
                tokenId, permissionName.c_str());
            return PERMISSION_DENIED;
        }
        inner = iter->second;
    }
    return inner->VerifyAccessToken(permissionName);
}

int32_t ToolTokenInfoManager::GetCliTokenInfo(AccessTokenID tokenId, CliTokenInfo& info) const
{
    std::shared_lock<std::shared_mutex> lock(lock_);
    auto iter = toolTokenInfoMap_.find(tokenId);
    if (iter == toolTokenInfoMap_.end() || iter->second == nullptr ||
        iter->second->GetType() != ToolTokenType::CLI) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Cli tool token info not found, tokenId=%{public}u.", tokenId);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    std::static_pointer_cast<CliTokenInfoInner>(iter->second)->GetTokenInfo(info);
    return RET_SUCCESS;
}

int32_t ToolTokenInfoManager::GetSkillTokenInfo(AccessTokenID tokenId, SkillTokenInfo& info) const
{
    std::shared_lock<std::shared_mutex> lock(lock_);
    auto iter = toolTokenInfoMap_.find(tokenId);
    if (iter == toolTokenInfoMap_.end() || iter->second == nullptr ||
        iter->second->GetType() != ToolTokenType::SKILL) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Skill tool token info not found, tokenId=%{public}u.", tokenId);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    std::static_pointer_cast<SkillTokenInfoInner>(iter->second)->GetTokenInfo(info);
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
