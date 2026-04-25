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

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {

ATokenTypeEnum GetTokenTypeByClawType(ClawTokenType clawType)
{
    return (clawType == ClawTokenType::CLI) ? TOKEN_SHELL : TOKEN_HAP;
}

void BuildGrantedKernelPermList(ClawTokenType clawType, const std::vector<PermissionStatus>& permStateList,
    std::vector<std::string>& kernelPermList)
{
    kernelPermList.clear();
    const auto tokenType = GetTokenTypeByClawType(clawType);
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

void BuildPermStatusList(ClawTokenType clawType, const std::vector<PermissionStatus>& permStateList,
    std::vector<uint32_t>& opCodeList, std::vector<bool>& statusList)
{
    opCodeList.clear();
    statusList.clear();
    const auto tokenType = GetTokenTypeByClawType(clawType);
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

ClawTokenInfoManager& ClawTokenInfoManager::GetInstance()
{
    static ClawTokenInfoManager instance;
    return instance;
}

bool ClawTokenInfoManager::CheckCliInfo(const CliInfo& info) const
{
    if (!DataValidator::IsProcessNameValid(info.cliName)) {
        return false;
    }
    if (!info.subCliName.empty() && !DataValidator::IsProcessNameValid(info.subCliName)) {
        return false;
    }
    return true;
}

bool ClawTokenInfoManager::CheckSkillInfo(const SkillInfo& info) const
{
    if (!DataValidator::IsBundleNameValid(info.bundleName) ||
        !DataValidator::IsBundleNameValid(info.moduleName) ||
        !DataValidator::IsBundleNameValid(info.skillName)) {
        return false;
    }
    return true;
}

bool CheckClawInitCommonInput(AccessTokenID hostTokenId, const std::string& challenge)
{
    if (hostTokenId == INVALID_TOKENID) {
        return false;
    }
    if (!DataValidator::IsProcessNameValid(challenge)) {
        return false;
    }
    return true;
}

int32_t ClawTokenInfoManager::GetUserIdByHostTokenId(AccessTokenID hostTokenId, int32_t& userId) const
{
    HapTokenInfo hapTokenInfo;
    int32_t ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(hostTokenId, hapTokenInfo);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    userId = hapTokenInfo.userID;
    return RET_SUCCESS;
}

AccessTokenIDEx ClawTokenInfoManager::CreateClawTokenId(ClawTokenType type) const
{
    AccessTokenIDEx tokenIdEx = {0};
    const auto tokenType = (type == ClawTokenType::CLI) ? TOKEN_SHELL : TOKEN_HAP;
    AccessTokenID tokenId = AccessTokenIDManager::GetInstance().CreateAndRegisterTokenId(tokenType, 0, 0);
    if (tokenId == INVALID_TOKENID) {
        return tokenIdEx;
    }
    tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    tokenIdEx.tokenIdExStruct.tokenAttr = 0;
    return tokenIdEx;
}

int32_t ClawTokenInfoManager::AddClawTokenInfoLocked(const std::shared_ptr<ClawTokenInfoInnerBase>& inner)
{
    if (inner == nullptr) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    const int32_t callerPid = inner->GetCallerPid();
    if (callerPid < 0) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (pidClawTokenMap_.count(callerPid) > 0) {
        return AccessTokenError::ERR_CLAW_TOKEN_ALREADY_EXIST;
    }
    const AccessTokenID tokenId = inner->GetTokenId();
    const AccessTokenID hostTokenId = inner->GetHostTokenId();
    clawTokenInfoMap_[tokenId] = inner;
    ownerClawTokenMap_[hostTokenId].insert(tokenId);
    pidClawTokenMap_[callerPid] = tokenId;
    return RET_SUCCESS;
}

std::shared_ptr<ClawTokenInfoInnerBase> ClawTokenInfoManager::RemoveClawTokenInfoLocked(AccessTokenID tokenId)
{
    auto iter = clawTokenInfoMap_.find(tokenId);
    if (iter == clawTokenInfoMap_.end()) {
        return nullptr;
    }

    std::shared_ptr<ClawTokenInfoInnerBase> inner = iter->second;
    clawTokenInfoMap_.erase(iter);
    if (inner == nullptr) {
        return inner;
    }

    const AccessTokenID hostTokenId = inner->GetHostTokenId();
    auto ownerIter = ownerClawTokenMap_.find(hostTokenId);
    if (ownerIter != ownerClawTokenMap_.end()) {
        ownerIter->second.erase(tokenId);
        if (ownerIter->second.empty()) {
            ownerClawTokenMap_.erase(ownerIter);
        }
    }
    const int32_t callerPid = inner->GetCallerPid();
    auto pidIter = pidClawTokenMap_.find(callerPid);
    if (pidIter != pidClawTokenMap_.end() && pidIter->second == tokenId) {
        pidClawTokenMap_.erase(pidIter);
    }
    return inner;
}

std::shared_ptr<ClawTokenInfoInnerBase> ClawTokenInfoManager::RemoveClawTokenInfoByPidLocked(int32_t pid)
{
    auto iter = pidClawTokenMap_.find(pid);
    if (iter == pidClawTokenMap_.end()) {
        return nullptr;
    }
    return RemoveClawTokenInfoLocked(iter->second);
}

int32_t ClawTokenInfoManager::InitCliToken(const CliInitInfo& info, int32_t callerPid, AccessTokenIDEx& tokenIdEx,
    std::vector<std::string>& kernelPermList)
{
    if (!CheckCliInfo(info.cliInfo) || !CheckClawInitCommonInput(info.hostTokenId, info.challenge)) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    std::vector<PermissionStatus> permStateList;
    int32_t ret = ClawTicketManager::GetInstance().VerifyCliClawTicket(
        info.hostTokenId, info.challenge, info.cliInfo, permStateList);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    int32_t userId = 0;
    ret = GetUserIdByHostTokenId(info.hostTokenId, userId);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    tokenIdEx = CreateClawTokenId(ClawTokenType::CLI);
    if (tokenIdEx.tokenIdExStruct.tokenID == INVALID_TOKENID) {
        return AccessTokenError::ERR_TOKENID_CREATE_FAILED;
    }

    ClawTokenBaseInfo baseInfo;
    baseInfo.clawType = ClawTokenType::CLI;
    baseInfo.hostTokenId = info.hostTokenId;
    baseInfo.userId = userId;
    baseInfo.callerPid = callerPid;
    baseInfo.tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    baseInfo.tokenAttr = tokenIdEx.tokenIdExStruct.tokenAttr;
    baseInfo.challenge = info.challenge;

    auto inner = std::make_shared<CliTokenInfoInner>();
    ret = inner->Init(baseInfo, info.cliInfo, permStateList);
    if (ret != RET_SUCCESS) {
        AccessTokenIDManager::GetInstance().ReleaseTokenId(baseInfo.tokenId);
        return ret;
    }

    {
        std::unique_lock<std::shared_mutex> lock(lock_);
        ret = AddClawTokenInfoLocked(inner);
        if (ret != RET_SUCCESS) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(baseInfo.tokenId);
            return ret;
        }
    }
    (void)ClawTicketManager::GetInstance().DeleteClawTicket(info.challenge);

    std::vector<uint32_t> opCodeList;
    std::vector<bool> statusList;
    BuildGrantedKernelPermList(ClawTokenType::CLI, permStateList, kernelPermList);
    BuildPermStatusList(ClawTokenType::CLI, permStateList, opCodeList, statusList);
    PermissionManager::GetInstance().AddNativePermToKernel(baseInfo.tokenId, opCodeList, statusList);

    return RET_SUCCESS;
}

int32_t ClawTokenInfoManager::InitSkillToken(const SkillInitInfo& info, int32_t callerPid,
    AccessTokenIDEx& tokenIdEx, std::vector<std::string>& kernelPermList)
{
    if (!CheckSkillInfo(info.skillInfo) || !CheckClawInitCommonInput(info.hostTokenId, info.challenge)) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    std::vector<PermissionStatus> permStateList;
    int32_t ret = ClawTicketManager::GetInstance().VerifySkillClawTicket(
        info.hostTokenId, info.challenge, info.skillInfo, permStateList);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    int32_t userId = 0;
    ret = GetUserIdByHostTokenId(info.hostTokenId, userId);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    tokenIdEx = CreateClawTokenId(ClawTokenType::SKILL);
    if (tokenIdEx.tokenIdExStruct.tokenID == INVALID_TOKENID) {
        return AccessTokenError::ERR_TOKENID_CREATE_FAILED;
    }

    ClawTokenBaseInfo baseInfo;
    baseInfo.clawType = ClawTokenType::SKILL;
    baseInfo.hostTokenId = info.hostTokenId;
    baseInfo.userId = userId;
    baseInfo.callerPid = callerPid;
    baseInfo.tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    baseInfo.tokenAttr = tokenIdEx.tokenIdExStruct.tokenAttr;
    baseInfo.challenge = info.challenge;

    auto inner = std::make_shared<SkillTokenInfoInner>();
    ret = inner->Init(baseInfo, info.skillInfo, permStateList);
    if (ret != RET_SUCCESS) {
        AccessTokenIDManager::GetInstance().ReleaseTokenId(baseInfo.tokenId);
        return ret;
    }

    {
        std::unique_lock<std::shared_mutex> lock(lock_);
        ret = AddClawTokenInfoLocked(inner);
        if (ret != RET_SUCCESS) {
            AccessTokenIDManager::GetInstance().ReleaseTokenId(baseInfo.tokenId);
            return ret;
        }
    }
    (void)ClawTicketManager::GetInstance().DeleteClawTicket(info.challenge);

    std::vector<uint32_t> opCodeList;
    std::vector<bool> statusList;
    BuildGrantedKernelPermList(ClawTokenType::SKILL, permStateList, kernelPermList);
    BuildPermStatusList(ClawTokenType::SKILL, permStateList, opCodeList, statusList);
    PermissionManager::GetInstance().AddNativePermToKernel(baseInfo.tokenId, opCodeList, statusList);

    return RET_SUCCESS;
}

int32_t ClawTokenInfoManager::DeleteClawToken(int32_t pid)
{
    std::shared_ptr<ClawTokenInfoInnerBase> inner;
    AccessTokenID tokenId = INVALID_TOKENID;
    {
        std::unique_lock<std::shared_mutex> lock(lock_);
        inner = RemoveClawTokenInfoByPidLocked(pid);
        if (inner == nullptr) {
            return AccessTokenError::ERR_TOKENID_NOT_EXIST;
        }
        tokenId = inner->GetTokenId();
    }
    PermissionManager::GetInstance().RemovePermFromKernel(tokenId);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
    return RET_SUCCESS;
}

bool ClawTokenInfoManager::IsClawToken(AccessTokenID tokenId) const
{
    std::shared_lock<std::shared_mutex> lock(lock_);
    return clawTokenInfoMap_.count(tokenId) > 0;
}

int32_t ClawTokenInfoManager::VerifyClawAccessToken(AccessTokenID tokenId, const std::string& permissionName) const
{
    std::shared_ptr<ClawTokenInfoInnerBase> inner;
    {
        std::shared_lock<std::shared_mutex> lock(lock_);
        auto iter = clawTokenInfoMap_.find(tokenId);
        if (iter == clawTokenInfoMap_.end()) {
            return PERMISSION_DENIED;
        }
        inner = iter->second;
    }
    return inner->VerifyAccessToken(permissionName);
}

int32_t ClawTokenInfoManager::GetCliTokenInfo(AccessTokenID tokenId, CliTokenInfo& info) const
{
    std::shared_lock<std::shared_mutex> lock(lock_);
    auto iter = clawTokenInfoMap_.find(tokenId);
    if (iter == clawTokenInfoMap_.end() || iter->second == nullptr ||
        iter->second->GetType() != ClawTokenType::CLI) {
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    std::static_pointer_cast<CliTokenInfoInner>(iter->second)->GetTokenInfo(info);
    return RET_SUCCESS;
}

int32_t ClawTokenInfoManager::GetSkillTokenInfo(AccessTokenID tokenId, SkillTokenInfo& info) const
{
    std::shared_lock<std::shared_mutex> lock(lock_);
    auto iter = clawTokenInfoMap_.find(tokenId);
    if (iter == clawTokenInfoMap_.end() || iter->second == nullptr ||
        iter->second->GetType() != ClawTokenType::SKILL) {
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    std::static_pointer_cast<SkillTokenInfoInner>(iter->second)->GetTokenInfo(info);
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS