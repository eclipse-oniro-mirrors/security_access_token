/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "permission_data_brief.h"

#include <algorithm>
#include <chrono>
#include <iostream>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_log.h"
#include "constant_common.h"
#include "permission_map.h"
#include "perm_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "PermissionDataBrief"};
std::recursive_mutex g_briefInstanceMutex;

PermissionDataBrief& PermissionDataBrief::GetInstance()
{
    static PermissionDataBrief* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_briefInstanceMutex);
        if (instance == nullptr) {
            PermissionDataBrief* tmp = new PermissionDataBrief();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

int32_t PermissionDataBrief::AddBriefPermDataByTokenId(
    AccessTokenID tokenID, const std::vector<BriefPermData>& listInput)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter != requestedPermData_.end()) {
        ACCESSTOKEN_LOG_INFO(LABEL, "TokenID %{public}d is cleared first.", tokenID);
        requestedPermData_.erase(tokenID);
    }
    requestedPermData_[tokenID] = listInput;
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenID %{public}d is set.", tokenID);
    return RET_SUCCESS;
}

int32_t PermissionDataBrief::DeleteBriefPermDataByTokenId(AccessTokenID tokenID)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID %{public}d is not exist.", tokenID);
        return ERR_TOKEN_INVALID;
    }
    requestedPermData_.erase(tokenID);
    std::list<BriefSecCompData>::iterator secCompData;
    for (secCompData = secCompList_.begin(); secCompData != secCompList_.end();) {
        if (secCompData->tokenId != tokenID) {
            ++secCompData;
        } else {
            secCompData = secCompList_.erase(secCompData);
        }
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "TokenID %{public}u is deleted.", tokenID);
    return RET_SUCCESS;
}

int32_t PermissionDataBrief::SetBriefPermData(AccessTokenID tokenID, int32_t opCode, bool status, uint32_t flag)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID %{public}d is not exist.", tokenID);
        return ERR_TOKEN_INVALID;
    }
    auto it = std::find_if(iter->second.begin(), iter->second.end(), [opCode](BriefPermData data) {
        return (data.permCode == opCode);
    });
    if (it != iter->second.end()) {
        it->status = status ? 1 : 0;
        it->flag = flag;
        return RET_SUCCESS;
    }

    if (flag != PERMISSION_COMPONENT_SET) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Permission is not requested.");
        return ERR_PERMISSION_NOT_EXIST;
    }
    // Set secComp permission without existing in state list.
    if (status) {
        BriefSecCompData secCompData = { 0 };
        secCompData.permCode = opCode;
        secCompData.tokenId = tokenID;
        secCompList_.push_back(secCompData);
    } else {
        std::list<BriefSecCompData>::iterator secCompData;
        for (secCompData = secCompList_.begin(); secCompData != secCompList_.end(); ++secCompData) {
            if (secCompData->tokenId == tokenID && secCompData->permCode == opCode) {
                secCompList_.erase(secCompData);
                break;
            }
        }
    }
    return RET_SUCCESS;
}

int32_t PermissionDataBrief::GetBriefPermDataByTokenId(AccessTokenID tokenID, std::vector<BriefPermData>& list)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID %{public}d is not exist.", tokenID);
        return ERR_TOKEN_INVALID;
    }
    for (const auto& data : iter->second) {
        list.emplace_back(data);
    }
    return RET_SUCCESS;
}

void PermissionDataBrief::GetGrantedPermByTokenId(AccessTokenID tokenID,
    const std::vector<std::string>& constrainedList, std::vector<std::string>& permissionList)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID %{public}d is not exist.", tokenID);
        return;
    }
    for (const auto& data : iter->second) {
        if (data.status) {
            std::string permission;
            (void)TransferOpcodeToPermission(data.permCode, permission);
            if (constrainedList.empty() ||
                (std::find(constrainedList.begin(), constrainedList.end(), permission) == constrainedList.end())) {
                permissionList.emplace_back(permission);
                ACCESSTOKEN_LOG_DEBUG(LABEL, "Permission %{public}s is granted.", permission.c_str());
            }
        }
    }
    std::list<BriefSecCompData>::iterator secCompData;
    for (secCompData = secCompList_.begin(); secCompData != secCompList_.end(); ++secCompData) {
        if (secCompData->tokenId == tokenID) {
            std::string permission;
            (void)TransferOpcodeToPermission(secCompData->permCode, permission);
            permissionList.emplace_back(permission);
            ACCESSTOKEN_LOG_DEBUG(LABEL, "Permission %{public}s is granted by secComp.", permission.c_str());
        }
    }
    return;
}

void PermissionDataBrief::GetPermStatusListByTokenId(AccessTokenID tokenID,
    const std::vector<uint32_t> constrainedList, std::vector<uint32_t>& opCodeList, std::vector<bool>& statusList)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID %{public}d is not exist.", tokenID);
        return;
    }
    for (const auto& data : iter->second) {
        /* The permission is not constrained by user policy. */
        if (constrainedList.empty() ||
            (std::find(constrainedList.begin(), constrainedList.end(), data.permCode) == constrainedList.end())) {
            opCodeList.emplace_back(data.permCode);
            statusList.emplace_back(data.status);
        } else {
        /* The permission is constrained by user policy which is in constrainedList. */
            opCodeList.emplace_back(data.permCode);
            statusList.emplace_back(false);
        }
    }

    AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&tokenID);
    if (static_cast<ATokenTypeEnum>(idInner->type) != TOKEN_HAP) {
        return;
    }
    /* Only an application can be granted by secComp. */
    std::list<BriefSecCompData>::iterator secCompData;
    for (secCompData = secCompList_.begin(); secCompData != secCompList_.end(); ++secCompData) {
        if (secCompData->tokenId == tokenID) {
            opCodeList.emplace_back(secCompData->permCode);
            statusList.emplace_back(true);
        }
    }
    return;
}

PermUsedTypeEnum PermissionDataBrief::GetPermissionUsedType(AccessTokenID tokenID, int32_t opCode)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID is not exist %{public}d.", tokenID);
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    auto it = std::find_if(iter->second.begin(), iter->second.end(), [opCode](BriefPermData data) {
        return (data.permCode == opCode);
    });
    if (it != iter->second.end()) {
        if (ConstantCommon::IsPermGrantedBySecComp(it->flag)) {
            return PermUsedTypeEnum::SEC_COMPONENT_TYPE;
        }
        if (it->status == 0) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Permission of %{public}d is requested, but not granted.", tokenID);
            return PermUsedTypeEnum::INVALID_USED_TYPE;
        }
        return PermUsedTypeEnum::NORMAL_TYPE;
    }
    std::list<BriefSecCompData>::iterator secCompData;
    for (secCompData = secCompList_.begin(); secCompData != secCompList_.end(); ++secCompData) {
        if ((secCompData->tokenId == tokenID) && (secCompData->permCode == opCode)) {
            return PermUsedTypeEnum::SEC_COMPONENT_TYPE;
        }
    }
    return PermUsedTypeEnum::INVALID_USED_TYPE;
}

int32_t PermissionDataBrief::VerifyPermissionStatus(AccessTokenID tokenID, const std::string& permission)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "tokenID %{public}d, permissionName %{public}s.", tokenID, permission.c_str());
    uint32_t opCode;
    if (!TransferPermissionToOpcode(permission, opCode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PermissionName is invalid %{public}s.", permission.c_str());
        return PERMISSION_DENIED;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID is not exist %{public}d.", tokenID);
        return PERMISSION_DENIED;
    }
    auto it = std::find_if(iter->second.begin(), iter->second.end(), [opCode](BriefPermData data) {
        return (data.permCode == opCode);
    });
    if (it != iter->second.end()) {
        if (ConstantCommon::IsPermGrantedBySecComp(it->flag)) {
            ACCESSTOKEN_LOG_DEBUG(LABEL, "TokenID: %{public}d, permission is granted by secComp", tokenID);
            return PERMISSION_GRANTED;
        }
        if (it->status) {
            return PERMISSION_GRANTED;
        }
        return PERMISSION_DENIED;
    }

    std::list<BriefSecCompData>::iterator secCompData;
    for (secCompData = secCompList_.begin(); secCompData != secCompList_.end(); ++secCompData) {
        if ((secCompData->tokenId == tokenID) && (secCompData->permCode == opCode)) {
            ACCESSTOKEN_LOG_DEBUG(LABEL,
                "TokenID: %{public}d, permission is not requested. While it is granted by secComp", tokenID);
            return PERMISSION_GRANTED;
        }
    }
    return PERMISSION_DENIED;
}

bool PermissionDataBrief::IsPermissionGrantedWithSecComp(AccessTokenID tokenID, const std::string& permissionName)
{
    uint32_t opCode;
    if (!TransferPermissionToOpcode(permissionName, opCode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PermissionName is invalid %{public}s.", permissionName.c_str());
        return false;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID is not exist %{public}d.", tokenID);
        return false;
    }
    auto it = std::find_if(iter->second.begin(), iter->second.end(), [opCode](BriefPermData data) {
        return (data.permCode == opCode);
    });
    if (it != iter->second.end()) {
        if (ConstantCommon::IsPermGrantedBySecComp(it->flag)) {
            ACCESSTOKEN_LOG_INFO(LABEL, "TokenID: %{public}d, permission is granted by secComp", tokenID);
            return true;
        }
    }
    std::list<BriefSecCompData>::iterator secCompData;
    for (secCompData = secCompList_.begin(); secCompData != secCompList_.end(); ++secCompData) {
        if (secCompData->tokenId == tokenID && secCompData->permCode == opCode) {
            return true;
        }
    }
    return false;
}

int32_t PermissionDataBrief::QueryPermissionFlag(AccessTokenID tokenID, const std::string& permissionName,
    uint32_t& flag)
{
    uint32_t opCode;
    if (!TransferPermissionToOpcode(permissionName, opCode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PermissionName is invalid %{public}s.", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID is invalid %{public}u.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    auto it = std::find_if(iter->second.begin(), iter->second.end(), [opCode](BriefPermData data) {
        return (data.permCode == opCode);
    });
    if (it != iter->second.end()) {
        flag = it->flag;
        return RET_SUCCESS;
    }
    ACCESSTOKEN_LOG_ERROR(LABEL, "PermissionName is not in requestedPerm list %{public}s.", permissionName.c_str());
    return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
}

void PermissionDataBrief::SecCompGrantedPermListUpdated(
    AccessTokenID tokenID, const std::string& permissionName, bool isAdded)
{
    uint32_t opCode;
    if (!TransferPermissionToOpcode(permissionName, opCode)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PermissionName is invalid %{public}s.", permissionName.c_str());
        return;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID is invalid %{public}u.", tokenID);
        return;
    }

    if (isAdded) {
        BriefSecCompData secCompData = { 0 };
        secCompData.permCode = opCode;
        secCompData.tokenId = tokenID;
        secCompList_.push_back(secCompData);
    } else {
        std::list<BriefSecCompData>::iterator secCompData;
        for (secCompData = secCompList_.begin(); secCompData != secCompList_.end(); ++secCompData) {
            if (secCompData->tokenId == tokenID && secCompData->permCode == opCode) {
                secCompList_.erase(secCompData);
                break;
            }
        }
    }

    auto it = std::find_if(iter->second.begin(), iter->second.end(), [opCode](BriefPermData data) {
        return (data.permCode == opCode);
    });
    if (it != iter->second.end()) {
        uint32_t oldFlag = it->flag;
        uint32_t newFlag =
            isAdded ? (oldFlag | PERMISSION_COMPONENT_SET) : (oldFlag & (~PERMISSION_COMPONENT_SET));
        it->flag = newFlag;
        ACCESSTOKEN_LOG_INFO(LABEL, "Update flag newFlag %{public}u, oldFlag %{public}u .", newFlag, oldFlag);
    }
    return;
}

void PermissionDataBrief::ClearAllSecCompGrantedPerm()
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    std::list<BriefSecCompData>::iterator secCompData;
    for (secCompData = secCompList_.begin(); secCompData != secCompList_.end();) {
        secCompData = secCompList_.erase(secCompData);
    }
}

void PermissionDataBrief::ClearAllSecCompGrantedPermById(AccessTokenID tokenID)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    std::list<BriefSecCompData>::iterator secCompData;
    for (secCompData = secCompList_.begin(); secCompData != secCompList_.end();) {
        if (secCompData->tokenId == tokenID) {
            ACCESSTOKEN_LOG_INFO(LABEL, "TokenID is cleared %{public}u.", tokenID);
            secCompData = secCompList_.erase(secCompData);
        } else {
            ++secCompData;
        }
    }
}

int32_t PermissionDataBrief::RefreshPermStateToKernel(const std::vector<std::string>& constrainedList,
    bool hapUserIsActive, AccessTokenID tokenId, std::map<std::string, bool>& refreshedPermList)
{
    std::vector<uint32_t> constrainedCodeList;
    for (const auto& perm : constrainedList) {
        uint32_t code;
        if (TransferPermissionToOpcode(perm, code)) {
            constrainedCodeList.emplace_back(code);
        } else {
            ACCESSTOKEN_LOG_WARN(LABEL, "Perm %{public}s is not exist.", perm.c_str());
        }
    }
    if (constrainedCodeList.empty()) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "constrainedCodeList is null.");
        return RET_SUCCESS;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenId);
    if (iter == requestedPermData_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "TokenID is not exist in requestedPermData_ %{public}u.", tokenId);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    for (const auto& data : iter->second) {
        if (std::find(constrainedCodeList.begin(), constrainedCodeList.end(), data.permCode) ==
            constrainedCodeList.end()) {
            continue;
        }
        bool isGrantedCurr;
        int32_t ret = GetPermissionFromKernel(tokenId, data.permCode, isGrantedCurr);
        if (ret != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GetPermissionToKernel err=%{public}d", ret);
            continue;
        }
        bool isGrantedToBe = (data.status) && hapUserIsActive;
        ACCESSTOKEN_LOG_INFO(LABEL,
            "id=%{public}u, opCode=%{public}u, isGranted=%{public}d, hapUserIsActive=%{public}d",
            tokenId, data.permCode, isGrantedToBe, hapUserIsActive);
        if (isGrantedCurr == isGrantedToBe) {
            continue;
        }
        ret = SetPermissionToKernel(tokenId, data.permCode, isGrantedToBe);
        if (ret != RET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "SetPermissionToKernel err=%{public}d", ret);
            continue;
        }
        std::string permission;
        (void)TransferOpcodeToPermission(data.permCode, permission);
        refreshedPermList[permission] = isGrantedToBe;
    }
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS