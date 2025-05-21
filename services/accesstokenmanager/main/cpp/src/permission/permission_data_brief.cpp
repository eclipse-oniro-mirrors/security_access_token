/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "accesstoken_common_log.h"
#include "constant_common.h"
#include "permission_map.h"
#include "perm_setproc.h"
#include "permission_validator.h"
#include "accesstoken_id_manager.h"
#include "data_validator.h"
#include "token_field_const.h"
#include "data_translator.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
std::recursive_mutex g_briefInstanceMutex;

const uint32_t IS_KERNEL_EFFECT = (0x1 << 0);
const uint32_t HAS_VALUE = (0x1 << 1);

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

bool PermissionDataBrief::GetPermissionBriefData(
    AccessTokenID tokenID, const PermissionStatus &permState,
    const std::map<std::string, std::string>& aclExtendedMap, BriefPermData& briefPermData)
{
    uint32_t code;
    if (PermissionValidator::IsGrantStatusValid(permState.grantStatus) &&
        TransferPermissionToOpcode(permState.permissionName, code)) {
        PermissionBriefDef briefDef;
        GetPermissionBriefDef(code, briefDef);

        briefPermData.status = static_cast<int8_t>(permState.grantStatus);
        briefPermData.permCode = code;
        briefPermData.flag = permState.grantFlag;
        if (briefDef.isKernelEffect) {
            briefPermData.type = IS_KERNEL_EFFECT;
        } else {
            briefPermData.type = 0;
        }

        uint64_t key = (static_cast<uint64_t>(tokenID) << 32) | briefPermData.permCode;
        if (briefDef.hasValue) {
            auto iter = aclExtendedMap.find(permState.permissionName);
            if (iter != aclExtendedMap.end()) {
                extendedValue_[key] = iter->second;
            } else {
                extendedValue_[key] = "";
            }
            briefPermData.type |= HAS_VALUE;
        }

        if (briefPermData.type != 0) {
            LOGI(ATM_DOMAIN, ATM_TAG, "%{public}s with type %{public}d",
                permState.permissionName.c_str(), static_cast<int32_t>(briefPermData.type));
        }
        // if permission is about kernel permission without value, do not add it to extendedValue_
        return true;
    }

    return false;
}

void PermissionDataBrief::GetExetendedValueList(
    AccessTokenID tokenId, std::vector<PermissionWithValue>& extendedPermList)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    return GetExetendedValueListInner(tokenId, extendedPermList);
}

void PermissionDataBrief::GetExetendedValueListInner(
    AccessTokenID tokenId, std::vector<PermissionWithValue>& extendedPermList)
{
    for (const auto& item : extendedValue_) {
        uint64_t key = item.first;
        uint32_t permCode = key & 0xFFFFFFFF;
        std::string permissionName;
        if (!TransferOpcodeToPermission(permCode, permissionName)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TransferOpcodeToPermission failed, permCode: %{public}u", permCode);
            continue;
        }
        uint32_t tmpTokenID = key >> 32;
        if (tmpTokenID != tokenId) {
            continue;
        }
        PermissionWithValue extendedPerm;
        extendedPerm.permissionName = permissionName;
        extendedPerm.value = item.second;
        extendedPermList.emplace_back(extendedPerm);
    }
}

int32_t PermissionDataBrief::GetKernelPermissions(
    AccessTokenID tokenId, std::vector<PermissionWithValue>& kernelPermList)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);

    std::vector<BriefPermData> list;
    int32_t ret = GetBriefPermDataByTokenIdInner(tokenId, list);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "GetBriefPermDataByTokenIdInner failed, tokenId: %{public}d, ret is  %{public}d", tokenId, ret);
        return ret;
    }
    for (const auto& data : list) {
        if ((data.type & IS_KERNEL_EFFECT) != IS_KERNEL_EFFECT) {
            continue;
        }
        std::string permissionName;
        if (!TransferOpcodeToPermission(data.permCode, permissionName)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TransferOpcodeToPermission failed, permCode: %{public}u", data.permCode);
            continue;
        }
        std::string value;
        if ((data.type & HAS_VALUE) == HAS_VALUE) {
            uint64_t key = (static_cast<uint64_t>(tokenId) << 32) | data.permCode;
            auto it = extendedValue_.find(key);
            if (it == extendedValue_.end()) {
                LOGE(ATM_DOMAIN, ATM_TAG, "%{public}s not with value.", permissionName.c_str());
                return ERR_PERMISSION_WITHOUT_VALUE;
            }
            value = it->second;
            if (value.empty()) {
                value = "true";
            }
        } else {
            value = "true";
        }
        PermissionWithValue kernelPerm;
        kernelPerm.permissionName = permissionName;
        kernelPerm.value = value;
        kernelPermList.emplace_back(kernelPerm);
    }
    return RET_SUCCESS;
}

int32_t PermissionDataBrief::GetReqPermissionByName(
    AccessTokenID tokenId, const std::string& permissionName,
    std::string& value, bool tokenIdCheck)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    if (tokenIdCheck) {
        auto iter = requestedPermData_.find(tokenId);
        if (iter == requestedPermData_.end()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is not exist.", tokenId);
            return ERR_TOKEN_INVALID;
        }
    }

    uint32_t permCode;
    if (!TransferPermissionToOpcode(permissionName, permCode)) {
        LOGE(ATM_DOMAIN, ATM_TAG,
            "TransferPermissionToOpcode failed, permissionName: %{public}s.", permissionName.c_str());
        return ERR_PERMISSION_NOT_EXIST;
    }
    uint64_t key = (static_cast<uint64_t>(tokenId) << 32) | permCode;
    auto it = extendedValue_.find(key);
    if (it == extendedValue_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "%{public}s not with value.", permissionName.c_str());
        return ERR_PERMISSION_WITHOUT_VALUE;
    }

    value = it->second;
    return RET_SUCCESS;
}

bool PermissionDataBrief::GetPermissionStatus(const BriefPermData& briefPermData, PermissionStatus &permState)
{
    std::string permissionName;
    if (TransferOpcodeToPermission(briefPermData.permCode, permissionName)) {
        permState.grantStatus = static_cast<int32_t>(briefPermData.status);
        permState.permissionName = permissionName;
        permState.grantFlag = briefPermData.flag;
        return true;
    }
    return false;
}

void PermissionDataBrief::GetPermissionBriefDataList(AccessTokenID tokenID,
    const std::vector<PermissionStatus>& permStateList,
    const std::map<std::string, std::string>& aclExtendedMap,
    std::vector<BriefPermData>& list)
{
    // delte permission with value
    DeleteExtendedValue(tokenID);

    for (const auto& state : permStateList) {
        BriefPermData data = {0};
        if (GetPermissionBriefData(tokenID, state, aclExtendedMap, data)) {
            list.emplace_back(data);
        }
    }
}

void PermissionDataBrief::AddBriefPermDataByTokenId(
    AccessTokenID tokenID, const std::vector<BriefPermData>& listInput)
{
    auto iter = requestedPermData_.find(tokenID);
    if (iter != requestedPermData_.end()) {
        requestedPermData_.erase(tokenID);
    }
    requestedPermData_[tokenID] = listInput;
}

void PermissionDataBrief::AddPermToBriefPermission(
    AccessTokenID tokenId, const std::vector<PermissionStatus>& permStateList, bool defCheck)
{
    std::map<std::string, std::string> aclExtendedMap;
    return AddPermToBriefPermission(tokenId, permStateList, aclExtendedMap, defCheck);
}

void PermissionDataBrief::AddPermToBriefPermission(
    AccessTokenID tokenId, const std::vector<PermissionStatus>& permStateList,
    const std::map<std::string, std::string>& aclExtendedMap, bool defCheck)
{
    ATokenTypeEnum tokenType = AccessTokenIDManager::GetInstance().GetTokenIdTypeEnum(tokenId);
    std::vector<PermissionStatus> permStateListRes;
    if (defCheck) {
        PermissionValidator::FilterInvalidPermissionState(tokenType, true, permStateList, permStateListRes);
    } else {
        permStateListRes.assign(permStateList.begin(), permStateList.end());
    }

    std::vector<BriefPermData> list;
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    GetPermissionBriefDataList(tokenId, permStateListRes, aclExtendedMap, list);
    AddBriefPermDataByTokenId(tokenId, list);
}

void PermissionDataBrief::UpdatePermStatus(const BriefPermData& permOld, BriefPermData& permNew)
{
    // if user_grant permission is not operated by user, it keeps the new initalized state.
    // the new state can be pre_authorization.
    if ((permOld.flag == PERMISSION_DEFAULT_FLAG) && (permOld.status == PERMISSION_DENIED)) {
        return;
    }
    // if old user_grant permission is granted by pre_authorization fixed, it keeps the new initalized state.
    // the new state can be pre_authorization or not.
    if ((permOld.flag == PERMISSION_SYSTEM_FIXED) ||
        // if old user_grant permission is granted by pre_authorization unfixed
        // and the user has not operated this permission, it keeps the new initalized state.
        (permOld.flag == PERMISSION_GRANTED_BY_POLICY)) {
        return;
    }

    permNew.status = permOld.status;
    permNew.flag = permOld.flag;
}

void PermissionDataBrief::Update(
    AccessTokenID tokenId, const std::vector<PermissionStatus>& permStateList,
    const std::map<std::string, std::string>& aclExtendedMap)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    std::vector<PermissionStatus> permStateFilterList;
    PermissionValidator::FilterInvalidPermissionState(TOKEN_HAP, true, permStateList, permStateFilterList);
    LOGI(ATM_DOMAIN, ATM_TAG, "PermStateFilterList size: %{public}zu.", permStateFilterList.size());

    std::vector<BriefPermData> newList;
    GetPermissionBriefDataList(tokenId, permStateFilterList, aclExtendedMap, newList);
    std::vector<BriefPermData> briefPermDataList;
    (void)GetBriefPermDataByTokenIdInner(tokenId, briefPermDataList);
    for (BriefPermData& newPermData : newList) {
        auto iter = std::find_if(briefPermDataList.begin(), briefPermDataList.end(),
            [newPermData](const BriefPermData& oldPermData) {
                return newPermData.permCode == oldPermData.permCode;
            });
        if (iter != briefPermDataList.end()) {
            UpdatePermStatus(*iter, newPermData);
        }
    }
    AddBriefPermDataByTokenId(tokenId, newList);
}

uint32_t PermissionDataBrief::GetFlagWroteToDb(uint32_t grantFlag)
{
    return ConstantCommon::GetFlagWithoutSpecifiedElement(grantFlag, PERMISSION_COMPONENT_SET);
}

int32_t PermissionDataBrief::TranslationIntoAclExtendedMap(
    AccessTokenID tokenId,
    const std::vector<GenericValues>& extendedPermRes,
    std::map<std::string, std::string>& aclExtendedMap)
{
    for (const GenericValues& permValue : extendedPermRes) {
        if ((AccessTokenID)permValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID) != tokenId) {
            continue;
        }
        PermissionWithValue perm;
        int ret = DataTranslator::TranslationIntoExtendedPermission(permValue, perm);
        if (ret != RET_SUCCESS) {
            return ret;
        }
        aclExtendedMap[perm.permissionName] = perm.value;
    }
    return RET_SUCCESS;
}

void PermissionDataBrief::RestorePermissionBriefData(AccessTokenID tokenId,
    const std::vector<GenericValues>& permStateRes, const std::vector<GenericValues> extendedPermRes)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    std::vector<BriefPermData> list;
    std::map<std::string, std::string> aclExtendedMap;
    int result = TranslationIntoAclExtendedMap(tokenId, extendedPermRes, aclExtendedMap);
    if (result != RET_SUCCESS) {
        return;
    }
    for (const GenericValues& stateValue : permStateRes) {
        if ((AccessTokenID)stateValue.GetInt(TokenFiledConst::FIELD_TOKEN_ID) != tokenId) {
            continue;
        }
        PermissionStatus state;
        int ret = DataTranslator::TranslationIntoPermissionStatus(stateValue, state);
        if (ret == RET_SUCCESS) {
            BriefPermData data = {0};
            if (!GetPermissionBriefData(tokenId, state, aclExtendedMap, data)) {
                continue;
            }
            MergePermBriefData(list, data);
        } else {
            LOGE(ATM_DOMAIN, ATM_TAG, "TokenId 0x%{public}x permState is wrong.", tokenId);
        }
    }
    AddBriefPermDataByTokenId(tokenId, list);
}

void PermissionDataBrief::MergePermBriefData(std::vector<BriefPermData>& permBriefDataList,
    BriefPermData& data)
{
    uint32_t flag = GetFlagWroteToDb(data.flag);
    data.flag = flag;
    for (auto iter = permBriefDataList.begin(); iter != permBriefDataList.end(); iter++) {
        if (data.permCode == iter->permCode) {
            iter->status = data.status;
            iter->flag = data.flag;
            LOGD(ATM_DOMAIN, ATM_TAG, "Update permission: %{public}d.", static_cast<int32_t>(data.permCode));
            return;
        }
    }
    LOGD(ATM_DOMAIN, ATM_TAG, "Add permission: %{public}d.", static_cast<int32_t>(data.permCode));
    permBriefDataList.emplace_back(data);
}

int32_t PermissionDataBrief::StorePermissionBriefData(AccessTokenID tokenId,
    std::vector<GenericValues>& permStateValueList)
{
    std::vector<BriefPermData> permBriefDatalist;
    {
        Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
        int32_t ret = GetBriefPermDataByTokenIdInner(tokenId, permBriefDatalist);
        if (ret != RET_SUCCESS) {
            return ret;
        }
    }

    for (const auto& data : permBriefDatalist) {
        LOGD(ATM_DOMAIN, ATM_TAG, "PermissionName: %{public}d", static_cast<int32_t>(data.permCode));
        GenericValues genericValues;
        PermissionStatus permState;
        if (!GetPermissionStatus(data, permState)) {
            return ERR_PERMISSION_NOT_EXIST;
        }
        genericValues.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
        DataTranslator::TranslationIntoGenericValues(permState, genericValues);
        permStateValueList.emplace_back(genericValues);
    }
    return RET_SUCCESS;
}

static uint32_t UpdateWithNewFlag(uint32_t oldFlag, uint32_t currFlag)
{
    uint32_t newFlag = currFlag | (oldFlag & PERMISSION_GRANTED_BY_POLICY);
    return newFlag;
}

int32_t PermissionDataBrief::UpdatePermStateList(
    AccessTokenID tokenId, uint32_t opCode, bool isGranted, uint32_t flag)
{
    auto iterPermData = requestedPermData_.find(tokenId);
    if (iterPermData == requestedPermData_.end()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is not exist.", tokenId);
        return ERR_TOKEN_INVALID;
    }
    std::vector<BriefPermData>& permBriefDatalist = requestedPermData_[tokenId];
    auto iter = std::find_if(permBriefDatalist.begin(), permBriefDatalist.end(),
        [opCode](const BriefPermData& permData) {
            return opCode == permData.permCode;
        });
    if (iter == permBriefDatalist.end()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Permission not request!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    
    if ((static_cast<uint32_t>(iter->flag) & PERMISSION_SYSTEM_FIXED) == PERMISSION_SYSTEM_FIXED) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Permission fixed by system!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    iter->status = isGranted ? PERMISSION_GRANTED : PERMISSION_DENIED;
    iter->flag = UpdateWithNewFlag(iter->flag, flag);
    return RET_SUCCESS;
}

int32_t PermissionDataBrief::UpdateSecCompGrantedPermList(AccessTokenID tokenId,
    const std::string& permissionName, bool isToGrant)
{
    uint32_t flag = 0;
    int32_t ret = QueryPermissionFlag(tokenId, permissionName, flag);

    LOGD(ATM_DOMAIN, ATM_TAG, "Ret is %{public}d. flag is %{public}d", ret, flag);
    // if the permission has been operated by user or the permission has been granted by system.
    if ((ConstantCommon::IsPermOperatedByUser(flag) || ConstantCommon::IsPermOperatedBySystem(flag))) {
        LOGD(ATM_DOMAIN, ATM_TAG, "The permission has been operated.");
        if (isToGrant) {
            // The data included in requested perm list.
            int32_t status = VerifyPermissionStatus(tokenId, permissionName);
            // Permission has been granted, there is no need to add perm state in security component permList.
            if (status == PERMISSION_GRANTED) {
                return RET_SUCCESS;
            } else {
                LOGC(ATM_DOMAIN, ATM_TAG, "Permission has been revoked by user.");
                return ERR_PERMISSION_DENIED;
            }
        } else {
            /* revoke is called while the permission has been operated by user or system */
            SecCompGrantedPermListUpdated(
                tokenId, permissionName, false);
            return RET_SUCCESS;
        }
    }
    // the permission has not been operated by user or the app has not applied for this permission in config.json
    SecCompGrantedPermListUpdated(tokenId, permissionName, isToGrant);
    return RET_SUCCESS;
}

int32_t PermissionDataBrief::UpdatePermissionStatus(AccessTokenID tokenId,
    const std::string& permissionName, bool isGranted, uint32_t flag, bool& statusChanged)
{
    uint32_t opCode;
    if (!TransferPermissionToOpcode(permissionName, opCode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid %{public}s.", permissionName.c_str());
        return ERR_PARAM_INVALID;
    }
    int32_t ret;
    int32_t oldStatus = VerifyPermissionStatus(tokenId, opCode);
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    if (!ConstantCommon::IsPermGrantedBySecComp(flag)) {
        ret = UpdatePermStateList(tokenId, opCode, isGranted, flag);
    } else {
        LOGD(ATM_DOMAIN, ATM_TAG, "Permission is set by security component.");
        ret = UpdateSecCompGrantedPermList(tokenId, permissionName, isGranted);
    }
    int32_t newStatus = VerifyPermissionStatus(tokenId, opCode);
    statusChanged = (oldStatus == newStatus) ? false : true;
    return ret;
}

int32_t PermissionDataBrief::ResetUserGrantPermissionStatus(AccessTokenID tokenID)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is not exist.", tokenID);
        return ERR_TOKEN_INVALID;
    }
    for (auto& perm : iter->second) {
        uint32_t oldFlag = static_cast<uint32_t>(perm.flag);
        if ((oldFlag & PERMISSION_SYSTEM_FIXED) != 0) {
            continue;
        }
        /* A user_grant permission has been set by system for cancellable pre-authorization. */
        /* it should keep granted when the app reset. */
        if ((oldFlag & PERMISSION_GRANTED_BY_POLICY) != 0) {
            perm.status = PERMISSION_GRANTED;
            perm.flag = PERMISSION_GRANTED_BY_POLICY;
            continue;
        }
        perm.status = PERMISSION_DENIED;
        perm.flag = PERMISSION_DEFAULT_FLAG;
    }
    ClearAllSecCompGrantedPermById(tokenID);
    return RET_SUCCESS;
}

void PermissionDataBrief::DeleteExtendedValue(AccessTokenID tokenID)
{
    auto it = extendedValue_.begin();
    while (it != extendedValue_.end()) {
        uint64_t key = it->first;
        AccessTokenID tokenIDToDelete = key >> 32;
        if (tokenIDToDelete == tokenID) {
            it = extendedValue_.erase(it);
        } else {
            ++it;
        }
    }
}

int32_t PermissionDataBrief::DeleteBriefPermDataByTokenId(AccessTokenID tokenID)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is not exist.", tokenID);
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
    DeleteExtendedValue(tokenID);
    LOGI(ATM_DOMAIN, ATM_TAG, "TokenID %{public}u is deleted.", tokenID);
    return RET_SUCCESS;
}
int32_t PermissionDataBrief::GetBriefPermDataByTokenIdInner(AccessTokenID tokenID, std::vector<BriefPermData>& list)
{
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is not exist.", tokenID);
        return ERR_TOKEN_INVALID;
    }
    for (const auto& data : iter->second) {
        list.emplace_back(data);
    }
    return RET_SUCCESS;
}

int32_t PermissionDataBrief::GetBriefPermDataByTokenId(AccessTokenID tokenID, std::vector<BriefPermData>& list)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    return GetBriefPermDataByTokenIdInner(tokenID, list);
}

void PermissionDataBrief::GetGrantedPermByTokenId(AccessTokenID tokenID,
    const std::vector<std::string>& constrainedList, std::vector<std::string>& permissionList)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is not exist.", tokenID);
        return;
    }
    for (const auto& data : iter->second) {
        if (data.status == PERMISSION_GRANTED) {
            std::string permission;
            (void)TransferOpcodeToPermission(data.permCode, permission);
            if (constrainedList.empty() ||
                (std::find(constrainedList.begin(), constrainedList.end(), permission) == constrainedList.end())) {
                permissionList.emplace_back(permission);
                LOGD(ATM_DOMAIN, ATM_TAG, "Permission %{public}s is granted.", permission.c_str());
            }
        }
    }
    std::list<BriefSecCompData>::iterator secCompData;
    for (secCompData = secCompList_.begin(); secCompData != secCompList_.end(); ++secCompData) {
        if (secCompData->tokenId == tokenID) {
            std::string permission;
            (void)TransferOpcodeToPermission(secCompData->permCode, permission);
            permissionList.emplace_back(permission);
            LOGD(ATM_DOMAIN, ATM_TAG, "Permission %{public}s is granted by secComp.", permission.c_str());
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
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID %{public}d is not exist.", tokenID);
        return;
    }
    for (const auto& data : iter->second) {
        /* The permission is not constrained by user policy. */
        if (constrainedList.empty() ||
            (std::find(constrainedList.begin(), constrainedList.end(), data.permCode) == constrainedList.end())) {
            opCodeList.emplace_back(data.permCode);
            bool status = data.status == PERMISSION_GRANTED ? true : false;
            statusList.emplace_back(status);
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
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is not exist %{public}d.", tokenID);
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    auto it = std::find_if(iter->second.begin(), iter->second.end(), [opCode](BriefPermData data) {
        return (data.permCode == opCode);
    });
    if (it != iter->second.end()) {
        if (ConstantCommon::IsPermGrantedBySecComp(it->flag)) {
            return PermUsedTypeEnum::SEC_COMPONENT_TYPE;
        }
        if (it->status == PERMISSION_DENIED) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Permission of %{public}d is requested, but not granted.", tokenID);
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
int32_t PermissionDataBrief::VerifyPermissionStatus(AccessTokenID tokenID, uint32_t permCode)
{
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is not exist %{public}d.", tokenID);
        return PERMISSION_DENIED;
    }
    auto it = std::find_if(iter->second.begin(), iter->second.end(), [permCode](BriefPermData data) {
        return (data.permCode == permCode);
    });
    if (it != iter->second.end()) {
        if (ConstantCommon::IsPermGrantedBySecComp(it->flag)) {
            LOGD(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d, permission is granted by secComp", tokenID);
            return PERMISSION_GRANTED;
        }
        return static_cast<int32_t>(it->status);
    }

    std::list<BriefSecCompData>::iterator secCompData;
    for (secCompData = secCompList_.begin(); secCompData != secCompList_.end(); ++secCompData) {
        if ((secCompData->tokenId == tokenID) && (secCompData->permCode == permCode)) {
            LOGD(ATM_DOMAIN, ATM_TAG,
                "TokenID: %{public}d, permission is not requested. While it is granted by secComp", tokenID);
            return PERMISSION_GRANTED;
        }
    }
    return PERMISSION_DENIED;
}

int32_t PermissionDataBrief::VerifyPermissionStatus(AccessTokenID tokenID, const std::string& permission)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "tokenID %{public}d, permissionName %{public}s.", tokenID, permission.c_str());
    uint32_t opCode;
    if (!TransferPermissionToOpcode(permission, opCode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid %{public}s.", permission.c_str());
        return PERMISSION_DENIED;
    }
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    return VerifyPermissionStatus(tokenID, opCode);
}

bool PermissionDataBrief::IsPermissionGrantedWithSecComp(AccessTokenID tokenID, const std::string& permissionName)
{
    uint32_t opCode;
    if (!TransferPermissionToOpcode(permissionName, opCode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid %{public}s.", permissionName.c_str());
        return false;
    }

    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is not exist %{public}d.", tokenID);
        return false;
    }
    auto it = std::find_if(iter->second.begin(), iter->second.end(), [opCode](BriefPermData data) {
        return (data.permCode == opCode);
    });
    if (it != iter->second.end()) {
        if (ConstantCommon::IsPermGrantedBySecComp(it->flag)) {
            LOGI(ATM_DOMAIN, ATM_TAG, "TokenID: %{public}d, permission is granted by secComp", tokenID);
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
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid %{public}s.", permissionName.c_str());
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }

    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid %{public}u.", tokenID);
        return AccessTokenError::ERR_TOKENID_NOT_EXIST;
    }
    auto it = std::find_if(iter->second.begin(), iter->second.end(), [opCode](BriefPermData data) {
        return (data.permCode == opCode);
    });
    if (it != iter->second.end()) {
        flag = it->flag;
        return RET_SUCCESS;
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is not in requestedPerm list %{public}s.", permissionName.c_str());
    return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
}

void PermissionDataBrief::SecCompGrantedPermListUpdated(
    AccessTokenID tokenID, const std::string& permissionName, bool isAdded)
{
    uint32_t opCode;
    if (!TransferPermissionToOpcode(permissionName, opCode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermissionName is invalid %{public}s.", permissionName.c_str());
        return;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenID);
    if (iter == requestedPermData_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is invalid %{public}u.", tokenID);
        return;
    }
    std::list<BriefSecCompData>::iterator secCompDataIter;
    for (secCompDataIter = secCompList_.begin(); secCompDataIter != secCompList_.end(); ++secCompDataIter) {
        if (secCompDataIter->tokenId == tokenID && secCompDataIter->permCode == opCode) {
            break;
        }
    }
    if (isAdded) {
        if (secCompDataIter == secCompList_.end()) {
            BriefSecCompData secCompData = { 0 };
            secCompData.permCode = opCode;
            secCompData.tokenId = tokenID;
            secCompList_.emplace_back(secCompData);
        }
    } else {
        if (secCompDataIter != secCompList_.end()) {
            secCompList_.erase(secCompDataIter);
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
        LOGI(ATM_DOMAIN, ATM_TAG, "Update flag newFlag %{public}u, oldFlag %{public}u .", newFlag, oldFlag);
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
    std::list<BriefSecCompData>::iterator secCompData;
    for (secCompData = secCompList_.begin(); secCompData != secCompList_.end();) {
        if (secCompData->tokenId == tokenID) {
            LOGI(ATM_DOMAIN, ATM_TAG, "TokenID is cleared %{public}u.", tokenID);
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
            LOGW(ATM_DOMAIN, ATM_TAG, "Perm %{public}s is not exist.", perm.c_str());
        }
    }
    if (constrainedCodeList.empty()) {
        LOGD(ATM_DOMAIN, ATM_TAG, "constrainedCodeList is null.");
        return RET_SUCCESS;
    }

    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    auto iter = requestedPermData_.find(tokenId);
    if (iter == requestedPermData_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "TokenID is not exist in requestedPermData_ %{public}u.", tokenId);
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
            LOGE(ATM_DOMAIN, ATM_TAG, "GetPermissionToKernel err=%{public}d", ret);
            continue;
        }
        bool isGrantedToBe = (data.status == PERMISSION_GRANTED) && hapUserIsActive;
        LOGI(ATM_DOMAIN, ATM_TAG,
            "id=%{public}u, opCode=%{public}u, isGranted=%{public}d, hapUserIsActive=%{public}d",
            tokenId, data.permCode, isGrantedToBe, hapUserIsActive);
        if (isGrantedCurr == isGrantedToBe) {
            continue;
        }
        ret = SetPermissionToKernel(tokenId, data.permCode, isGrantedToBe);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG, "SetPermissionToKernel err=%{public}d", ret);
            continue;
        }
        std::string permission;
        (void)TransferOpcodeToPermission(data.permCode, permission);
        refreshedPermList[permission] = isGrantedToBe;
    }
    return RET_SUCCESS;
}

int32_t PermissionDataBrief::AddBriefPermData(AccessTokenID tokenID, const std::string& permissionName,
    PermissionState grantStatus, PermissionFlag grantFlag, const std::string& value)
{
    PermissionStatus status;
    status.permissionName = permissionName;
    status.grantStatus = static_cast<int32_t>(grantStatus);
    status.grantFlag = static_cast<uint32_t>(grantFlag);

    std::map<std::string, std::string> aclExtendedMap;
    aclExtendedMap[permissionName] = value;

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->permissionStateDataLock_);
    BriefPermData data;
    if (!GetPermissionBriefData(tokenID, status, aclExtendedMap, data)) {
        return AccessTokenError::ERR_PERMISSION_NOT_EXIST;
    }

    std::vector<BriefPermData> list;
    int32_t res = GetBriefPermDataByTokenIdInner(tokenID, list);
    if (res != RET_SUCCESS) {
        return res;
    }

    MergePermBriefData(list, data);
    AddBriefPermDataByTokenId(tokenID, list);

    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS