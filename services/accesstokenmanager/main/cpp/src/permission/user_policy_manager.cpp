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

#include "user_policy_manager.h"

#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <mutex>
#include <new>
#include <set>
#include <string>

#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "constant_common.h"
#include "data_validator.h"
#include "permission_map.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
#ifdef SUPPORT_MANAGE_USER_POLICY
constexpr char USER_POLICY_SEPARATOR = ',';
constexpr size_t USER_POLICY_MAX_LIST_SIZE = 1024;

std::string Trim(const std::string& value)
{
    const std::string spaces = " \t";
    size_t begin = value.find_first_not_of(spaces);
    if (begin == std::string::npos) {
        return "";
    }
    size_t end = value.find_last_not_of(spaces);
    return value.substr(begin, end - begin + 1);
}

bool ParseInt32Value(const std::string& value, int32_t& parsedValue)
{
    std::string trimmedValue = Trim(value);
    char* endPtr = nullptr;
    long parsed = std::strtol(trimmedValue.c_str(), &endPtr, 10);
    if ((*endPtr != '\0') || (parsed < INT32_MIN) || (parsed > INT32_MAX)) {
        return false;
    }
    parsedValue = static_cast<int32_t>(parsed);
    return true;
}

bool ParseTokenIdValue(const std::string& value, AccessTokenID& parsedValue)
{
    std::string trimmedValue = Trim(value);
    char* endPtr = nullptr;
    unsigned long parsed = std::strtoul(trimmedValue.c_str(), &endPtr, 10);
    if ((*endPtr != '\0') || (parsed > UINT32_MAX)) {
        return false;
    }
    parsedValue = static_cast<AccessTokenID>(parsed);
    return true;
}

bool ParseUserList(const std::string& value, std::vector<int32_t>& userList)
{
    userList.clear();
    if (value.empty()) {
        return true;
    }
    size_t begin = 0;
    while (begin <= value.size()) {
        size_t end = value.find(USER_POLICY_SEPARATOR, begin);
        std::string item = (end == std::string::npos) ? value.substr(begin) : value.substr(begin, end - begin);
        if (!Trim(item).empty()) {
            int32_t userId = 0;
            if (!ParseInt32Value(item, userId)) {
                return false;
            }
            userList.emplace_back(userId);
        }
        if (end == std::string::npos) {
            break;
        }
        begin = end + 1;
    }
    return true;
}

bool ParseWhiteTokenList(const std::string& value, std::unordered_set<AccessTokenID>& whiteList)
{
    whiteList.clear();
    if (value.empty()) {
        return true;
    }
    size_t begin = 0;
    while (begin <= value.size()) {
        size_t end = value.find(USER_POLICY_SEPARATOR, begin);
        std::string item = (end == std::string::npos) ? value.substr(begin) : value.substr(begin, end - begin);
        if (!Trim(item).empty()) {
            AccessTokenID tokenId = INVALID_TOKENID;
            if (!ParseTokenIdValue(item, tokenId)) {
                return false;
            }
            whiteList.insert(tokenId);
        }
        if (end == std::string::npos) {
            break;
        }
        begin = end + 1;
    }
    return true;
}

template<typename T>
std::string SerializeList(const std::vector<T>& valueList)
{
    std::string result;
    for (size_t index = 0; index < valueList.size(); ++index) {
        if (!result.empty()) {
            result.push_back(USER_POLICY_SEPARATOR);
        }
        result.append(std::to_string(valueList[index]));
    }
    return result;
}

std::string SerializeWhiteTokenList(const std::unordered_set<AccessTokenID>& whiteList)
{
    std::vector<AccessTokenID> tokenIdList(whiteList.begin(), whiteList.end());
    std::sort(tokenIdList.begin(), tokenIdList.end());
    return SerializeList(tokenIdList);
}

bool IsSupportedPolicyApl(ATokenAplEnum apl)
{
    return apl == APL_NORMAL || apl == APL_SYSTEM_BASIC;
}

GenericValues BuildUserPolicyCondition(const std::string& permissionName)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
    return conditionValue;
}

GenericValues BuildUserPolicyValue(const std::string& permissionName, const UserPolicyRecord& record)
{
    GenericValues value;
    value.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permissionName);
    value.Put(TokenFiledConst::FIELD_CONTROLLER_TOKENID, static_cast<int32_t>(record.controllerToken));
    value.Put(TokenFiledConst::FIELD_RESTRICTED_USER, SerializeList(record.userList));
    value.Put(TokenFiledConst::FIELD_WHITLIST, SerializeWhiteTokenList(record.whiteList));
    return value;
}

std::set<int32_t> UpdateRestrictedUserList(
    const std::vector<UserPolicy>& requestedUserPolicies, std::vector<int32_t>& restrictedUserList)
{
    std::set<int32_t> changedUserList;
    for (const auto& item : requestedUserPolicies) {
        auto iter = std::find(restrictedUserList.begin(), restrictedUserList.end(), item.userId);
        if ((iter != restrictedUserList.end()) && !item.isRestricted) {
            // Remove this user from policy control; related tokens should restore their real permission state.
            restrictedUserList.erase(iter);
            changedUserList.insert(item.userId);
        } else if ((iter == restrictedUserList.end()) && item.isRestricted) {
            // Add this user to policy control; related tokens should be restricted by user policy.
            restrictedUserList.emplace_back(item.userId);
            changedUserList.insert(item.userId);
        }
    }
    return changedUserList;
}

bool IsUserPolicyRecordSizeValid(const UserPolicyRecord& record)
{
    return !record.userList.empty() && record.userList.size() <= USER_POLICY_MAX_LIST_SIZE &&
        record.whiteList.size() <= USER_POLICY_MAX_LIST_SIZE;
}

bool IsUserPolicyRecordsSizeValid(const std::map<uint32_t, UserPolicyRecord>& records)
{
    if (records.size() > USER_POLICY_MAX_LIST_SIZE) {
        return false;
    }
    return std::all_of(records.begin(), records.end(), [](const auto& item) {
        return IsUserPolicyRecordSizeValid(item.second);
    });
}

#endif

}

UserPolicyManager& UserPolicyManager::GetInstance()
{
    static UserPolicyManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            UserPolicyManager* tmp = new (std::nothrow) UserPolicyManager();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

#ifdef SUPPORT_MANAGE_USER_POLICY
int32_t UserPolicyManager::ValidateSetUserPolicy(const std::vector<UserPermissionPolicy>& userPermissionList,
    AccessTokenID callerToken, std::vector<uint32_t>& permCodeList) const
{
    permCodeList.clear();
    permCodeList.reserve(userPermissionList.size());
    std::map<uint32_t, bool> batchPolicyPersistFlags;
    for (const auto& policy : userPermissionList) {
        PermissionBriefDef briefDef;
        uint32_t code = 0;
        if (!GetPermissionBriefDef(policy.permissionName, briefDef, code)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Permission(%{public}s) is invalid.", policy.permissionName.c_str());
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        if (!IsSupportedPolicyApl(briefDef.availableLevel)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Permission(%{public}s) apl %{public}d is not supported.",
                policy.permissionName.c_str(), briefDef.availableLevel);
            return AccessTokenError::ERR_PARAM_INVALID;
        }

        const size_t len = policy.userPolicyList.size();
        if (len == 0) {
            return AccessTokenError::ERR_PARAM_INVALID;
        }

        auto [batchPolicyIter, isNewBatchPolicy] = batchPolicyPersistFlags.emplace(code, policy.isPersist);
        if (!isNewBatchPolicy) {
            if (batchPolicyIter->second != policy.isPersist) {
                return AccessTokenError::ERR_PERM_POLICY_PERSISTENCE_FLAG_NOT_MATCH;
            }
            LOGE(ATM_DOMAIN, ATM_TAG, "Permission(%{public}s) is duplicated.", policy.permissionName.c_str());
            return AccessTokenError::ERR_PARAM_INVALID;
        }

        auto recordIter = userPolicyRecords_.find(code);
        if (recordIter != userPolicyRecords_.end()) {
            if (recordIter->second.controllerToken != callerToken) {
                LOGE(ATM_DOMAIN, ATM_TAG, "Perm(%{public}s) is already set by %{public}u, currCaller(%{public}u).",
                    policy.permissionName.c_str(), recordIter->second.controllerToken, callerToken);
                return AccessTokenError::ERR_PERM_POLICY_ALREADY_SET_BY_OTHER;
            }
            if (recordIter->second.isPersist != policy.isPersist) {
                return AccessTokenError::ERR_PERM_POLICY_PERSISTENCE_FLAG_NOT_MATCH;
            }
        }

        for (size_t i = 0; i < len; ++i) {
            if (!DataValidator::IsUserIdValid(policy.userPolicyList[i].userId)) {
                return AccessTokenError::ERR_PARAM_INVALID;
            }
        }
        permCodeList.emplace_back(code);
    }
    return RET_SUCCESS;
}

int32_t UserPolicyManager::ValidateClearUserPolicy(const std::vector<std::string>& permissionList,
    AccessTokenID callerToken, std::vector<uint32_t>& permCodeList) const
{
    permCodeList.clear();
    permCodeList.reserve(permissionList.size());
    for (const auto& permission : permissionList) {
        uint32_t permCode = 0;
        if (!TransferPermissionToOpcode(permission, permCode)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Permission(%{public}s) is invalid.", permission.c_str());
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        auto recordIter = userPolicyRecords_.find(permCode);
        if (recordIter == userPolicyRecords_.end()) {
            return AccessTokenError::ERR_PERM_POLICY_NOT_SET;
        }
        if (recordIter->second.controllerToken != callerToken) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Permission(%{public}s) is already set by %{public}u, currCaller(%{public}u).",
                permission.c_str(), recordIter->second.controllerToken, callerToken);
            return AccessTokenError::ERR_PERM_POLICY_ALREADY_SET_BY_OTHER;
        }
        permCodeList.emplace_back(permCode);
    }
    return RET_SUCCESS;
}

std::map<uint32_t, UserPolicyRecord> UserPolicyManager::UpdateUserPolicyCache(
    const std::vector<UserPermissionPolicy>& userPermissionList, const std::vector<uint32_t>& permCodeList,
    AccessTokenID callerToken, std::vector<UserPolicyChange>& userPolicyChanges) const
{
    std::map<uint32_t, UserPolicyRecord> nextUserPolicyRecords = userPolicyRecords_;
    for (size_t index = 0; index < userPermissionList.size(); ++index) {
        const auto& policy = userPermissionList[index];
        uint32_t permCode = permCodeList[index];
        auto recordIter = nextUserPolicyRecords.find(permCode);
        bool hasPolicyRecord = recordIter != nextUserPolicyRecords.end(); // Whether this permission already has policy.
        UserPolicyRecord oldRecord;
        if (hasPolicyRecord) {
            oldRecord = recordIter->second;
        } else {
            oldRecord.isPersist = policy.isPersist;
        }

        std::vector<int32_t> userList = oldRecord.userList;
        std::set<int32_t> changedUserList = UpdateRestrictedUserList(policy.userPolicyList, userList);
        bool hasChangedUser = !changedUserList.empty(); // Whether any user's restricted state changed.
        if (userList.empty()) { // Empty user list means no policy record should remain for this permission.
            if (hasPolicyRecord) {
                nextUserPolicyRecords.erase(permCode);
            }
            if (!hasChangedUser) {
                continue;
            }
            userPolicyChanges.emplace_back(UserPolicyChange { permCode, oldRecord.isPersist,
                std::move(changedUserList) });
            continue;
        }

        UserPolicyRecord newRecord = oldRecord;
        newRecord.userList = std::move(userList);
        newRecord.controllerToken = callerToken;
        newRecord.isPersist = oldRecord.isPersist;
        nextUserPolicyRecords[permCode] = std::move(newRecord);
        if (!hasChangedUser) {
            continue;
        }
        userPolicyChanges.emplace_back(UserPolicyChange { permCode, oldRecord.isPersist, std::move(changedUserList) });
    }
    return nextUserPolicyRecords;
}

int32_t UserPolicyManager::UpdateUserPolicyDatabase(const std::vector<UserPolicyChange>& userPolicyChanges,
    const std::map<uint32_t, UserPolicyRecord>& nextUserPolicyRecords) const
{
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    for (const auto& change : userPolicyChanges) {
        std::string permissionName = TransferOpcodeToPermission(change.permCode);
        // Delete the current persisted row first, then insert the next persisted row if it still exists.
        auto oldIter = userPolicyRecords_.find(change.permCode);
        if (oldIter != userPolicyRecords_.end() && oldIter->second.isPersist) {
            delInfoVec.emplace_back(DelInfo {
                .delType = AtmDataType::ACCESSTOKEN_USER_POLICY,
                .delValue = BuildUserPolicyCondition(permissionName)
            });
        }

        auto nextRecordIter = nextUserPolicyRecords.find(change.permCode);
        if (nextRecordIter == nextUserPolicyRecords.end() || !nextRecordIter->second.isPersist) {
            continue;
        }
        addInfoVec.emplace_back(AddInfo {
            .addType = AtmDataType::ACCESSTOKEN_USER_POLICY,
            .addValues = { BuildUserPolicyValue(permissionName, nextRecordIter->second) }
        });
    }
    if (delInfoVec.empty() && addInfoVec.empty()) {
        return RET_SUCCESS;
    }
    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    return ret == RET_SUCCESS ? RET_SUCCESS : AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
}

int32_t UserPolicyManager::SetUserPolicy(const std::vector<UserPermissionPolicy>& userPermissionList,
    AccessTokenID callerToken, std::vector<UserPolicyChange>& userPolicyList)
{
    userPolicyList.clear();
    std::unique_lock<std::shared_mutex> infoGuard(this->userPolicyLock_);
    std::vector<uint32_t> permCodeList;
    int32_t ret = ValidateSetUserPolicy(userPermissionList, callerToken, permCodeList);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    std::vector<UserPolicyChange> userPolicyChanges;
    std::map<uint32_t, UserPolicyRecord> nextUserPolicyRecords = UpdateUserPolicyCache(
        userPermissionList, permCodeList, callerToken, userPolicyChanges);
    if (!nextUserPolicyRecords.empty() && !IsUserPolicyRecordsSizeValid(nextUserPolicyRecords)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "User policy cache size %{public}zu is invalid.", nextUserPolicyRecords.size());
        return AccessTokenError::ERR_OVERSIZE;
    }
    ret = UpdateUserPolicyDatabase(userPolicyChanges, nextUserPolicyRecords);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    // Update in-memory cache only after database refresh succeeds to keep cache and database consistent.
    userPolicyRecords_ = std::move(nextUserPolicyRecords);
    userPolicyList = std::move(userPolicyChanges);
    return RET_SUCCESS;
}

int32_t UserPolicyManager::ClearUserPolicy(const std::vector<std::string>& permissionList, AccessTokenID callerToken,
    std::vector<UserPolicyChange>& userPolicyList)
{
    userPolicyList.clear();
    std::unique_lock<std::shared_mutex> infoGuard(this->userPolicyLock_);
    std::vector<uint32_t> permCodeList;
    int32_t ret = ValidateClearUserPolicy(permissionList, callerToken, permCodeList);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    std::map<uint32_t, UserPolicyRecord> stagedRecords = userPolicyRecords_;
    std::vector<UserPolicyChange> stagedChanges;
    std::vector<DelInfo> delInfoVec;
    for (const auto& permCode : permCodeList) {
        auto recordIter = stagedRecords.find(permCode);
        if (recordIter == stagedRecords.end()) {
            continue;
        }
        std::set<int32_t> changedUserList;
        for (const auto& userId : recordIter->second.userList) {
            changedUserList.insert(userId);
        }
        std::string permissionName = TransferOpcodeToPermission(permCode);
        if (recordIter->second.isPersist) {
            delInfoVec.emplace_back(DelInfo {
                .delType = AtmDataType::ACCESSTOKEN_USER_POLICY,
                .delValue = BuildUserPolicyCondition(permissionName)
            });
        }
        stagedChanges.emplace_back(UserPolicyChange {
            .permCode = permCode,
            .isPersist = recordIter->second.isPersist,
            .changedUserList = std::move(changedUserList)
        });
        stagedRecords.erase(permCode);
    }

    if (!delInfoVec.empty()) {
        const std::vector<AddInfo> addInfoVec;
        ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
        if (ret != RET_SUCCESS) {
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }
    }
    // Update in-memory cache only after database refresh succeeds to keep cache and database consistent.
    userPolicyRecords_ = std::move(stagedRecords);
    userPolicyList = std::move(stagedChanges);
    return RET_SUCCESS;
}

int32_t UserPolicyManager::ValidatePolicyWhiteListUpdateLocked(
    const PolicyWhiteListUpdateInfo& context, const std::string& permission, UserPolicyRecord& record) const
{
    auto recordIter = userPolicyRecords_.find(context.permCode);
    if (recordIter == userPolicyRecords_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission(%{public}s) policy is not set.", permission.c_str());
        return AccessTokenError::ERR_PERM_POLICY_NOT_SET;
    }
    if (recordIter->second.controllerToken != context.callerToken) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission(%{public}s) is already set by %{public}u, currCaller(%{public}u).",
            permission.c_str(), recordIter->second.controllerToken, context.callerToken);
        return AccessTokenError::ERR_PERM_POLICY_ALREADY_SET_BY_OTHER;
    }

    UserPolicyRecord stagedRecord = recordIter->second;
    bool isRestricted = std::find(stagedRecord.userList.begin(), stagedRecord.userList.end(), context.userId) !=
        stagedRecord.userList.end();
    if (!isRestricted) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u userId %{public}d is not controlled by perm %{public}s.",
            context.tokenId, context.userId, permission.c_str());
        return AccessTokenError::ERR_TOKENID_NOT_IN_POLICY_USERLIST;
    }

    if (context.type == ADD) {
        if (stagedRecord.whiteList.find(context.tokenId) != stagedRecord.whiteList.end()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is already in whitelist.", context.tokenId);
            return AccessTokenError::ERR_TOKENID_ALREADY_IN_POLICY_WHITELIST;
        }
        size_t nextWhiteListSize = stagedRecord.whiteList.size() + 1;
        if (nextWhiteListSize > USER_POLICY_MAX_LIST_SIZE) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Permission(%{public}s) whitelist size %{public}zu is invalid.",
                permission.c_str(), nextWhiteListSize);
            return AccessTokenError::ERR_OVERSIZE;
        }
    } else {
        if (stagedRecord.whiteList.find(context.tokenId) == stagedRecord.whiteList.end()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Token %{public}u is not in whitelist.", context.tokenId);
            return AccessTokenError::ERR_TOKENID_NOT_IN_POLICY_WHITELIST;
        }
    }
    record = std::move(stagedRecord);
    return RET_SUCCESS;
}

int32_t UserPolicyManager::UpdatePolicyWhiteList(const PolicyWhiteListUpdateInfo& context)
{
    bool unusedPersist = false;
    return UpdatePolicyWhiteList(context, unusedPersist);
}

int32_t UserPolicyManager::UpdatePolicyWhiteList(const PolicyWhiteListUpdateInfo& context, bool& isPersist)
{
    std::string permission = TransferOpcodeToPermission(context.permCode);
    if (permission.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermCode %{public}u does not exist.", context.permCode);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    UserPolicyRecord stagedRecord;
    std::unique_lock<std::shared_mutex> infoGuard(this->userPolicyLock_);
    int32_t ret = ValidatePolicyWhiteListUpdateLocked(context, permission, stagedRecord);
    if (ret != RET_SUCCESS) {
        return ret;
    }
    isPersist = stagedRecord.isPersist;

    auto& whiteList = stagedRecord.whiteList;
    if (context.type == ADD) {
        whiteList.insert(context.tokenId);
    } else {
        whiteList.erase(context.tokenId);
    }

    if (stagedRecord.isPersist) {
        GenericValues modifyValue;
        modifyValue.Put(TokenFiledConst::FIELD_WHITLIST, SerializeWhiteTokenList(stagedRecord.whiteList));
        ret = AccessTokenDbOperator::Modify(AtmDataType::ACCESSTOKEN_USER_POLICY, modifyValue,
            BuildUserPolicyCondition(permission));
        if (ret != RET_SUCCESS) {
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }
    }

    userPolicyRecords_[context.permCode].whiteList = std::move(stagedRecord.whiteList);
    return RET_SUCCESS;
}

int32_t UserPolicyManager::RemoveTokenFromPolicyWhiteList(AccessTokenID tokenId)
{
    std::unique_lock<std::shared_mutex> infoGuard(this->userPolicyLock_);
    std::map<uint32_t, UserPolicyRecord> stagedRecords = userPolicyRecords_;
    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVec;
    bool hasChanged = false;

    for (auto& [permCode, record] : stagedRecords) {
        if (record.whiteList.erase(tokenId) == 0) {
            continue;
        }
        hasChanged = true;
        if (!record.isPersist) {
            continue;
        }

        std::string permissionName = TransferOpcodeToPermission(permCode);
        delInfoVec.emplace_back(DelInfo {
            .delType = AtmDataType::ACCESSTOKEN_USER_POLICY,
            .delValue = BuildUserPolicyCondition(permissionName)
        });

        addInfoVec.emplace_back(AddInfo {
            .addType = AtmDataType::ACCESSTOKEN_USER_POLICY,
            .addValues = { BuildUserPolicyValue(permissionName, record) }
        });
    }

    if (!hasChanged) {
        return RET_SUCCESS;
    }
    if ((!delInfoVec.empty()) || (!addInfoVec.empty())) {
        int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
        if (ret != RET_SUCCESS) {
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }
    }
    userPolicyRecords_ = std::move(stagedRecords);
    return RET_SUCCESS;
}

int32_t UserPolicyManager::GetPolicyWhiteList(uint32_t permCode, std::vector<AccessTokenID>& tokenIdList) const
{
    tokenIdList.clear();
    std::string permission = TransferOpcodeToPermission(permCode);
    if (permission.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermCode %{public}u does not exist.", permCode);
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    std::shared_lock<std::shared_mutex> infoGuard(this->userPolicyLock_);
    auto iter = userPolicyRecords_.find(permCode);
    if (iter != userPolicyRecords_.end()) {
        tokenIdList.assign(iter->second.whiteList.begin(), iter->second.whiteList.end());
    }
    return RET_SUCCESS;
}

void UserPolicyManager::UpdatePermissionStatusListForUserPolicy(
    AccessTokenID tokenId, int32_t userId, std::vector<PermissionStatus>& permStateList) const
{
    for (auto& permState : permStateList) {
        uint32_t permCode = 0;
        if (!TransferPermissionToOpcode(permState.permissionName, permCode)) {
            continue;
        }
        if (IsPermissionRestricted(tokenId, userId, permCode)) {
            permState.grantFlag |= PERMISSION_RESTRICTED_BY_ADMIN;
            continue;
        }
        permState.grantFlag =
            ConstantCommon::GetFlagWithoutSpecifiedElement(permState.grantFlag, PERMISSION_RESTRICTED_BY_ADMIN);
    }
}

bool UserPolicyManager::IsPermissionRestricted(AccessTokenID tokenId, int32_t userId, uint32_t permCode) const
{
    std::shared_lock<std::shared_mutex> infoGuard(this->userPolicyLock_);
    auto iter = userPolicyRecords_.find(permCode);
    if (iter == userPolicyRecords_.end()) {
        return false;
    }
    if (IsInPolicyWhiteList(tokenId, iter->second)) {
        return false;
    }
    if (std::find(iter->second.userList.begin(), iter->second.userList.end(), userId) != iter->second.userList.end()) {
        return true;
    }
    return false;
}

std::vector<uint32_t> UserPolicyManager::GetRestrictedPermListByUserId(int32_t userId) const
{
    std::vector<uint32_t> permList = {};
    std::shared_lock<std::shared_mutex> infoGuard(this->userPolicyLock_);
    for (const auto& [permCode, record] : userPolicyRecords_) {
        if (std::find(record.userList.begin(), record.userList.end(), userId) != record.userList.end()) {
            permList.emplace_back(permCode);
        }
    }
    return permList;
}

bool UserPolicyManager::IsPolicyPersisted(uint32_t permCode) const
{
    std::shared_lock<std::shared_mutex> infoGuard(this->userPolicyLock_);
    auto iter = userPolicyRecords_.find(permCode);
    return (iter != userPolicyRecords_.end()) && iter->second.isPersist;
}

int32_t UserPolicyManager::LoadPersistedPolicies()
{
    GenericValues conditionValue;
    std::vector<GenericValues> results;
    int32_t ret = AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_USER_POLICY, conditionValue, results);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    std::unique_lock<std::shared_mutex> infoGuard(this->userPolicyLock_);
    for (auto iter = userPolicyRecords_.begin(); iter != userPolicyRecords_.end();) {
        if (iter->second.isPersist) {
            iter = userPolicyRecords_.erase(iter);
            continue;
        }
        ++iter;
    }

    for (const auto& item : results) {
        std::string permissionName = item.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
        uint32_t permCode = 0;
        if (!TransferPermissionToOpcode(permissionName, permCode)) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Ignore invalid permission %{public}s from db.", permissionName.c_str());
            continue;
        }

        UserPolicyRecord record;
        record.controllerToken = static_cast<AccessTokenID>(item.GetInt(TokenFiledConst::FIELD_CONTROLLER_TOKENID));
        record.isPersist = true;
        if (!ParseUserList(item.GetString(TokenFiledConst::FIELD_RESTRICTED_USER), record.userList) ||
            !ParseWhiteTokenList(item.GetString(TokenFiledConst::FIELD_WHITLIST), record.whiteList) ||
            record.userList.empty()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Ignore invalid persisted policy %{public}s.", permissionName.c_str());
            continue;
        }
        userPolicyRecords_[permCode] = std::move(record);
    }
    return RET_SUCCESS;
}

bool UserPolicyManager::IsInPolicyWhiteList(AccessTokenID tokenId, const UserPolicyRecord& record) const
{
    return record.whiteList.find(tokenId) != record.whiteList.end();
}
#else
int32_t UserPolicyManager::SetUserPolicy(const std::vector<UserPermissionPolicy>&, AccessTokenID,
    std::vector<UserPolicyChange>& userPolicyList)
{
    userPolicyList.clear();
    return AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT;
}

int32_t UserPolicyManager::ClearUserPolicy(const std::vector<std::string>&, AccessTokenID,
    std::vector<UserPolicyChange>& userPolicyList)
{
    userPolicyList.clear();
    return AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT;
}

int32_t UserPolicyManager::UpdatePolicyWhiteList(const PolicyWhiteListUpdateInfo&)
{
    return AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT;
}

int32_t UserPolicyManager::UpdatePolicyWhiteList(const PolicyWhiteListUpdateInfo&, bool& isPersist)
{
    isPersist = false;
    return AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT;
}

int32_t UserPolicyManager::RemoveTokenFromPolicyWhiteList(AccessTokenID)
{
    return RET_SUCCESS;
}

int32_t UserPolicyManager::GetPolicyWhiteList(uint32_t, std::vector<AccessTokenID>& tokenIdList) const
{
    tokenIdList.clear();
    return AccessTokenError::ERR_CAPABILITY_NOT_SUPPORT;
}

void UserPolicyManager::UpdatePermissionStatusListForUserPolicy(
    AccessTokenID, int32_t, std::vector<PermissionStatus>&) const
{}

bool UserPolicyManager::IsPermissionRestricted(AccessTokenID, int32_t, uint32_t) const
{
    return false;
}

std::vector<uint32_t> UserPolicyManager::GetRestrictedPermListByUserId(int32_t) const
{
    return {};
}

bool UserPolicyManager::IsPolicyPersisted(uint32_t) const
{
    return false;
}

int32_t UserPolicyManager::LoadPersistedPolicies()
{
    return RET_SUCCESS;
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
