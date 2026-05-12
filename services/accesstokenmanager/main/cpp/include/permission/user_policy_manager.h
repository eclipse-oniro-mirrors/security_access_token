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

#ifndef USER_POLICY_MANAGER_H
#define USER_POLICY_MANAGER_H

#include <map>
#include <set>
#include <shared_mutex>
#include <unordered_set>
#include <vector>

#include "access_token.h"
#include "access_token_error.h"
#include "atm_data_type.h"
#include "nocopyable.h"
#include "permission_status.h"
#include "user_policy_types.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct UserPolicyRecord {
    std::vector<int32_t> userList;
    AccessTokenID controllerToken = INVALID_TOKENID;
    std::unordered_set<AccessTokenID> whiteList;
    bool isPersist = false;
};

struct PolicyWhiteListUpdateInfo {
    AccessTokenID tokenId = INVALID_TOKENID;
    int32_t userId = 0;
    uint32_t permCode = 0;
    UpdateWhiteListType type = ADD;
    AccessTokenID callerToken = INVALID_TOKENID;
};

class UserPolicyManager final {
public:
    static UserPolicyManager& GetInstance();
    ~UserPolicyManager() = default;

    int32_t SetUserPolicy(const std::vector<UserPermissionPolicy>& userPermissionList, AccessTokenID callerToken,
        std::vector<UserPolicyChange>& userPolicyList);
    int32_t ClearUserPolicy(const std::vector<std::string>& permissionList, AccessTokenID callerToken,
        std::vector<UserPolicyChange>& userPolicyList);
    int32_t UpdatePolicyWhiteList(const PolicyWhiteListUpdateInfo& context);
    int32_t UpdatePolicyWhiteList(const PolicyWhiteListUpdateInfo& context, bool& isPersist);
    int32_t RemoveTokenFromPolicyWhiteList(AccessTokenID tokenId);
    int32_t GetPolicyWhiteList(uint32_t permCode, std::vector<AccessTokenID>& tokenIdList) const;
    void UpdatePermissionStatusListForUserPolicy(
        AccessTokenID tokenId, int32_t userId, std::vector<PermissionStatus>& permStateList) const;
    bool IsPermissionRestricted(AccessTokenID tokenId, int32_t userId, uint32_t permCode) const;
    std::vector<uint32_t> GetRestrictedPermListByUserId(int32_t userId) const;
    bool IsPolicyPersisted(uint32_t permCode) const;
    int32_t LoadPersistedPolicies();

private:
    UserPolicyManager() = default;
    DISALLOW_COPY_AND_MOVE(UserPolicyManager);

#ifdef SUPPORT_MANAGE_USER_POLICY
    int32_t ValidateSetUserPolicy(const std::vector<UserPermissionPolicy>& userPermissionList,
        AccessTokenID callerToken, std::vector<uint32_t>& permCodeList) const;
    int32_t ValidateClearUserPolicy(const std::vector<std::string>& permissionList,
        AccessTokenID callerToken, std::vector<uint32_t>& permCodeList) const;
    std::map<uint32_t, UserPolicyRecord> UpdateUserPolicyCache(
        const std::vector<UserPermissionPolicy>& userPermissionList, const std::vector<uint32_t>& permCodeList,
        AccessTokenID callerToken, std::vector<UserPolicyChange>& userPolicyChanges) const;
    // Builds and commits all persistence operations for permissions modified by the staged update.
    int32_t UpdateUserPolicyDatabase(const std::vector<UserPolicyChange>& userPolicyChanges,
        const std::map<uint32_t, UserPolicyRecord>& nextUserPolicyRecords) const;
    int32_t ValidatePolicyWhiteListUpdateLocked(
        const PolicyWhiteListUpdateInfo& context, const std::string& permission, UserPolicyRecord& record) const;
    // Caller must hold userPolicyLock_.
    bool IsInPolicyWhiteList(AccessTokenID tokenId, const UserPolicyRecord& record) const;

    mutable std::shared_mutex userPolicyLock_;
    std::map<uint32_t, UserPolicyRecord> userPolicyRecords_; // key-permCode, value-policy record
#endif
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // USER_POLICY_MANAGER_H
