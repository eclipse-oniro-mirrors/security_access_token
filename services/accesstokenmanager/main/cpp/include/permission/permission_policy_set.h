/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef PERMISSION_POLICY_SET_H
#define PERMISSION_POLICY_SET_H

#include <memory>
#include <string>
#include <vector>

#include "access_token.h"
#include "callback_manager.h"
#include "generic_values.h"
#include "permission_def.h"
#include "permission_state_full.h"
#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct PermissionPolicySet final {
public:
    PermissionPolicySet() : tokenId_(0) {}
    virtual ~PermissionPolicySet();

    static std::shared_ptr<PermissionPolicySet> BuildPermissionPolicySet(AccessTokenID tokenId,
        const std::vector<PermissionStateFull>& permStateList);
    static std::shared_ptr<PermissionPolicySet> BuildPolicySetWithoutDefCheck(AccessTokenID tokenId,
        const std::vector<PermissionStateFull>& permStateList);
    static std::shared_ptr<PermissionPolicySet> RestorePermissionPolicy(AccessTokenID tokenId,
        const std::vector<GenericValues>& permStateRes);
    void StorePermissionPolicySet(std::vector<GenericValues>& permStateValueList);
    void Update(const std::vector<PermissionStateFull>& permStateList);

    PermUsedTypeEnum GetUserGrantedPermissionUsedType(const std::string& permissionName);
    int VerifyPermissionStatus(const std::string& permissionName);
    void GetDefPermissions(std::vector<PermissionDef>& permList);
    void GetPermissionStateFulls(std::vector<PermissionStateFull>& permList);
    int QueryPermissionFlag(const std::string& permissionName, int& flag);
    int32_t UpdatePermissionStatus(const std::string& permissionName, bool isGranted, uint32_t flag);
    void ToString(std::string& info);
    bool IsPermissionReqValid(int32_t tokenApl, const std::string& permissionName,
        const std::vector<std::string>& nativeAcls);
    void PermStateToString(int32_t tokenApl, const std::vector<std::string>& nativeAcls, std::string& info);
    void GetPermissionStateList(std::vector<PermissionStateFull>& stateList);
    void ResetUserGrantPermissionStatus(void);
    void ClearSecCompGrantedPerm(void);
    static uint32_t GetFlagWithoutSpecifiedElement(uint32_t fullFlag, uint32_t removedFlag);
    static uint32_t GetFlagWroteToDb(uint32_t grantFlag);
    void GetDeletedPermissionListToNotify(std::vector<std::string>& permissionList);
    void GetGrantedPermissionList(std::vector<std::string>& permissionList);

    void GetPermissionStateList(std::vector<uint32_t>& opCodeList, std::vector<bool>& statusList);
private:
    static void MergePermissionStateFull(std::vector<PermissionStateFull>& permStateList,
        PermissionStateFull& state);
    void UpdatePermStateFull(const PermissionStateFull& permOld, PermissionStateFull& permNew);
    void StorePermissionDef(std::vector<GenericValues>& valueList) const;
    void StorePermissionState(std::vector<GenericValues>& valueList) const;
    void PermDefToString(const PermissionDef& def, std::string& info) const;
    void PermStateFullToString(const PermissionStateFull& state, std::string& info) const;
    int32_t UpdateSecCompGrantedPermList(const std::string& permissionName, bool isGranted);
    int32_t UpdatePermStateList(const std::string& permissionName, bool isGranted, uint32_t flag);
    void SetPermissionFlag(const std::string& permissionName, uint32_t flag, bool needToAdd);
    void SecCompGrantedPermListUpdated(const std::string& permissionName, bool isToGrant);
    OHOS::Utils::RWLock permPolicySetLock_;
    std::vector<PermissionStateFull> permStateList_;
    std::vector<std::string> secCompGrantedPermList_;
    AccessTokenID tokenId_;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif  // PERMISSION_POLICY_SET_H

