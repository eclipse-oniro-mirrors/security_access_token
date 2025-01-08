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
#include "generic_values.h"
#include "permission_def.h"
#include "permission_data_brief.h"
#include "permission_status.h"
#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct PermissionPolicySet final {
public:
    PermissionPolicySet() : tokenId_(0) {}
    virtual ~PermissionPolicySet();

    static std::shared_ptr<PermissionPolicySet> BuildPermissionPolicySet(AccessTokenID tokenId,
        const std::vector<PermissionStatus>& permStateList);
    static std::shared_ptr<PermissionPolicySet> BuildPolicySetWithoutDefCheck(AccessTokenID tokenId,
        const std::vector<PermissionStatus>& permStateList);
    static std::shared_ptr<PermissionPolicySet> RestorePermissionPolicy(AccessTokenID tokenId,
        const std::vector<GenericValues>& permStateRes);
    void StorePermissionPolicySet(std::vector<GenericValues>& permStateValueList);
    void Update(const std::vector<PermissionStatus>& permStateList);

    PermUsedTypeEnum GetPermissionUsedType(const std::string& permissionName);
    void GetDefPermissions(std::vector<PermissionDef>& permList);
    bool IsPermissionGrantedWithSecComp(const std::string& permissionName);
    int QueryPermissionFlag(const std::string& permissionName, int& flag);
    int32_t UpdatePermissionStatus(
        const std::string& permissionName, bool isGranted, uint32_t flag, bool& statusChanged);
    void ToString(std::string& info);
    static void ToString(std::string& info, const std::vector<PermissionDef>& permList,
        const std::vector<PermissionStatus>& permStateList);
    bool IsPermissionReqValid(int32_t tokenApl, const std::string& permissionName,
        const std::vector<std::string>& nativeAcls);
    void PermStateToString(int32_t tokenApl, const std::vector<std::string>& nativeAcls, std::string& info);
    void GetPermissionStateList(std::vector<PermissionStatus>& stateList);
    void ResetUserGrantPermissionStatus(void);
    static uint32_t GetFlagWroteToDb(uint32_t grantFlag);
    void GetPermissionStateList(std::vector<uint32_t>& opCodeList, std::vector<bool>& statusList);
    uint32_t GetReqPermissionSize();
    static std::shared_ptr<PermissionPolicySet> BuildPermissionPolicySetFromDb(
        AccessTokenID tokenId, const std::vector<GenericValues>& permStateRes);
private:
    static void GetPermissionBriefData(std::vector<BriefPermData>& list,
        const std::vector<PermissionStatus> &permStateList);
    static void MergePermissionStatus(std::vector<PermissionStatus>& permStateList,
        PermissionStatus& state);
    void UpdatePermStatus(const PermissionStatus& permOld, PermissionStatus& permNew);
    void StorePermissionDef(std::vector<GenericValues>& valueList) const;
    void StorePermissionState(std::vector<GenericValues>& valueList) const;
    int32_t UpdateSecCompGrantedPermList(const std::string& permissionName, bool isGranted);
    int32_t UpdatePermStateList(const std::string& permissionName, bool isGranted, uint32_t flag);
    void SetPermissionFlag(const std::string& permissionName, uint32_t flag, bool needToAdd);
    OHOS::Utils::RWLock permPolicySetLock_;
    std::vector<PermissionStatus> permStateList_;
    std::vector<std::string> secCompGrantedPermList_;
    AccessTokenID tokenId_;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif  // PERMISSION_POLICY_SET_H

