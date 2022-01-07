/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "permission_def.h"
#include "permission_state_full.h"
#include "access_token.h"
#include "generic_values.h"

#include <vector>
#include <string>
#include <memory>

namespace OHOS {
namespace Security {
namespace AccessToken {
struct PermissionPolicySet final {
public:
    PermissionPolicySet() : tokenId_(0) {};
    virtual ~PermissionPolicySet() {};

    static std::shared_ptr<PermissionPolicySet> BuildPermissionPolicySet(AccessTokenID tokenId,
        const std::vector<PermissionDef>& permList, const std::vector<PermissionStateFull>& permStateList);
    static std::shared_ptr<PermissionPolicySet> RestorePermissionPolicy(AccessTokenID tokenId,
        const std::vector<GenericValues>& permDefRes, const std::vector<GenericValues>& permStateRes);
    void StorePermissionPolicySet(std::vector<GenericValues>& permDefValueList,
        std::vector<GenericValues>& permStateValueList) const;
    void Update(const std::vector<PermissionDef>& permList, const std::vector<PermissionStateFull>& permStateList);
    void ToString(std::string& info) const;
    std::vector<PermissionDef> permList_;
    std::vector<PermissionStateFull> permStateList_;

private:
    static void MergePermissionStateFull(std::vector<PermissionStateFull>& permStateList,
        const PermissionStateFull& state);
    void UpdatePermStateFull(PermissionStateFull& permOld, const PermissionStateFull& permNew);
    void UpdatePermDef(PermissionDef& permOld, const PermissionDef& permNew);
    void StorePermissionDef(std::vector<GenericValues>& valueList) const;
    void StorePermissionState(std::vector<GenericValues>& valueList) const;
    void PermDefToString(const PermissionDef& def, std::string& info) const;
    void PermStateFullToString(const PermissionStateFull& state, std::string& info) const;
    AccessTokenID tokenId_;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif  // PERMISSION_POLICY_SET_H

