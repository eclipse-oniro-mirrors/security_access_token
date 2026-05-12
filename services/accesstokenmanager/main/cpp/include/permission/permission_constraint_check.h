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

#ifndef PERMISSION_CONSTRAINT_CHECK_H
#define PERMISSION_CONSTRAINT_CHECK_H

#include <memory>

#include "hap_data_structure.h"
#include "hap_token_info.h"
#include "permission_data_brief.h"
#include "permission_map.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionConstraintCheck final {
public:
    static bool AclAndEdmCheck(const BundleParam& param, const PermissionBriefDef& briefDef,
        const HapPolicy& policy, HapInfoCheckResult& result);
    static bool IsAclSatisfied(const PermissionBriefDef& briefDef, const HapPolicy& policy);
    static bool IsPermAvailableRangeSatisfied(const BundleParam& param, const PermissionBriefDef& briefDef,
        PermissionRulesEnum& rule);
    static int BuildIdType(const BundleParam& param, const HapPolicy& policy);
    static void FixBriefPermData(
        const BundleInfoInner& infoInner, int32_t dlpType, std::vector<BriefPermData>& data, bool& isFixed);

private:
    PermissionConstraintCheck() = delete;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // PERMISSION_CONSTRAINT_CHECK_H
