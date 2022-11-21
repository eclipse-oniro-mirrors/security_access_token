/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_HAP_TOKEN_INFO_INNER_H
#define ACCESSTOKEN_HAP_TOKEN_INFO_INNER_H

#include <memory>
#include <string>
#include <vector>

#include "access_token.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "permission_def.h"
#include "permission_policy_set.h"
#include "permission_state_full.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class HapTokenInfoInner final {
public:
    HapTokenInfoInner();
    HapTokenInfoInner(AccessTokenID id, const HapInfoParams& info, const HapPolicyParams& policy);
    HapTokenInfoInner(AccessTokenID id, const HapTokenInfo &info,
        const std::vector<PermissionStateFull>& permStateList);
    virtual ~HapTokenInfoInner();

    void Update(const std::string& appIDDesc, int32_t apiVersion, const HapPolicyParams& policy);
    void TranslateToHapTokenInfo(HapTokenInfo& infoParcel) const;
    void StoreHapInfo(std::vector<GenericValues>& hapInfoValues,
        std::vector<GenericValues>& permStateValues) const;
    int RestoreHapTokenInfo(AccessTokenID tokenId, const GenericValues& tokenValue,
        const std::vector<GenericValues>& permStateRes);

    std::shared_ptr<PermissionPolicySet> GetHapInfoPermissionPolicySet() const;
    HapTokenInfo GetHapInfoBasic() const;
    int GetUserID() const;
    int GetDlpType() const;
    std::string GetBundleName() const;
    int GetInstIndex() const;
    AccessTokenID GetTokenID() const;
    void SetTokenBaseInfo(const HapTokenInfo& baseInfo);
    void SetPermissionPolicySet(std::shared_ptr<PermissionPolicySet>& policySet);
    void ToString(std::string& info) const;
    bool IsRemote() const;
    void SetRemote(bool isRemote);

    uint64_t permUpdateTimestamp_;
private:
    void StoreHapBasicInfo(std::vector<GenericValues>& valueList) const;
    void TranslationIntoGenericValues(GenericValues& outGenericValues) const;
    int RestoreHapTokenBasicInfo(const GenericValues& inGenericValues);

    HapTokenInfo tokenInfoBasic_;

    // true means sync from remote.
    bool isRemote_;

    std::shared_ptr<PermissionPolicySet> permPolicySet_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_HAP_TOKEN_INFO_INNER_H
