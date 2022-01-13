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
    HapTokenInfoInner() : ver_(DEFAULT_TOKEN_VERSION), tokenID_(0), tokenAttr_(0), userID_(0),
        instIndex_(0), apl_(APL_NORMAL) {};
    virtual ~HapTokenInfoInner();

    void Init(AccessTokenID id, const HapInfoParams& info, const HapPolicyParams& policy);
    void Update(const std::string& appIDDesc, const HapPolicyParams& policy);
    void TranslateToHapTokenInfo(HapTokenInfo& InfoParcel) const;
    void StoreHapInfo(std::vector<GenericValues>& hapInfoValues,
        std::vector<GenericValues>& permDefValues,
        std::vector<GenericValues>& permStateValues) const;
    int RestoreHapTokenInfo(AccessTokenID tokenId, GenericValues& tokenValue,
        const std::vector<GenericValues>& permDefRes, const std::vector<GenericValues>& permStateRes);

    std::shared_ptr<PermissionPolicySet> GetHapInfoPermissionPolicySet() const;
    int GetUserID() const;
    std::string GetBundleName() const;
    int GetInstIndex() const;
    AccessTokenID GetTokenID() const;
    void ToString(std::string& info) const;

private:
    void StoreHapBasicInfo(std::vector<GenericValues>& valueList) const;
    void TranslationIntoGenericValues(GenericValues& outGenericValues) const;
    int RestoreHapTokenBasicInfo(const GenericValues& inGenericValues);

    char ver_;
    AccessTokenID tokenID_;
    AccessTokenAttr tokenAttr_;
    int userID_;
    std::string bundleName_;
    int instIndex_;
    std::string appID_;
    std::string deviceID_;
    ATokenAplEnum apl_;
    std::shared_ptr<PermissionPolicySet> permPolicySet_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_HAP_TOKEN_INFO_INNER_H
