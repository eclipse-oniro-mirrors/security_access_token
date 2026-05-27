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

#ifndef ACCESS_TOKEN_HAP_SIGN_VERIFY_HELPER_H
#define ACCESS_TOKEN_HAP_SIGN_VERIFY_HELPER_H

#include <map>
#include <string>
#include <vector>

#include "access_token.h"
#include "hap_sign_verify_manager.h"
#include "hap_token_info_inner.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class HapSignVerifyHelper final {
public:
    static std::map<std::string, std::string> ParseAclExtendedMap(const std::string& appServiceCapabilities);
    static uint64_t BuildOwnerId(const std::string& appIdentifier);
    static AccessTokenID GetTokenId(uint64_t tokenIdEx);

    static ATokenAplEnum ConvertApl(const std::string& apl);
    static int ConvertGrantMode(const std::string& grantMode);
    static ATokenAvailableTypeEnum ConvertAvailableType(const std::string& availableType);
    static void FillPermissionDefList(const std::vector<TrustedBundleInfoInner>& sortedInfos,
        std::vector<PermissionDef>& permList);
    static void FillAclRequestedList(const std::vector<TrustedBundleInfoInner>& sortedInfos,
        std::vector<std::string>& aclRequestedList);
    static void FillAclExtendedMap(const std::vector<TrustedBundleInfoInner>& sortedInfos,
        std::map<std::string, std::string>& aclExtendedMap);
    static void FillPermissionStateList(const std::vector<TrustedBundleInfoInner>& sortedInfos,
        std::vector<PermissionStatus>& permStateList);
    static void BuildPermBriefDataListFromPolicy(const HapPolicy& policy,
        std::vector<BriefPermData>& permBriefDataList);
    static void BuildExtendPermListFromPolicy(const HapPolicy& policy,
        std::vector<PermissionWithValue>& extendPermList);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_HAP_SIGN_VERIFY_HELPER_H
