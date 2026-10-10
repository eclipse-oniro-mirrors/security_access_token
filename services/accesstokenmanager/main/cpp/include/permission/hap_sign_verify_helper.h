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
    /**
     * @brief Parse the ACL extended map from the app service capabilities JSON string.
     * @param appServiceCapabilities JSON string containing the service capabilities.
     * @return Map of permission name to its extended value.
     */
    static std::map<std::string, std::string> ParseAclExtendedMap(const std::string& appServiceCapabilities);

    /**
     * @brief Build the owner ID by parsing the app identifier as a decimal number.
     * @param appIdentifier Application identifier string.
     * @return The parsed owner ID, or 0 when the identifier is empty, invalid or overflows uint64_t.
     */
    static uint64_t BuildOwnerId(const std::string& appIdentifier);

    /**
     * @brief Determine the process owner ID type.
     * @param isDebug Whether the app is a debug app.
     * @param appIdentifier Application identifier string.
     * @param permStateList Requested permission state list.
     * @return The process owner ID type constant.
     */
    static uint32_t BuildIdType(bool isDebug, const std::string& appIdentifier,
        const std::vector<PermissionStatus>& permStateList);

    /**
     * @brief Extract the token ID from a 64-bit token ID.
     * @param tokenIdEx The 64-bit token ID.
     * @return The lower 32-bit token ID.
     */
    static AccessTokenID GetTokenId(uint64_t tokenIdEx);

    /**
     * @brief Convert the APL string to the ATokenAplEnum.
     * @param apl APL string, whose valid values are "system_core" and "system_basic".
     * @return The corresponding ATokenAplEnum, or APL_NORMAL for unknown values.
     */
    static ATokenAplEnum ConvertApl(const std::string& apl);

    /**
     * @brief Convert the grant mode string to the GrantMode value.
     * @param grantMode Grant mode string, valid values are "system_grant" and "manual_settings".
     * @return The corresponding GrantMode, or USER_GRANT for unknown values.
     */
    static int ConvertGrantMode(const std::string& grantMode);

    /**
     * @brief Convert the available type string to the ATokenAvailableTypeEnum.
     * @param availableType Available type string, valid value is "mdm".
     * @return The corresponding ATokenAvailableTypeEnum, or NORMAL for unknown values.
     */
    static ATokenAvailableTypeEnum ConvertAvailableType(const std::string& availableType);

    /**
     * @brief Fill the permission definition list from the trusted bundle infos.
     * @param sortedInfos Sorted trusted bundle info list.
     * @param permList Output permission definition list.
     */
    static void FillPermissionDefList(const std::vector<TrustedBundleInfoInner>& sortedInfos,
        std::vector<PermissionDef>& permList);

    /**
     * @brief Fill the ACL requested list from the trusted bundle infos.
     * @param sortedInfos Sorted trusted bundle info list.
     * @param aclRequestedList Output ACL requested permission name list.
     */
    static void FillAclRequestedList(const std::vector<TrustedBundleInfoInner>& sortedInfos,
        std::vector<std::string>& aclRequestedList);

    /**
     * @brief Fill the ACL extended map from the trusted bundle infos.
     * @param sortedInfos Sorted trusted bundle info list.
     * @param aclExtendedMap Output ACL extended map.
     */
    static void FillAclExtendedMap(const std::vector<TrustedBundleInfoInner>& sortedInfos,
        std::map<std::string, std::string>& aclExtendedMap);

    /**
     * @brief Fill the permission state list from the trusted bundle infos.
     * @param sortedInfos Sorted trusted bundle info list.
     * @param permStateList Output permission state list.
     */
    static void FillPermissionStateList(const std::vector<TrustedBundleInfoInner>& sortedInfos,
        std::vector<PermissionStatus>& permStateList);

    /**
     * @brief Build the brief permission data list from the hap policy.
     * @param policy Hap policy.
     * @param permBriefDataList Output brief permission data list.
     */
    static void BuildPermBriefDataListFromPolicy(const HapPolicy& policy,
        std::vector<BriefPermData>& permBriefDataList);

    /**
     * @brief Build the permission with value list from the hap policy.
     * @param policy Hap policy.
     * @param extendPermList Output permission with value list.
     */
    static void BuildExtendPermListFromPolicy(const HapPolicy& policy,
        std::vector<PermissionWithValue>& extendPermList);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_HAP_SIGN_VERIFY_HELPER_H
