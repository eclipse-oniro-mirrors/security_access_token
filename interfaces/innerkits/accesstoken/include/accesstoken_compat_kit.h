/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

/**
 * @addtogroup AccessToken
 * @{
 *
 * @brief Provides permission management.
 *
 * Provides tokenID-based application permission verification mechanism.
 * When an application accesses sensitive data or APIs, this module can check
 * whether the application has the corresponding permission. Allows applications
 * to query their access token information or APL levcels based on token IDs.
 *
 * @since 23
 * @version 23
 */

/**
 * @file accesstoken_compat_kit.h
 *
 * @brief Declares access token interfaces.
 *
 * @since 23
 * @version 23
 */

#ifndef INTERFACES_INNER_KITS_ACCESSTOKEN_COMPAT_KIT_H
#define INTERFACES_INNER_KITS_ACCESSTOKEN_COMPAT_KIT_H

#include <string>
#include <vector>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Declares hap token info class
 */
class HapTokenInfoCompat final {
public:
    /** bundle name of this hap */
    std::string bundleName;
    /** user id of this hap */
    int32_t userID = 0;
    /** instance index */
    int32_t instIndex = 0;
    /** which version of the SDK is used to develop this hap */
    int32_t apiVersion;
};

/**
 * @brief Declares AccessTokenCompatKit class
 */
class AccessTokenCompatKit {
public:
    /**
     * @brief Get token type from flag in tokenId, which doesn't depend on ATM service.
     * @param tokenID token id
     * @return token type enum, see access_token.h
     */
    static ATokenTypeEnum GetTokenTypeFlag(AccessTokenID tokenID);
    /**
     * @brief Get hap token info by token id.
     * @param tokenID token id
     * @param hapTokenInfo HapTokenInfoCompat quote, as query result
     * @return error code, see access_token_error.h
     */
    static int32_t GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoCompat& hapTokenInfo);
    /**
     * @brief Check whehter the input tokenID has been granted the input permission.
     * @param tokenID token id
     * @param permissionName permission to be checked
     * @return enum PermissionState, see access_token.h
     */
    static PermissionState VerifyAccessToken(AccessTokenID tokenID, const std::string& permission);
    /**
     * @brief Get tokenID by native process name.
     * @param processName native process name
     * @return token id of native process
     */
    static AccessTokenID GetNativeTokenId(const std::string& processName);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif
