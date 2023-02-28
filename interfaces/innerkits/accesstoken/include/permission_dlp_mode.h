/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
 * @brief Provides permission management interfaces.
 *
 * Provides tokenID-based application permission verification mechanism.
 * When an application accesses sensitive data or APIs, this module can check
 * whether the application has the corresponding permission. Allows applications
 * to query their access token information or APL levcels based on token IDs.
 *
 * @since 7.0
 * @version 7.0
 */

/**
 * @file permission_dlp_mode.h
 *
 * @brief Declares permission dlp mode class.
 *
 * @since 8.0
 * @version 8.0
 */

#ifndef INTERFACES_INNER_KITS_ACCESSTOKEN_PERMISSION_DLP_MODE_H
#define INTERFACES_INNER_KITS_ACCESSTOKEN_PERMISSION_DLP_MODE_H

#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Declares permission dlp mode class
 */
class PermissionDlpMode final {
public:
    std::string permissionName;
    /**
     * dlp mode, for details about the valid values,
     * see the definition of DlpPermMode in the access_token.h file
     */
    int32_t dlpMode;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // INTERFACES_INNER_KITS_ACCESSTOKEN_PERMISSION_DLP_MODE_H
