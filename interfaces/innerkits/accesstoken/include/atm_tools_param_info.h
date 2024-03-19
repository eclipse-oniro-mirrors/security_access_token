/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 * @file atm_tools_param_info.h
 *
 * @brief Declares atm tools param infos.
 *
 * @since 11.0
 * @version 11.0
 */

#ifndef ATM_TOOLS_PARAM_INFO_H
#define ATM_TOOLS_PARAM_INFO_H

#include "access_token.h"
#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Declares atm tools param class
 */

/**
 * @brief Atm tools param info
 */
class AtmToolsParamInfo final {
public:
    /**
     * operate type, for details about the valid values,
     * see the definition of OptType in the access_token.h file.
     */
    OptType type = DEFAULT_OPER;
    union {
        AccessTokenID tokenId = 0;
        int32_t userID;
    };
    uint32_t status = 0;
    std::string permissionName;
    std::string bundleName;
    std::string processName;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ATM_TOOLS_PARAM_INFO_H
