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
 * @addtogroup Privacy
 * @{
 *
 * @brief Provides sensitive data access management.
 *
 * @since 8.0
 * @version 8.0
 */

/**
 * @file perm_disable_info.h
 *
 * @brief Declares struct PermDisableInfo.
 *
 * @since 22.0
 * @version 22.0
 */

#ifndef SEC_AT_PERM_DISABLE_POLICY_INFO_H
#define SEC_AT_PERM_DISABLE_POLICY_INFO_H

#include <string>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Permission disable policy info struct
 */
struct PermDisablePolicyInfo {
    PermDisablePolicyInfo() = default;
    PermDisablePolicyInfo(const std::string& permissionName, bool isDisable)
        : permissionName(permissionName), isDisable(isDisable) {}

    std::string permissionName;
    bool isDisable;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // SEC_AT_PERM_DISABLE_POLICY_INFO_H