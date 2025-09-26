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
 * @file disable_policy_change_callback.h
 *
 * @brief Declares DisablePolicyChangeCallback class.
 *
 * @since 22.0
 * @version 22.0
 */

#ifndef SEC_AT_DISABLE_POLICY_CHANGE_CALLBACK_H
#define SEC_AT_DISABLE_POLICY_CHANGE_CALLBACK_H

#include <string>
#include <vector>

#include "perm_disable_policy_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Declares DisablePolicyChangeCallback class
 */
class DisablePolicyChangeCallback {
public:
    /**
     * @brief Constructor without any param.
     */
    DisablePolicyChangeCallback();
    /**
     * @brief Constructor with param.
     * @param permissionName permission name
     */
    explicit DisablePolicyChangeCallback(const std::vector<std::string>& permList);
    /**
     * @brief Destructor without any param.
     */
    virtual ~DisablePolicyChangeCallback();

    /**
     * @brief Pure virtual function for callback.
     * @param info PermDisablePolicyInfo quote
     */
    virtual void PermDisablePolicyCallback(const PermDisablePolicyInfo& info) = 0;

    /**
     * @brief Get private permission name list permList_.
     * @param permList string list quote as return value
     */
    void GetPermList(std::vector<std::string>& permList) const;

private:
    /** private variable permission name */
    std::vector<std::string> permList_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif  // SEC_AT_DISABLE_POLICY_CHANGE_CALLBACK_H