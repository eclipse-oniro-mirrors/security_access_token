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

#ifndef AUTOMATION_CONTROL_TYPES_H
#define AUTOMATION_CONTROL_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

/**
 * @brief Automation control switch status.
 */
enum AutomationControlStatus {
    AUTOMATION_CONTROL_DISABLED = 0,  // Disable automation control for the target
    AUTOMATION_CONTROL_ENABLED = 1,   // Enable automation control for the target
};

/**
 * @brief Per-element result for SetAutomationControlStatus.
 */
enum AutomationControlSetResult {
    AUTOMATION_CONTROL_SET_SUCCESS = 0,            // Target set successfully
    AUTOMATION_CONTROL_SET_TOKEN_ID_NOT_EXIST = 1, // Target tokenId not exist or not HAP
};

/**
 * @brief Input parameter for SetAutomationControlStatus (per-element).
 */
struct AutomationControlTargetParam final {
    AccessTokenID targetTokenID = 0;                // Target tokenId to control
    int32_t status = AUTOMATION_CONTROL_DISABLED;   // Switch status (DISABLED/ENABLED)
};

/**
 * @brief Output result for GetAutomationControlTargets (per-element).
 */
struct AutomationControlTargetResult final {
    AccessTokenID targetTokenID = 0;                 // Target tokenId
    int32_t status = AUTOMATION_CONTROL_DISABLED;    // Current switch status
    std::string bundleName;                          // Target bundle name
};

/**
 * @brief Output result for GetAutomationControlControllers (per-element).
 */
struct AutomationControlControllerInfo final {
    AccessTokenID controllerTokenID = 0;  // Controller tokenId
    std::string bundleName;               // Controller bundle name
};

/**
 * @brief Per-element decision for CheckAutomationControlAccess.
 */
enum AutomationControlAccessDecision {
    TARGET_NOT_EXIST = 1,          // Target tokenId not exist or not HAP
    POPUP_NEEDED = 2,              // No record found, popup is needed
    NO_POPUP_NEEDED_GRANTED = 3,   // Controller set ENABLED for the target
    NO_POPUP_NEEDED_DENIED = 4,    // Controller set DISABLED for the target
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // AUTOMATION_CONTROL_TYPES_H
