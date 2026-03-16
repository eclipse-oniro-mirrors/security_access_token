/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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
 * @file active_change_response_info.h
 *
 * @brief Declares enum ActiveChangeType and struct ActiveChangeResponse.
 *
 * @since 8.0
 * @version 8.0
 */

#ifndef ACTIVE_CHANGE_RESPONSE_INFO_H
#define ACTIVE_CHANGE_RESPONSE_INFO_H

#include <string>
#include <vector>

#include "access_token.h"
#include "permission_used_type.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Permission active state state values
 */
enum ActiveChangeType {
    PERM_INACTIVE = 0,
    PERM_ACTIVE_IN_FOREGROUND = 1,
    PERM_ACTIVE_IN_BACKGROUND = 2,
    PERM_TEMPORARY_CALL = 3,
    PERM_REMOTE_USING = 4,
    PERM_ADD = 5,
};

/**
 * @brief Permission lockscreen state values
 */
enum LockScreenStatusChangeType {
    PERM_ACTIVE_IN_UNLOCKED = 1,
    PERM_ACTIVE_IN_LOCKED = 2,
};

/**
 * @brief Permission active state change response struct
 */
struct ActiveChangeResponse {
    AccessTokenID callingTokenID = INVALID_TOKENID;
    AccessTokenID tokenID = INVALID_TOKENID;
    std::string permissionName;
    /**
     * permission active change type, for details about the valid values,
     * see the definition above.
     */
    ActiveChangeType type = PERM_INACTIVE;
    PermissionUsedType usedType = NORMAL_TYPE;
    int32_t pid = -1;
    bool isRemote = false;
    std::string deviceId;
    std::string remoteDeviceName;
    /** extra info propagated from AddPermParamInfo::extra for PERM_ADD callback */
    std::string extra = "";
    /**
     * This field is only filled in callbacks triggered by bundle-based start/stop using permission.
     * The callback contains the bundle name, permission name of this access.
     */
    std::string bundleName;

    ActiveChangeResponse() = default;

    // Used by token-based active records and current-using queries.
    ActiveChangeResponse(AccessTokenID callingTokenID, AccessTokenID tokenID, const std::string& permissionName,
        ActiveChangeType type, PermissionUsedType usedType, int32_t pid = -1)
        : callingTokenID(callingTokenID), tokenID(tokenID), permissionName(permissionName), type(type),
          usedType(usedType), pid(pid)
    {}

    // Used by bundle-based current-using queries.
    ActiveChangeResponse(const std::string& bundleName, const std::string& permissionName)
        : permissionName(permissionName), type(PERM_ACTIVE_IN_FOREGROUND), bundleName(bundleName)
    {}

    // Used by remote permission active records and callbacks.
    ActiveChangeResponse(const std::string& permissionName, const std::string& deviceId,
        const std::string& remoteDeviceName)
        : permissionName(permissionName), type(PERM_REMOTE_USING), isRemote(true), deviceId(deviceId),
          remoteDeviceName(remoteDeviceName)
    {}
};

typedef ActiveChangeResponse CurrUsingPermInfo;
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACTIVE_CHANGE_RESPONSE_INFO_H
