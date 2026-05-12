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

#ifndef PERMISSION_REQUEST_TOGGLE_MANAGER_H
#define PERMISSION_REQUEST_TOGGLE_MANAGER_H

#include <cstdint>
#include <string>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionRequestToggleManager final {
public:
    static PermissionRequestToggleManager& GetInstance();

    int32_t SetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t status, int32_t userID);
    int32_t GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status, int32_t userID);

private:
    PermissionRequestToggleManager() = default;
    ~PermissionRequestToggleManager() = default;
    PermissionRequestToggleManager(const PermissionRequestToggleManager&) = delete;
    PermissionRequestToggleManager& operator=(const PermissionRequestToggleManager&) = delete;
    PermissionRequestToggleManager(PermissionRequestToggleManager&&) = delete;
    PermissionRequestToggleManager& operator=(PermissionRequestToggleManager&&) = delete;

    int32_t AddPermRequestToggleStatusToDb(int32_t userID, const std::string& permissionName, int32_t status);
    int32_t FindPermRequestToggleStatusFromDb(int32_t userID, const std::string& permissionName);
    int32_t ResolveUserId(int32_t userID) const;
    int32_t ValidatePermissionForToggle(const std::string& permissionName, int32_t userID) const;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_REQUEST_TOGGLE_MANAGER_H
