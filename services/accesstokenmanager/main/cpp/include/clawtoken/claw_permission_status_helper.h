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

#ifndef SERVICES_ACCESSTOKENMANAGER_CLAW_PERMISSION_STATUS_HELPER_H
#define SERVICES_ACCESSTOKENMANAGER_CLAW_PERMISSION_STATUS_HELPER_H

#include <string>
#include <unordered_map>

#include "access_token.h"
#include "permission_status.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
using PermissionStatusMap = std::unordered_map<std::string, PermissionStatus>;

bool IsUserDeniedFlag(uint32_t flag);
bool IsRestrictedFlag(uint32_t flag);
bool IsAllowThisTimeFlag(uint32_t flag);
bool IsGrantedWithoutDialog(const PermissionStatus& status);
int32_t BuildPermissionStatusMap(AccessTokenID tokenId, PermissionStatusMap& permissionStatusMap);
bool ResolveCliGrantedPermission(const PermissionStatusMap& permissionStatusMap,
    const std::string& permissionName, bool cliAuthorizationResult);
int32_t TransferErrorCode(int32_t ret);
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // SERVICES_ACCESSTOKENMANAGER_CLAW_PERMISSION_STATUS_HELPER_H
