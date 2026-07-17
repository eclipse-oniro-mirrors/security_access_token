/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#ifndef PERMISSION_MAP_H
#define PERMISSION_MAP_H

#include <map>
#include <string>
#include <vector>
#include "access_token.h"

#include "access_token.h"
#include "permission_def.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct PermissionBriefDef {
    const char* permissionName;
    GrantMode grantMode;
    ATokenAplEnum availableLevel;
    ATokenAvailableTypeEnum availableType;
    bool provisionEnable;
    bool distributedSceneEnable;
    bool isKernelEffect;
    bool hasValue;
    bool isEnable;
};

bool TransferPermissionToOpcode(const std::string& permissionName, uint32_t& opCode);
std::string TransferOpcodeToPermission(uint32_t opCode);
__attribute__((visibility("default"))) bool QueryRequredPermissions(
    const std::string& cliPermission, std::vector<std::string>& requiredPermission);
__attribute__((visibility("default"))) bool QueryMappedPermissionsByCliPermission(
    const std::string& cliPermission, std::vector<std::string>& mappedPermissions);
bool IsUserGrantPermission(const std::string& permission);
bool IsOperablePermission(const std::string& permission);
// Only allowed on the server side. Do not use in client-side code.
bool IsDefinedPermissionInner(const std::string& permission);
bool GetPermissionBriefDef(const std::string& permission, PermissionBriefDef& permissionBriefDef);
bool GetPermissionBriefDef(const std::string& permission, PermissionBriefDef& permissionBriefDef, uint32_t& opCode);
void GetPermissionBriefDef(uint32_t code, PermissionBriefDef& permissionBriefDef);
void ConvertPermissionBriefToDef(const PermissionBriefDef& briefDef, PermissionDef& def);
bool IsPermissionValidForHap(const std::string& permissionName);
size_t GetDefPermissionsSize();
const char* GetPermDefVersion();
bool SetPermissionBriefEnabled(const std::string& permissionName, bool isEnable);
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_CODE_H
