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
#include "permission_map.h"
#include "cli_permisison_map.h"
#include "permission_map_constant.h"

#include <cstring>
#include <map>
#include <mutex>
#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
static bool g_initedPermMap = false;
static std::mutex g_lockPermMap;

class CharArrayCompare {
public:
    CharArrayCompare() {};

    bool operator() (const char* str1, const char* str2) const
    {
        if (str1 == str2) {
            return false;
        } else {
            return (strcmp(str1, str2) < 0);
        }
    }
};
std::map<const char*, uint32_t, CharArrayCompare> g_permMap;

static void InitMap()
{
    std::lock_guard<std::mutex> lock(g_lockPermMap);
    if (g_initedPermMap) {
        return;
    }
    for (uint32_t i = 0; i < MAX_PERM_SIZE; i++) {
        g_permMap[g_permList[i].permissionName] = i;
    }
    g_initedPermMap = true;
}

bool TransferPermissionToOpcode(const std::string& permission, uint32_t& opCode)
{
    if (!g_initedPermMap) {
        InitMap();
    }
    auto it = g_permMap.find(permission.c_str());
    if (it == g_permMap.end()) {
        return false;
    }
    opCode = it->second;
    return true;
}

std::string TransferOpcodeToPermission(uint32_t opCode)
{
    if (opCode >= MAX_PERM_SIZE) {
        return "";
    }
    return std::string(g_permList[opCode].permissionName);
}

bool QueryRequredPermissions(const std::string& cliPermission, std::vector<std::string>& requiredPermission)
{
    requiredPermission.clear();
    auto iter = g_cliPermissionMap.find(cliPermission);
    if (iter == g_cliPermissionMap.end()) {
        return false;
    }
    requiredPermission = iter->second;
    return true;
}

bool IsUserGrantPermission(const std::string& permission)
{
    uint32_t opCode;
    if (!TransferPermissionToOpcode(permission, opCode)) {
        return false; // default is false
    }
    return g_permList[opCode].isEnable && g_permList[opCode].grantMode == USER_GRANT;
}

bool IsOperablePermission(const std::string& permission)
{
    uint32_t opCode;
    if (!TransferPermissionToOpcode(permission, opCode)) {
        return false; // default is false
    }
    return g_permList[opCode].isEnable &&
        (g_permList[opCode].grantMode == USER_GRANT || g_permList[opCode].grantMode == MANUAL_SETTINGS);
}

bool IsDefinedPermissionInner(const std::string& permission)
{
    if (!g_initedPermMap) {
        InitMap();
    }
    auto it = g_permMap.find(permission.c_str());
    if (it == g_permMap.end()) {
        return false;
    }
    return g_permList[it->second].isEnable;
}

bool GetPermissionBriefDef(const std::string& permission, PermissionBriefDef& permissionBriefDef)
{
    uint32_t opCode;
    if (!TransferPermissionToOpcode(permission, opCode)) {
        return false; // default is false
    }
    permissionBriefDef = g_permList[opCode];
    return true;
}

bool GetPermissionBriefDef(const std::string& permission, PermissionBriefDef& permissionBriefDef, uint32_t& opCode)
{
    if (!TransferPermissionToOpcode(permission, opCode)) {
        return false; // default is false
    }
    permissionBriefDef = g_permList[opCode];
    return true;
}

void GetPermissionBriefDef(uint32_t opCode, PermissionBriefDef& permissionBriefDef)
{
    if (!g_initedPermMap) {
        InitMap();
    }
    permissionBriefDef = g_permList[opCode];
}

void ConvertPermissionBriefToDef(const PermissionBriefDef& briefDef, PermissionDef& def)
{
    def.permissionName = std::string(briefDef.permissionName);
    def.grantMode = static_cast<int>(briefDef.grantMode);
    def.availableLevel = briefDef.availableLevel;
    def.provisionEnable = briefDef.provisionEnable;
    def.distributedSceneEnable = briefDef.distributedSceneEnable;
    def.availableType = briefDef.availableType;
    def.isKernelEffect = briefDef.isKernelEffect;
    def.hasValue = briefDef.hasValue;
}

bool IsPermissionValidForHap(const std::string& permissionName)
{
    uint32_t opCode;
    if (!TransferPermissionToOpcode(permissionName, opCode)) {
        return false;
    }

    return g_permList[opCode].isEnable && g_permList[opCode].availableType != ATokenAvailableTypeEnum::SERVICE;
}

size_t GetDefPermissionsSize()
{
    return MAX_PERM_SIZE;
}

const char* GetPermDefVersion()
{
    return PERMISSION_DEFINITION_VERSION;
}

bool SetPermissionBriefEnabled(const std::string& permissionName, bool isEnable)
{
    if (!g_initedPermMap) {
        InitMap();
    }
    auto it = g_permMap.find(permissionName.c_str());
    if (it == g_permMap.end()) {
        return false;
    }
    g_permList[it->second].isEnable = isEnable;
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
