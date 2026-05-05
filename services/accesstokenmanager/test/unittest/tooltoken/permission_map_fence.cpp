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

#include "permission_map_fence.h"

#include "permission_map.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
bool g_mockMappingConfigured = false;
std::map<std::string, std::vector<std::string>> g_mockCliRuntimePermissions;

const std::map<std::string, std::vector<std::string>> DEFAULT_CLI_PERMISSION_MAP = {
    {"ohos.permission.POWER_MANAGER", {"ohos.permission.POWER_MANAGER"}},
    {"ohos.permission.APPROXIMATELY_LOCATION",
        {"ohos.permission.LOCATION", "ohos.permission.APPROXIMATELY_LOCATION"}},
    {"ohos.permission.cli.resolved", {"ohos.permission.CAMERA"}},
};

bool QueryFromMap(const std::map<std::string, std::vector<std::string>>& permissionMap,
    const std::string& cliPermission, std::vector<std::string>& requiredPermission)
{
    auto iter = permissionMap.find(cliPermission);
    if (iter == permissionMap.end()) {
        return false;
    }
    requiredPermission = iter->second;
    return true;
}
} // namespace

void SetMockCliRuntimePermissionsForTest(
    const std::map<std::string, std::vector<std::string>>& permissionMap)
{
    g_mockCliRuntimePermissions = permissionMap;
    g_mockMappingConfigured = true;
}

void ClearMockCliRuntimePermissionsForTest()
{
    g_mockCliRuntimePermissions.clear();
    g_mockMappingConfigured = false;
}

bool QueryRequredPermissions(const std::string& cliPermission, std::vector<std::string>& requiredPermission)
{
    requiredPermission.clear();
    if (g_mockMappingConfigured &&
        QueryFromMap(g_mockCliRuntimePermissions, cliPermission, requiredPermission)) {
        return true;
    }
    return QueryFromMap(DEFAULT_CLI_PERMISSION_MAP, cliPermission, requiredPermission);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
