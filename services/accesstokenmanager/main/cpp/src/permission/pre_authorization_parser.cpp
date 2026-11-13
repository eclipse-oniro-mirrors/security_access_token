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

#include "pre_authorization_parser.h"

#include <fstream>
#include <set>
#include <sstream>

#include "accesstoken_common_log.h"
#include "libraryloader.h"
#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
#include "config_policy_utils.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
// install_list_permissions.json relative path + default root dir path.
constexpr const char* INSTALL_LIST_PERMISSIONS_CONFIG = "/etc/app/install_list_permissions.json";
constexpr const char* INSTALL_LIST_PERMISSIONS_FILE_PATH = "/system/etc/app/install_list_permissions.json";

bool ReadFileToString(const std::string& filePath, std::string& content)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    content = buffer.str();
    return !content.empty();
}
}

PreAuthorizationParser& PreAuthorizationParser::GetInstance()
{
    static PreAuthorizationParser instance;
    return instance;
}

void PreAuthorizationParser::Init()
{
    preAuthMap_.clear();
    std::vector<std::string> filePaths;
    CollectFilePaths(filePaths);
    for (const auto& path : filePaths) {
        ParseOneFile(path);
    }
}

void PreAuthorizationParser::Clear()
{
    preAuthMap_.clear();
}

void PreAuthorizationParser::CollectFilePaths(std::vector<std::string>& filePaths)
{
    std::set<std::string> seenPaths;
#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
    CfgDir* dirs = GetCfgDirList();
    if (dirs != nullptr) {
        // GetCfgDirList returns dirs ordered from low to high priority;
        // iterate in order with dedup so that the high-priority path wins when a later parse overwrites an earlier one.
        for (const auto& path : dirs->paths) {
            if (path == nullptr) {
                continue;
            }
            std::string filePath = std::string(path) + INSTALL_LIST_PERMISSIONS_CONFIG;
            if (seenPaths.insert(filePath).second) {
                filePaths.emplace_back(std::move(filePath));
            }
        }
        FreeCfgDirList(dirs);
    }
#endif
    // Default /system root dir fallback: append to the end (lowest priority) when not present.
    if (seenPaths.count(INSTALL_LIST_PERMISSIONS_FILE_PATH) == 0) {
        filePaths.emplace_back(INSTALL_LIST_PERMISSIONS_FILE_PATH);
    }
}

void PreAuthorizationParser::ParseOneFile(const std::string& filePath)
{
    std::string rawData;
    if (!ReadFileToString(filePath, rawData)) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Read install_list_permissions.json failed: %{public}s.", filePath.c_str());
        return;
    }
    LibraryLoader loader(CONFIG_PARSE_LIBPATH, CONFIG_PARSE_CREATE_SYMBOL, CONFIG_PARSE_DESTROY_SYMBOL);
    ConfigPolicyLoaderInterface* policy = loader.GetObject<ConfigPolicyLoaderInterface>();
    if (policy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Load json parse loader failed.");
        return;
    }
    std::vector<PreAuthBundleInfo> bundleInfos;
    if (!policy->ParseInstallListPermissions(rawData, bundleInfos)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Parse install_list_permissions.json failed: %{public}s.", filePath.c_str());
        return;
    }
    for (const auto& bundleInfo : bundleInfos) {
        // Same bundleName: a later parse overwrites an earlier one (the later, higher-priority path wins).
        preAuthMap_[bundleInfo.bundleName] = bundleInfo;
    }
}

std::map<std::string, bool> PreAuthorizationParser::GetPreAuthPermissions(const std::string& bundleName) const
{
    auto iter = preAuthMap_.find(bundleName);
    if (iter == preAuthMap_.end()) {
        return {};
    }
    return iter->second.permissions;
}

const PreAuthBundleInfo* PreAuthorizationParser::GetPreAuthBundleInfo(const std::string& bundleName) const
{
    auto iter = preAuthMap_.find(bundleName);
    if (iter == preAuthMap_.end()) {
        return nullptr;
    }
    return &iter->second;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS