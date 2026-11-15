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

#ifndef PRE_AUTHORIZATION_PARSER_H
#define PRE_AUTHORIZATION_PARSER_H

#include <map>
#include <string>
#include <vector>

#include "json_parse_loader.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

/**
 * Pre-authorization list parser: parses install_list_permissions.json locally,
 * supports multiple paths (config_policy root dirs + the default /system root), and builds
 * the bundleName -> pre-authorized bundle info mapping (including app signature and permission list).
 */
class PreAuthorizationParser final {
public:
    static PreAuthorizationParser& GetInstance();

    void Init();
    void Clear();
    std::map<std::string, bool> GetPreAuthPermissions(const std::string& bundleName) const;
    const PreAuthBundleInfo* GetPreAuthBundleInfo(const std::string& bundleName) const;

private:
    PreAuthorizationParser() = default;
    ~PreAuthorizationParser() = default;
    PreAuthorizationParser(const PreAuthorizationParser&) = delete;
    PreAuthorizationParser& operator=(const PreAuthorizationParser&) = delete;

    void CollectFilePaths(std::vector<std::string>& filePaths);
    void ParseOneFile(const std::string& filePath);

    std::map<std::string, PreAuthBundleInfo> preAuthMap_;
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // PRE_AUTHORIZATION_PARSER_H
