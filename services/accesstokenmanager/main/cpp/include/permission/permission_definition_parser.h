/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef PERMISSION_DEFINITION_PARSER_H
#define PERMISSION_DEFINITION_PARSER_H

#include <string>

#include "accesstoken_log.h"
#include "nlohmann/json.hpp"
#include "nocopyable.h"
#include "permission_def.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct PermissionDefParseRet {
    PermissionDef permDef;
    bool isSuccessful = false;
};
class PermissionDefinitionParser final {
public:
    static PermissionDefinitionParser& GetInstance();
    virtual ~PermissionDefinitionParser() = default;
    int32_t Init();

private:
    PermissionDefinitionParser() : ready_(false) {}
    DISALLOW_COPY_AND_MOVE(PermissionDefinitionParser);
    int ReadCfgFile(std::string& PermsRawData);
    int32_t GetPermissionDefList(const nlohmann::json& json, const std::string& permsRawData, const std::string& type,
        std::vector<PermissionDef>& permDefList);
    int32_t ParserPermsRawData(const std::string& permsRawData, std::vector<PermissionDef>& perms);
    void from_json(const nlohmann::json& j, PermissionDefParseRet& p);
    void ProcessPermsInfos(std::vector<PermissionDef>& Perms);

    bool ready_;
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif  // PERMISSION_DEFINITION_PARSER_H