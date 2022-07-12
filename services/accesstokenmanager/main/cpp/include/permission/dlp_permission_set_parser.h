/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_DLP_PERMISSION_SET_PARSER_H
#define ACCESSTOKEN_DLP_PERMISSION_SET_PARSER_H

#include <memory>
#include <string>

#include "permission_dlp_mode.h"
#include "nlohmann/json.hpp"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
const std::string CLONE_PERMISSION_CONFIG_FILE = "/system/etc/dlp_permission/clone_app_permission.json";
constexpr int32_t MAX_CLONE_PERMISSION_CONFIG_FILE_SIZE = 5 * 1024 * 1024;
constexpr size_t MAX_BUFFER_SIZE = 1024;
class DlpPermissionSetParser final {
public:
    static DlpPermissionSetParser& GetInstance();
    virtual ~DlpPermissionSetParser() = default;
    int32_t Init();

private:
    DlpPermissionSetParser() : ready_(false) {}
    DISALLOW_COPY_AND_MOVE(DlpPermissionSetParser);
    int ReadCfgFile(std::string& dlpPermsRawData);
    void FromJson(const nlohmann::json& jsonObject, std::vector<PermissionDlpMode>& dlpPerms);
    int32_t ParserDlpPermsRawData(const std::string& dlpPermsRawData,
        std::vector<PermissionDlpMode>& dlpPerms);
    void from_json(const nlohmann::json& j, PermissionDlpMode& p);
    void ProcessDlpPermsInfos(std::vector<PermissionDlpMode>& dlpPerms);

    bool ready_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_DLP_PERMISSION_SET_PARSER_H
