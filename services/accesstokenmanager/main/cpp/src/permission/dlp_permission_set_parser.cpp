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
#include "dlp_permission_set_parser.h"

#include <fcntl.h>
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "accesstoken_log.h"
#include "data_validator.h"
#include "dlp_permission_set_manager.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "DlpPermissionSetParser"};
}

// nlohmann json need the function named from_json to parse
void from_json(const nlohmann::json& j, PermissionDlpMode& p)
{
    if (j.find("name") == j.end()) {
        return;
    }
    p.permissionName = j.at("name").get<std::string>();
    if (!DataValidator::IsProcessNameValid(p.permissionName)) {
        return;
    }

    if (j.find("dlpGrantRange") == j.end()) {
        return;
    }
    std::string dlpModeStr = j.at("dlpGrantRange").get<std::string>();
    if (dlpModeStr == "all") {
        p.dlpMode = DLP_PERM_ALL;
        return;
    }
    if (dlpModeStr == "full_control") {
        p.dlpMode = DLP_PERM_FULL_CONTROL;
        return;
    }
    p.dlpMode = DLP_PERM_NONE;
    return;
}

int32_t DlpPermissionSetParser::ParserDlpPermsRawData(const std::string& dlpPermsRawData,
    std::vector<PermissionDlpMode>& dlpPerms)
{
    nlohmann::json jsonRes = nlohmann::json::parse(dlpPermsRawData, nullptr, false);
    if (jsonRes.is_discarded()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "jsonRes is invalid.");
        return RET_FAILED;
    }

    if (jsonRes.find("dlpPermissions") != jsonRes.end()) {
        nlohmann::json dlpPermTokenJson = jsonRes.at("dlpPermissions").get<nlohmann::json>();
        dlpPerms = dlpPermTokenJson.get<std::vector<PermissionDlpMode>>();
    }

    return RET_SUCCESS;
}

int32_t DlpPermissionSetParser::ReadCfgFile(std::string& dlpPermsRawData)
{
    int32_t fd = open(CLONE_PERMISSION_CONFIG_FILE.c_str(), O_RDONLY);
    if (fd < 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "open failed errno %{public}d.", errno);
        return RET_FAILED;
    }
    struct stat statBuffer;

    if (fstat(fd, &statBuffer) != 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "fstat failed errno %{public}d.", errno);
        close(fd);
        return RET_FAILED;
    }

    if (statBuffer.st_size == 0) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "config file size is 0.");
        close(fd);
        return RET_FAILED;
    }
    if (statBuffer.st_size > MAX_CLONE_PERMISSION_CONFIG_FILE_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "config file size is too large.");
        close(fd);
        return RET_FAILED;
    }
    dlpPermsRawData.reserve(statBuffer.st_size);

    char buff[MAX_BUFFER_SIZE] = { 0 };
    ssize_t readLen = 0;
    while ((readLen = read(fd, buff, MAX_BUFFER_SIZE)) > 0) {
        dlpPermsRawData.append(buff, readLen);
    }
    close(fd);

    if (readLen == 0) {
        return RET_SUCCESS;
    }
    return RET_FAILED;
}

int32_t DlpPermissionSetParser::Init()
{
    if (ready_) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "dlp permission has been set.");
        return RET_SUCCESS;
    }

    std::string dlpPermsRawData;
    int32_t ret = ReadCfgFile(dlpPermsRawData);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "readCfgFile failed.");
        return RET_FAILED;
    }
    std::vector<PermissionDlpMode> dlpPerms;
    ret = ParserDlpPermsRawData(dlpPermsRawData, dlpPerms);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "ParserDlpPermsRawData failed.");
        return RET_FAILED;
    }
    DlpPermissionSetManager::GetInstance().ProcessDlpPermInfos(dlpPerms);

    ready_ = true;
    ACCESSTOKEN_LOG_INFO(LABEL, "init ok.");
    return RET_SUCCESS;
}

DlpPermissionSetParser& DlpPermissionSetParser::GetInstance()
{
    static DlpPermissionSetParser instance;
    return instance;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
