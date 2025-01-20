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

#include "json_parser.h"

#include <fcntl.h>
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int MAX_NATIVE_CONFIG_FILE_SIZE = 5 * 1024 * 1024; // 5M
constexpr size_t BUFFER_SIZE = 1024;
}

bool JsonParser::GetStringFromJson(const nlohmann::json& j, const std::string& tag, std::string& out)
{
    if (j.find(tag) != j.end() && j.at(tag).is_string()) {
        out = j.at(tag).get<std::string>();
        return true;
    }
    return false;
}

bool JsonParser::GetIntFromJson(const nlohmann::json& j, const std::string& tag, int& out)
{
    if (j.find(tag) != j.end() && j.at(tag).is_number()) {
        out = j.at(tag).get<int>();
        return true;
    }
    return false;
}

bool JsonParser::GetUnsignedIntFromJson(const nlohmann::json& j, const std::string& tag, unsigned int& out)
{
    if (j.find(tag) != j.end() && j.at(tag).is_number()) {
        out = j.at(tag).get<unsigned int>();
        return true;
    }
    return false;
}

bool JsonParser::GetBoolFromJson(const nlohmann::json& j, const std::string& tag, bool& out)
{
    if (j.find(tag) != j.end() && j.at(tag).is_boolean()) {
        out = j.at(tag).get<bool>();
        return true;
    }
    return false;
}

int32_t JsonParser::ReadCfgFile(const std::string& file, std::string& rawData)
{
    char filePath[PATH_MAX + 1] = {0};
    if (realpath(file.c_str(), filePath) == NULL) {
        return ERR_FILE_OPERATE_FAILED;
    }
    int32_t fd = open(filePath, O_RDONLY);
    if (fd < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Open failed errno %{public}d.", errno);
        return ERR_FILE_OPERATE_FAILED;
    }
    struct stat statBuffer;

    if (fstat(fd, &statBuffer) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fstat failed.");
        close(fd);
        return ERR_FILE_OPERATE_FAILED;
    }

    if (statBuffer.st_size == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Config file size is invalid.");
        close(fd);
        return ERR_PARAM_INVALID;
    }
    if (statBuffer.st_size > MAX_NATIVE_CONFIG_FILE_SIZE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Config file size is too large.");
        close(fd);
        return ERR_OVERSIZE;
    }
    rawData.reserve(statBuffer.st_size);

    char buff[BUFFER_SIZE] = { 0 };
    ssize_t readLen = 0;
    while ((readLen = read(fd, buff, BUFFER_SIZE)) > 0) {
        rawData.append(buff, readLen);
    }
    close(fd);
    if (readLen == 0) {
        return RET_SUCCESS;
    }
    return ERR_FILE_OPERATE_FAILED;
}

bool JsonParser::IsDirExsit(const std::string& file)
{
    if (file.empty()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "File path is empty");
        return false;
    }

    struct stat buf;
    if (stat(file.c_str(), &buf) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get file attributes failed, errno %{public}d.", errno);
        return false;
    }

    if (!S_ISDIR(buf.st_mode)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "File mode is not directory.");
        return false;
    }

    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS