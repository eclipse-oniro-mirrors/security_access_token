/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "data_usage_dfx.h"

#include <sys/statfs.h>
#include "accesstoken_common_log.h"
#include "directory_ex.h"
#include "hisysevent.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* ACCESSTOKEN_NAME = "access_token";
constexpr const char* NATIVE_CFG_FILE_PATH = "/data/service/el0/access_token/nativetoken.json";
constexpr const char* DATABASE_DIR_PATH = "/data/service/el1/public/access_token/";
constexpr const char* DATA_FOLDER = "/data";
constexpr const char* ACCESSTOKEN_DATABASE_NAME = "access_token.db";
constexpr const char* ACCESSTOKEN_DATABASE_NAME_BACK = "access_token_slave.db";
constexpr const char* PRIVACY_DATABASE_NAME = "permission_used_record.db";
static constexpr uint64_t INVALID_SIZE = 0;
}

uint64_t GetUserDataRemainSize()
{
    struct statfs stat;
    if (statfs(DATA_FOLDER, &stat) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get data remain size.");
        return INVALID_SIZE;
    }
    return static_cast<uint64_t>(stat.f_bfree) * stat.f_bsize;
}

uint64_t GetFileSize(const char* filePath)
{
    struct stat fileInfo;
    if (stat(filePath, &fileInfo) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get file stat, path=%{public}s.", filePath);
        return INVALID_SIZE;
    }
    return fileInfo.st_size;
}

void GetDatabaseFileSize(const std::string& name, std::vector<std::string>& filePath, std::vector<uint64_t>& fileSize)
{
    std::vector<std::string> files;
    GetDirFiles(DATABASE_DIR_PATH, files);
    for (const std::string& file : files) {
        if (file.find(name) != std::string::npos) {
            fileSize.emplace_back(GetFileSize(file.c_str()));
            filePath.emplace_back(file);
        }
    }
}

void ReportAccessTokenUserData()
{
    std::vector<std::string> filePath = { NATIVE_CFG_FILE_PATH };
    std::vector<uint64_t> fileSize = { GetFileSize(NATIVE_CFG_FILE_PATH) };
    GetDatabaseFileSize(ACCESSTOKEN_DATABASE_NAME, filePath, fileSize);
    GetDatabaseFileSize(ACCESSTOKEN_DATABASE_NAME_BACK, filePath, fileSize);
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::FILEMANAGEMENT, "USER_DATA_SIZE",
        HiviewDFX::HiSysEvent::EventType::STATISTIC, "COMPONENT_NAME", ACCESSTOKEN_NAME, "PARTITION_NAME", DATA_FOLDER,
        "REMAIN_PARTITION_SIZE", GetUserDataRemainSize(),
        "FILE_OR_FOLDER_PATH", filePath, "FILE_OR_FOLDER_SIZE", fileSize);
}

void ReportPrivacyUserData()
{
    std::vector<std::string> filePath;
    std::vector<uint64_t> fileSize;
    GetDatabaseFileSize(PRIVACY_DATABASE_NAME, filePath, fileSize);
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::FILEMANAGEMENT, "USER_DATA_SIZE",
        HiviewDFX::HiSysEvent::EventType::STATISTIC, "COMPONENT_NAME", ACCESSTOKEN_NAME, "PARTITION_NAME", DATA_FOLDER,
        "REMAIN_PARTITION_SIZE", GetUserDataRemainSize(),
        "FILE_OR_FOLDER_PATH", filePath, "FILE_OR_FOLDER_SIZE", fileSize);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS