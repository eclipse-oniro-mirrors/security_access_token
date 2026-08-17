/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/statfs.h>
#include "accesstoken_common_log.h"
#include "hisysevent.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* ACCESSTOKEN_NAME = "access_token";
constexpr const char* NATIVE_CFG_DIR_PATH = "/data/service/el0/access_token";
constexpr const char* NATIVE_CFG_FILE_NAME = "nativetoken.json";
constexpr const char* NATIVE_CFG_FILE_PATH = "/data/service/el0/access_token/nativetoken.json";
constexpr const char* DATABASE_DIR_PATH = "/data/service/el1/public/access_token/";
constexpr const char* DATA_FOLDER = "/data";
constexpr const char* CURRENT_FOLDER = ".";
constexpr const char* PARENT_FOLDER = "..";
constexpr const char* LOG_PATH_ELLIPSIS = "...";
constexpr const char PATH_DELIMITER = '/';
static constexpr uint64_t ZERO_SIZE = 0;
static constexpr int32_t MAX_DEPTH = 5;
static constexpr int32_t INITIAL_DEPTH = 1;
static constexpr size_t MAX_LOG_PATH_LEN = 256;

std::string GetLogPath(const std::string& path)
{
    if (path.size() <= MAX_LOG_PATH_LEN) {
        return path;
    }
    size_t suffixLen = MAX_LOG_PATH_LEN - strlen(LOG_PATH_ELLIPSIS);
    return std::string(LOG_PATH_ELLIPSIS) + path.substr(path.size() - suffixLen);
}

void GetCurrentDirFileNames(const std::string& path, std::vector<std::string>& fileNames)
{
    DIR* dirPtr = opendir(path.c_str());
    if (dirPtr == nullptr) {
        return;
    }
    struct dirent* ent = nullptr;
    while ((ent = readdir(dirPtr)) != nullptr) {
        if (strcmp(ent->d_name, CURRENT_FOLDER) == 0 || strcmp(ent->d_name, PARENT_FOLDER) == 0) {
            continue;
        }
        fileNames.emplace_back(ent->d_name);
    }
    closedir(dirPtr);
}

void AppendFileDfxInfoLog(const std::string& path, const std::string& fileName, std::ostringstream& oss)
{
    std::string filePath = GetFilePathByDir(path, fileName);
    struct stat fileInfo = {};
    if (lstat(filePath.c_str(), &fileInfo) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get file stat, path=%{public}s, err=%{public}d",
            filePath.c_str(), errno);
        return;
    }
    oss << "; filename=" << GetLogPath(fileName) <<
        ", size=" << fileInfo.st_size <<
        ", atime=" << fileInfo.st_atime <<
        ", mtime=" << fileInfo.st_mtime <<
        ", inode=" << fileInfo.st_ino;
}

void ReportDataUsageFileInfo(const std::string& path, const std::vector<std::string>& fileNames)
{
    ClearThreadErrorMsg();
    std::ostringstream oss;
    oss << "path=" << GetLogPath(path) << ", entryCount=" << fileNames.size();
    for (const std::string& fileName : fileNames) {
        AppendFileDfxInfoLog(path, fileName, oss);
    }
    std::string logMsg = oss.str();
    LOGC(ATM_DOMAIN, ATM_TAG, "Data usage file info, %{public}s", logMsg.c_str());
    ClearThreadErrorMsg();
}

}

uint64_t GetUserDataRemainSize()
{
    struct statfs stat;
    if (statfs(DATA_FOLDER, &stat) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get data remain size, err=%{public}d", errno);
        return ZERO_SIZE;
    }
    return static_cast<uint64_t>(stat.f_bfree) * stat.f_bsize;
}

uint64_t GetFileSize(const char* filePath)
{
    struct stat fileInfo;
    if (lstat(filePath, &fileInfo) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get file stat, path=%{public}s, err=%{public}d", filePath, errno);
        return ZERO_SIZE;
    }
    return fileInfo.st_size;
}

bool IsDirectory(const char* filePath)
{
    struct stat fileInfo;
    if (lstat(filePath, &fileInfo) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to get file stat, path=%{public}s, err=%{public}d", filePath, errno);
        return false;
    }
    return S_ISDIR(fileInfo.st_mode);
}

std::string GetFilePathByDir(const std::string& dir, const std::string& fileName)
{
    if (dir.empty()) {
        return fileName;
    }
    std::string filePath = dir;
    if (filePath.back() != PATH_DELIMITER) {
        filePath.push_back(PATH_DELIMITER);
    }
    filePath.append(fileName);
    return filePath;
}

void GetAllDirFile(const std::string& path, std::vector<std::string>& files)
{
    DIR* dirPtr = opendir(path.c_str());
    if (dirPtr == nullptr) {
        return;
    }
    struct dirent* ent = nullptr;
    while ((ent = readdir(dirPtr)) != nullptr) {
        if (strcmp(ent->d_name, CURRENT_FOLDER) == 0 || strcmp(ent->d_name, PARENT_FOLDER) == 0) {
            continue;
        }
        files.emplace_back(GetFilePathByDir(path, ent->d_name));
    }
    closedir(dirPtr);
}

void GetDirFileSize(
    const std::string& path, std::vector<std::string>& filePath, std::vector<uint64_t>& fileSize, int32_t depth)
{
    if (depth > MAX_DEPTH) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Maximum recursion depth exceeded.");
        return;
    }
    std::vector<std::string> files;
    GetAllDirFile(path, files);
    for (const std::string& file : files) {
        fileSize.emplace_back(GetFileSize(file.c_str()));
        filePath.emplace_back(file);
        if (IsDirectory(file.c_str())) {
            GetDirFileSize(file, filePath, fileSize, depth + 1);
        }
    }
}

void ReportAccessTokenUserData()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Report accesstoken_service userdata start.");
    std::vector<std::string> filePath = { NATIVE_CFG_FILE_PATH };
    std::vector<uint64_t> fileSize = { GetFileSize(NATIVE_CFG_FILE_PATH) };
    GetDirFileSize(DATABASE_DIR_PATH, filePath, fileSize, INITIAL_DEPTH);
    std::vector<std::string> dfxFileNames = { CURRENT_FOLDER };
    GetCurrentDirFileNames(DATABASE_DIR_PATH, dfxFileNames);
    ReportDataUsageFileInfo(NATIVE_CFG_DIR_PATH, { CURRENT_FOLDER, NATIVE_CFG_FILE_NAME });
    ReportDataUsageFileInfo(DATABASE_DIR_PATH, dfxFileNames);

    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::FILEMANAGEMENT, "USER_DATA_SIZE",
        HiviewDFX::HiSysEvent::EventType::STATISTIC, "COMPONENT_NAME", ACCESSTOKEN_NAME, "PARTITION_NAME", DATA_FOLDER,
        "REMAIN_PARTITION_SIZE", GetUserDataRemainSize(),
        "FILE_OR_FOLDER_PATH", filePath, "FILE_OR_FOLDER_SIZE", fileSize);
    LOGI(ATM_DOMAIN, ATM_TAG, "Report accesstoken_service userdata end.");
}

void ReportDbException(int32_t sceneCode, int32_t errCode, const std::string& dbName)
{
    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "DATABASE_EXCEPTION",
        HiviewDFX::HiSysEvent::EventType::FAULT, "SCENE_CODE", sceneCode, "ERROR_CODE", errCode,
        "TABLE_NAME", dbName);
}

#ifdef REMOTE_PRIVACY_ENABLE
void ReportPrivacyUserData(const std::string& path)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Report privacy_service userdata start, path=%{public}s.", path.c_str());

    std::vector<std::string> filePath;
    std::vector<uint64_t> fileSize;
    GetDirFileSize(path, filePath, fileSize, INITIAL_DEPTH);
    std::vector<std::string> dfxFileNames = { CURRENT_FOLDER };
    GetCurrentDirFileNames(path, dfxFileNames);
    ReportDataUsageFileInfo(path, dfxFileNames);

    (void)HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::FILEMANAGEMENT, "USER_DATA_SIZE",
        HiviewDFX::HiSysEvent::EventType::STATISTIC, "COMPONENT_NAME", ACCESSTOKEN_NAME, "PARTITION_NAME", DATA_FOLDER,
        "REMAIN_PARTITION_SIZE", GetUserDataRemainSize(),
        "FILE_OR_FOLDER_PATH", filePath, "FILE_OR_FOLDER_SIZE", fileSize);
    LOGI(ATM_DOMAIN, ATM_TAG, "Report privacy_service userdata end.");
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
