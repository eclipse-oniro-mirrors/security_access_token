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

#include "accesstoken_file_util.h"

#include <cerrno>
#include <fcntl.h>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

#include "securec.h"
#include "accesstoken_common_log.h"

#if __has_include(<sys/fdsan.h>)
#include <sys/fdsan.h>
#endif

#ifdef WITH_SELINUX
#include <policycoreutils.h>
#endif

namespace {
constexpr uint64_t FD_TAG = 0xD005A01;

int32_t GetParentDir(const char* filePath, char* parentDir, size_t parentDirLen)
{
    const char* lastSlash = strrchr(filePath, '/');
    if (lastSlash == nullptr || lastSlash == filePath) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetParentDir: no slash in path or root path.");
        return -1;
    }
    size_t dirLen = static_cast<size_t>(lastSlash - filePath);
    if (dirLen >= parentDirLen) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetParentDir: parent dir path too long.");
        return -1;
    }
    if (memcpy_s(parentDir, parentDirLen, filePath, dirLen) != EOK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetParentDir: memcpy_s failed.");
        return -1;
    }
    parentDir[dirLen] = '\0';
    return 0;
}

void FsyncDir(const char* dirPath)
{
    int32_t fd = open(dirPath, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "open dir failed, errno=%d.", errno);
        return;
    }
    fdsan_exchange_owner_tag(fd, 0, FD_TAG);
    if (fsync(fd) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "fsync dir failed, errno=%d.", errno);
    }
    (void)fdsan_close_with_tag(fd, FD_TAG);
}

int32_t WriteAndSync(const char* path, const char* data, size_t dataLen, int32_t mode)
{
    int32_t fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, static_cast<mode_t>(mode));
    if (fd < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "open failed, errno=%d.", errno);
        return -1;
    }
    fdsan_exchange_owner_tag(fd, 0, FD_TAG);
    bool failed = false;
    ssize_t written = write(fd, data, dataLen);
    if (written < 0 || static_cast<size_t>(written) != dataLen) {
        LOGE(ATM_DOMAIN, ATM_TAG, "write failed, written=%zd, errno=%d.", written, errno);
        failed = true;
    }
    if (!failed && fsync(fd) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "fsync failed, errno=%d.", errno);
        failed = true;
    }
    (void)fdsan_close_with_tag(fd, FD_TAG);
    if (failed) {
        if (unlink(path) != 0 && errno != ENOENT) {
            LOGE(ATM_DOMAIN, ATM_TAG, "WriteAndSync: unlink failed, path=%s, errno=%d.", path, errno);
        }
        return -1;
    }
    return 0;
}

int32_t WriteAndRename(const char* filePath, const char* data, size_t dataLen, int32_t mode)
{
    char newPath[PATH_MAX];
    int32_t newRet = snprintf_s(newPath, sizeof(newPath), sizeof(newPath) - 1, "%s.new", filePath);
    if (newRet < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "newPath too long.");
        return -1;
    }
    if (unlink(newPath) != 0 && errno != ENOENT) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteAndRename: unlink stale .new failed, path=%s, errno=%d.", newPath, errno);
    }

    if (WriteAndSync(newPath, data, dataLen, mode) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteAndRename: WriteAndSync failed, path=%s.", newPath);
        return -1;
    }

    char parentDir[PATH_MAX];
    struct stat dirStat;
    bool hasParentStat = (GetParentDir(filePath, parentDir, sizeof(parentDir)) == 0 &&
        stat(parentDir, &dirStat) == 0);
    if (!hasParentStat) {
        LOGE(ATM_DOMAIN, ATM_TAG, "WriteAndRename: failed to get parent dir stat, path=%s.", filePath);
    }
#ifdef WITH_SELINUX
    Restorecon(newPath);
#endif
    if (hasParentStat && chown(newPath, dirStat.st_uid, dirStat.st_gid) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "chown newPath failed, errno=%d.", errno);
    }

    if (rename(newPath, filePath) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "rename failed, errno=%d.", errno);
        return -1;
    }

#ifdef WITH_SELINUX
    Restorecon(filePath);
#endif
    if (hasParentStat) {
        FsyncDir(parentDir);
    }
    return 0;
}
} // namespace

int32_t GetBakFilePath(const char* filePath, char* bakPath, size_t bakPathLen)
{
    if (filePath == nullptr || bakPath == nullptr || bakPathLen == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetBakFilePath: invalid argument.");
        return -1;
    }
    const char* lastSlash = strrchr(filePath, '/');
    if (lastSlash == nullptr || lastSlash == filePath) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetBakFilePath: no slash in path or root path.");
        return -1;
    }
    size_t parentLen = static_cast<size_t>(lastSlash - filePath);
    const char* fileName = lastSlash + 1;
    int parentLenInt = static_cast<int>(parentLen);
    int32_t ret = snprintf_s(bakPath, bakPathLen, bakPathLen - 1, "%.*s/access_token_backup/%s",
        parentLenInt, filePath, fileName);
    if (ret < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GetBakFilePath: snprintf_s failed or truncated.");
        return -1;
    }
    return 0;
}

int32_t AtomicWriteFile(const char* filePath, const char* data, size_t dataLen, int32_t mode)
{
    if (filePath == nullptr || data == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AtomicWriteFile: invalid argument.");
        return -1;
    }

    if (WriteAndRename(filePath, data, dataLen, mode) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AtomicWriteFile: WriteAndRename main failed, path=%s.", filePath);
        return -1;
    }

    char bakPath[PATH_MAX];
    if (GetBakFilePath(filePath, bakPath, sizeof(bakPath)) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AtomicWriteFile: GetBakFilePath failed, path=%s.", filePath);
        return 0;
    }
    char parentDir[PATH_MAX];
    struct stat dirStat;
    bool hasParentStat = (GetParentDir(filePath, parentDir, sizeof(parentDir)) == 0 &&
        stat(parentDir, &dirStat) == 0);
    char bakDir[PATH_MAX];
    if (GetParentDir(bakPath, bakDir, sizeof(bakDir)) == 0) {
        if (mkdir(bakDir, S_IRWXU | S_IRGRP | S_IXGRP) != 0 && errno != EEXIST) {
            LOGE(ATM_DOMAIN, ATM_TAG, "AtomicWriteFile: mkdir backup dir failed, dir=%s, errno=%d.", bakDir, errno);
        }
#ifdef WITH_SELINUX
        Restorecon(bakDir);
#endif
        if (hasParentStat && chown(bakDir, dirStat.st_uid, dirStat.st_gid) != 0) {
            LOGE(ATM_DOMAIN, ATM_TAG, "AtomicWriteFile: chown backup dir failed, errno=%d.", errno);
        }
    }
    if (WriteAndRename(bakPath, data, dataLen, mode) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AtomicWriteFile: WriteAndRename backup failed, path=%s.", bakPath);
    }
    return 0;
}
