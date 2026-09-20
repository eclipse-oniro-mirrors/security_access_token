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
#include "accesstoken_klog.h"

#if __has_include(<sys/fdsan.h>)
#include <sys/fdsan.h>
#endif

#ifdef WITH_SELINUX
#include <policycoreutils.h>
#endif

namespace {
constexpr int32_t FILE_UTIL_FAILED = -1;
constexpr uint64_t FD_TAG = 0xD005A01;

int32_t GetParentDir(const char* filePath, char* parentDir, size_t parentDirLen)
{
    const char* lastSlash = strrchr(filePath, '/');
    if (lastSlash == nullptr || lastSlash == filePath) {
        LOGE("GetParentDir: no slash in path or root path.");
        return FILE_UTIL_FAILED;
    }
    size_t dirLen = static_cast<size_t>(lastSlash - filePath);
    if (dirLen >= parentDirLen) {
        LOGE("GetParentDir: parent dir path too long.");
        return FILE_UTIL_FAILED;
    }
    if (memcpy_s(parentDir, parentDirLen, filePath, dirLen) != EOK) {
        LOGE("GetParentDir: memcpy_s failed.");
        return FILE_UTIL_FAILED;
    }
    parentDir[dirLen] = '\0';
    return 0;
}

void FsyncDir(const char* dirPath)
{
    int32_t fd = open(dirPath, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        LOGE("Open dir failed, errno=%d.", errno);
        return;
    }
    fdsan_exchange_owner_tag(fd, 0, FD_TAG);
    if (fsync(fd) != 0) {
        LOGE("Fsync dir failed, errno=%d.", errno);
    }
    (void)fdsan_close_with_tag(fd, FD_TAG);
}

int32_t WriteAndSync(const char* path, const char* data, size_t dataLen, int32_t mode)
{
    int32_t fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, static_cast<mode_t>(mode));
    if (fd < 0) {
        LOGE("Open failed, errno=%d.", errno);
        return FILE_UTIL_FAILED;
    }
    fdsan_exchange_owner_tag(fd, 0, FD_TAG);
    bool failed = false;
    ssize_t written = write(fd, data, dataLen);
    if (written < 0 || static_cast<size_t>(written) != dataLen) {
        LOGE("Write failed, written=%zd, errno=%d.", written, errno);
        failed = true;
    }
    if (!failed && fsync(fd) != 0) {
        LOGE("Fsync failed, errno=%d.", errno);
        failed = true;
    }
    (void)fdsan_close_with_tag(fd, FD_TAG);
    if (failed) {
        if (unlink(path) != 0 && errno != ENOENT) {
            LOGE("WriteAndSync: unlink failed, path=%s, errno=%d.", path, errno);
        }
        return FILE_UTIL_FAILED;
    }
    return 0;
}

int32_t WriteAndRename(const char* filePath, const char* data, size_t dataLen, int32_t mode)
{
    char newPath[PATH_MAX];
    int32_t newRet = snprintf_s(newPath, sizeof(newPath), sizeof(newPath) - 1, "%s.new", filePath);
    if (newRet < 0) {
        LOGE("NewPath too long.");
        return FILE_UTIL_FAILED;
    }
    if (unlink(newPath) != 0 && errno != ENOENT) {
        LOGE("WriteAndRename: unlink stale .new failed, path=%s, errno=%d.", newPath, errno);
    }

    if (WriteAndSync(newPath, data, dataLen, mode) != 0) {
        LOGE("WriteAndRename: WriteAndSync failed, path=%s.", newPath);
        return FILE_UTIL_FAILED;
    }

    char parentDir[PATH_MAX];
    struct stat dirStat;
    bool hasParentStat = (GetParentDir(filePath, parentDir, sizeof(parentDir)) == 0 &&
        stat(parentDir, &dirStat) == 0);
    if (!hasParentStat) {
        LOGE("WriteAndRename: failed to get parent dir stat, path=%s.", filePath);
    }
#ifdef WITH_SELINUX
    Restorecon(newPath);
#endif
    if (hasParentStat && chown(newPath, dirStat.st_uid, dirStat.st_gid) != 0) {
        LOGE("Chown newPath failed, errno=%d.", errno);
    }

    if (rename(newPath, filePath) != 0) {
        LOGE("Rename failed, errno=%d.", errno);
        return FILE_UTIL_FAILED;
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
        LOGE("GetBakFilePath: invalid argument.");
        return FILE_UTIL_FAILED;
    }
    const char* lastSlash = strrchr(filePath, '/');
    if (lastSlash == nullptr || lastSlash == filePath) {
        LOGE("GetBakFilePath: no slash in path or root path.");
        return FILE_UTIL_FAILED;
    }
    size_t parentLen = static_cast<size_t>(lastSlash - filePath);
    const char* fileName = lastSlash + 1;
    int parentLenInt = static_cast<int>(parentLen);
    int32_t ret = snprintf_s(bakPath, bakPathLen, bakPathLen - 1, "%.*s/access_token_backup/%s",
        parentLenInt, filePath, fileName);
    if (ret < 0) {
        LOGE("GetBakFilePath: snprintf_s failed or truncated.");
        return FILE_UTIL_FAILED;
    }
    return 0;
}

int32_t AtomicWriteFile(const char* filePath, const char* data, size_t dataLen, int32_t mode)
{
    if (filePath == nullptr || data == nullptr) {
        LOGE("AtomicWriteFile: invalid argument.");
        return FILE_UTIL_FAILED;
    }

    if (WriteAndRename(filePath, data, dataLen, mode) != 0) {
        LOGE("AtomicWriteFile: WriteAndRename main failed, path=%s.", filePath);
        return FILE_UTIL_FAILED;
    }

    char bakPath[PATH_MAX];
    if (GetBakFilePath(filePath, bakPath, sizeof(bakPath)) != 0) {
        LOGE("AtomicWriteFile: GetBakFilePath failed, path=%s.", filePath);
        return 0;
    }
    char parentDir[PATH_MAX];
    struct stat dirStat;
    bool hasParentStat = (GetParentDir(filePath, parentDir, sizeof(parentDir)) == 0 &&
        stat(parentDir, &dirStat) == 0);
    char bakDir[PATH_MAX];
    if (GetParentDir(bakPath, bakDir, sizeof(bakDir)) == 0) {
        if (mkdir(bakDir, S_IRWXU | S_IRGRP | S_IXGRP) != 0 && errno != EEXIST) {
            LOGE("AtomicWriteFile: mkdir backup dir failed, dir=%s, errno=%d.", bakDir, errno);
        }
#ifdef WITH_SELINUX
        Restorecon(bakDir);
#endif
        if (hasParentStat && chown(bakDir, dirStat.st_uid, dirStat.st_gid) != 0) {
            LOGE("AtomicWriteFile: chown backup dir failed, errno=%d.", errno);
        }
    }
    if (WriteAndRename(bakPath, data, dataLen, mode) != 0) {
        LOGE("AtomicWriteFile: WriteAndRename backup failed, path=%s.", bakPath);
    }
    return 0;
}
