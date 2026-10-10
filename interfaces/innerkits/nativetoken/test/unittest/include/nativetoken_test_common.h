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

#ifndef NATIVE_TOKEN_TEST_COMMON_H
#define NATIVE_TOKEN_TEST_COMMON_H

#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include "securec.h"

#ifdef WITH_SELINUX
#include <policycoreutils.h>
#endif

#include "nativetoken.h"
#include "spm_setproc.h"

constexpr uint32_t MAX_SPM_PERM_NUM = 256;
constexpr uint32_t DEFAULT_EXTERM_SIZE = 1;

static bool IsKernelSupportSpm()
{
    static bool isSupportSpm = false;
    static bool hasChecked = false;
    if (hasChecked) {
        return isSupportSpm;
    }
    uint32_t version = 0;
    int32_t ret = SpmGetVersion(&version);
    isSupportSpm = (ret != ENOTSUP) ? true : false;
    hasChecked = true;
    std::cout << "IsKernelSupportSpm: " << isSupportSpm << std::endl;
    return isSupportSpm;
}

static void CopyFileContent(int32_t srcFd, int32_t dstFd)
{
    char buf[4096];
    ssize_t n;
    while ((n = read(srcFd, buf, sizeof(buf))) > 0) {
        ssize_t written = write(dstFd, buf, n);
        if (written < 0 || written != n) {
            break;
        }
    }
}

static void FixFileMetadata(const char* destPath)
{
    struct stat dirStat;
    if (stat(TOKEN_ID_CFG_DIR_PATH, &dirStat) == 0) {
        chown(destPath, dirStat.st_uid, dirStat.st_gid);
        chmod(destPath, S_IRUSR | S_IWUSR | S_IRGRP);
    }
#ifdef WITH_SELINUX
    Restorecon(destPath);
#endif
}

static inline void BackupTokenFile(const char* srcPath, const char* backupPath)
{
    int32_t srcFd = open(srcPath, O_RDONLY);
    if (srcFd < 0) { return; }
    int32_t dstFd = open(backupPath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (dstFd >= 0) {
        CopyFileContent(srcFd, dstFd);
        close(dstFd);
    }
    close(srcFd);
}

static inline void RestoreTokenFile(const char* backupPath, const char* destPath)
{
    int32_t srcFd = open(backupPath, O_RDONLY);
    if (srcFd < 0) { return; }
    int32_t dstFd = open(destPath, O_WRONLY | O_TRUNC);
    if (dstFd < 0) { dstFd = open(destPath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR); }
    if (dstFd >= 0) {
        CopyFileContent(srcFd, dstFd);
        close(dstFd);
    }
    close(srcFd);
    FixFileMetadata(destPath);
}

#endif // NATIVE_TOKEN_TEST_COMMON_H
