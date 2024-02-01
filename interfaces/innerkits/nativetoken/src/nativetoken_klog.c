/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "nativetoken_klog.h"
#include <fcntl.h>
#include <unistd.h>
#include "securec.h"

#define MAX_LOG_SIZE 1024
#define MAX_LEVEL_SIZE 3

static const char *LOG_LEVEL_STR[] = {"ERROR", "WARNING", "INFO"};

#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

static int g_fd = -1;
static void NativeTokenOpenLogDevice(void)
{
    int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        g_fd = fd;
    }
    return;
}

int NativeTokenKmsg(int logLevel, const char *fmt, ...)
{
    if ((logLevel < 0) || (logLevel >= MAX_LEVEL_SIZE)) {
        return -1;
    }
    if (UNLIKELY(g_fd < 0)) {
        NativeTokenOpenLogDevice();
        if (g_fd < 0) {
            return -1;
        }
    }
    va_list vargs;
    va_start(vargs, fmt);
    char tmpFmt[MAX_LOG_SIZE];
    if (vsnprintf_s(tmpFmt, MAX_LOG_SIZE, MAX_LOG_SIZE - 1, fmt, vargs) == -1) {
        close(g_fd);
        g_fd = -1;
        va_end(vargs);
        return -1;
    }

    char logInfo[MAX_LOG_SIZE];
    int res = snprintf_s(logInfo, MAX_LOG_SIZE, MAX_LOG_SIZE - 1, "[pid=%d][%s][%s] %s",
        getpid(), "access_token", LOG_LEVEL_STR[logLevel], tmpFmt);
    if (res == -1) {
        close(g_fd);
        g_fd = -1;
        va_end(vargs);
        return -1;
    }
    va_end(vargs);

    if (write(g_fd, logInfo, strlen(logInfo)) < 0) {
        close(g_fd);
        g_fd = -1;
    }
    return 0;
}
