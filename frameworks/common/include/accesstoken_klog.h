/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#ifndef ACCESSTOKEN_KLOG_H
#define ACCESSTOKEN_KLOG_H

#include <inttypes.h>
#include "accesstoken_thread_msg.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum NativeTokenKLogLevel {
    NATIVETOKEN_KERROR = 0,
    NATIVETOKEN_KWARN,
    NATIVETOKEN_KINFO,
} NativeTokenKLogLevel;

extern int NativeTokenKmsg(int logLevel, const char *fmt, ...);

#define LOG_PUBLIC ""

#define LOGE(fmt, ...)            \
    ((void)NativeTokenKmsg(NATIVETOKEN_KERROR, "[%s:%d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define LOGW(fmt, ...)            \
    ((void)NativeTokenKmsg(NATIVETOKEN_KWARN, "[%s:%d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define LOGI(fmt, ...)            \
    ((void)NativeTokenKmsg(NATIVETOKEN_KINFO, "[%s:%d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__))

// LOGC is used for critical errors that should be logged and reported.
#define LOGC(fmt, ...)            \
do { \
    (void)NativeTokenKmsg(NATIVETOKEN_KERROR, "[%s:%d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    AddEventMessage(0, 0, \
        "%" LOG_PUBLIC "s[%" LOG_PUBLIC "u]: " fmt, __func__, __LINE__, ##__VA_ARGS__); \
} while (0)

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // ACCESSTOKEN_KLOG_H
