/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_COMMON_LOG_H
#define ACCESSTOKEN_COMMON_LOG_H

#include <stdint.h>
#include "hilog/log.h"
#include "accesstoken_thread_msg.h"

#define ATM_DOMAIN 0xD005A01
#define ATM_TAG "ATM"

#define PRI_DOMAIN 0xD005A02
#define PRI_TAG "PRIVACY"

#define LOG_PUBLIC "{public}"

#define LOGF(domain, tag, fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_FATAL, domain, tag, \
    "[%{public}s:%{public}d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define LOGE(domain, tag, fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_ERROR, domain, tag, \
    "[%{public}s:%{public}d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define LOGW(domain, tag, fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_WARN, domain, tag, \
    "[%{public}s:%{public}d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define LOGI(domain, tag, fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_INFO, domain, tag, \
    "[%{public}s:%{public}d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define LOGD(domain, tag, fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, domain, tag, \
    "[%{public}s:%{public}d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__))

// LOGC is used for critical errors that should be logged and reported.
#define LOGC(domain, tag, fmt, ...)            \
do { \
    ((void)HILOG_IMPL(LOG_CORE, LOG_ERROR, domain, tag, \
    "[%{public}s:%{public}d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)); \
    AddEventMessage(domain, tag, \
        "%" LOG_PUBLIC "s[%" LOG_PUBLIC "u]: " fmt, __func__, __LINE__, ##__VA_ARGS__); \
} while (0)

#define IF_FALSE_PRINT_LOG(domain, tag, cond, fmt, ...) \
    do { \
        if (!(cond)) { \
            LOGE(domain, tag, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define IF_FALSE_RETURN_LOG(domain, tag, cond, fmt, ...) \
    do { \
        if (!(cond)) { \
            LOGE(domain, tag, fmt, ##__VA_ARGS__); \
            return; \
        } \
    } while (0)

#endif // ACCESSTOKEN_COMMON_LOG_H
