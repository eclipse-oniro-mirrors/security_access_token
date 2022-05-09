/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_LOG_H
#define ACCESSTOKEN_LOG_H

#ifdef HILOG_ENABLE

#include "hilog/log.h"

#define AT_LOG_DEBUG(fmt, ...) HILOG_DEBUG(LOG_CORE, fmt, ##__VA_ARGS__)
#define AT_LOG_INFO(fmt, ...) HILOG_INFO(LOG_CORE, fmt, ##__VA_ARGS__)
#define AT_LOG_WARN(fmt, ...) HILOG_WARN(LOG_CORE, fmt, ##__VA_ARGS__)
#define AT_LOG_ERROR(fmt, ...) HILOG_ERROR(LOG_CORE, fmt, ##__VA_ARGS__)
#define AT_LOG_FATAL(fmt, ...) HILOG_FATAL(LOG_CORE, fmt, ##__VA_ARGS__)

/* define LOG_TAG as "security_*" at your submodule, * means your submodule name such as "security_dac" */
#undef LOG_TAG
#undef LOG_DOMAIN

#else

#include <stdarg.h>
#include <stdio.h>

/* define LOG_TAG as "security_*" at your submodule, * means your submodule name such as "security_dac" */
#define LOG_TAG "accssToken_"

#define AT_LOG_DEBUG(fmt, ...) printf("[%s] debug: " fmt "\n", LOG_TAG, ##__VA_ARGS__)
#define AT_LOG_INFO(fmt, ...) printf("[%s] info: " fmt "\n", LOG_TAG,  ##__VA_ARGS__)
#define AT_LOG_WARN(fmt, ...) printf("[%s] warn: " fmt "\n", LOG_TAG,  ##__VA_ARGS__)
#define AT_LOG_ERROR(fmt, ...) printf("[%s] error: " fmt "\n", LOG_TAG, ##__VA_ARGS__)
#define AT_LOG_FATAL(fmt, ...) printf("[%s] fatal: " fmt "\n", LOG_TAG, ##__VA_ARGS__)

#endif  // HILOG_ENABLE

#endif  // ACCESSTOKEN_LOG_H
