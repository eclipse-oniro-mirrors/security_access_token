/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifdef USE_NATIVE_TOKEN_KLOG
#include "accesstoken_klog.h"
#else
#include "accesstoken_common_log.h"
#endif

#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <string>
#include "securec.h"

static constexpr uint32_t MAX_ERROR_MESSAGE_LEN = 4096;
static __thread uint32_t g_msgLen = 0;
static __thread char g_errMsg[MAX_ERROR_MESSAGE_LEN + 1];

#ifdef USE_NATIVE_TOKEN_KLOG
#define ACCESSTOKEN_COMMON_LOGE(domain, tag, fmt, ...) \
    ((void)LOGE(fmt, ##__VA_ARGS__))
#else
#define ACCESSTOKEN_COMMON_LOGE(domain, tag, fmt, ...) \
    ((void)LOGE(domain, tag, fmt, ##__VA_ARGS__))
#endif

uint32_t GetThreadErrorMsgLen(void)
{
    return g_msgLen;
}

const char* GetThreadErrorMsg(void)
{
    return g_errMsg;
}

void ClearThreadErrorMsg(void)
{
    (void)memset_s(g_errMsg, MAX_ERROR_MESSAGE_LEN + 1, 0, MAX_ERROR_MESSAGE_LEN + 1);
    g_msgLen = 0;
}

void AppendThreadErrMsg(unsigned int domain, const char* tag,
    const uint8_t* buff, uint32_t buffLen)
{
    if (g_msgLen + buffLen >= MAX_ERROR_MESSAGE_LEN) {
        ACCESSTOKEN_COMMON_LOGE(domain, tag, "Buff will overflow!"
            "g_msgLen = %" LOG_PUBLIC "u, buffLen = %" LOG_PUBLIC "u", g_msgLen, buffLen);
        return;
    }
    if (memcpy_s(g_errMsg + g_msgLen, MAX_ERROR_MESSAGE_LEN - g_msgLen, buff, buffLen) != EOK) {
        ACCESSTOKEN_COMMON_LOGE(domain, tag, "Failed to memcpy_s!"
            "g_msgLen = %" LOG_PUBLIC "u, buffLen = %" LOG_PUBLIC "u", g_msgLen, buffLen);
        return;
    }
    g_msgLen += buffLen;
}

static bool ReplaceSubstring(unsigned int domain, const char* tag,
    const char* format, char result[MAX_ERROR_MESSAGE_LEN])
{
    std::string formatString(format);
#ifndef USE_NATIVE_TOKEN_KLOG
    std::string::size_type pos;
    while ((pos = formatString.find(LOG_PUBLIC)) != std::string::npos) {
        formatString.replace(pos, strlen(LOG_PUBLIC), "");
    }
#endif
    if (memcpy_s(result, MAX_ERROR_MESSAGE_LEN, formatString.c_str(), formatString.size()) != EOK) {
        return false;
    }
    return true;
}

void AddEventMessage(unsigned int domain, const char* tag,
    const char* format, ...)
{
    va_list ap;

    if (g_msgLen == 0) {
        char newFormat[MAX_ERROR_MESSAGE_LEN] = {0};
        if (!ReplaceSubstring(domain, tag, format, newFormat)) {
            ACCESSTOKEN_COMMON_LOGE(domain, tag, "Skip to add errMsg");
            return;
        }
        va_start(ap, format);
        char buff[MAX_ERROR_MESSAGE_LEN] = {0};
        int32_t buffLen = vsnprintf_s(buff, MAX_ERROR_MESSAGE_LEN, MAX_ERROR_MESSAGE_LEN - 1, newFormat, ap);
        va_end(ap);
        if (buffLen < 0) {
            ACCESSTOKEN_COMMON_LOGE(domain, tag,
                "Failed to vsnprintf_s! Ret: %" LOG_PUBLIC "d, newFormat:[%" LOG_PUBLIC "s]", buffLen, newFormat);
            return;
        }
        if (g_msgLen + static_cast<uint32_t>(buffLen) >= MAX_ERROR_MESSAGE_LEN) {
            ACCESSTOKEN_COMMON_LOGE(domain, tag, "ErrMsg is almost full!");
            return;
        }

        if (memcpy_s(g_errMsg + g_msgLen, MAX_ERROR_MESSAGE_LEN, buff, buffLen) != EOK) {
            ACCESSTOKEN_COMMON_LOGE(domain, tag, "Failed to copy errMsg buff!");
            return;
        }
        g_msgLen += static_cast<uint32_t>(buffLen);
    } else {
        va_start(ap, format);
        char* funName = va_arg(ap, char*);
        uint32_t lineNo = va_arg(ap, uint32_t);
        va_end(ap);

        if (funName == nullptr) {
            ACCESSTOKEN_COMMON_LOGE(domain, tag, "Get funName fail!");
            return;
        }
        int32_t offset = sprintf_s(g_errMsg + g_msgLen, MAX_ERROR_MESSAGE_LEN - g_msgLen, " <%s[%u]",
            funName, lineNo);
        if (offset <= 0) {
            ACCESSTOKEN_COMMON_LOGE(domain, tag, "Failed to append call chain! Offset: [%" LOG_PUBLIC "d]", offset);
            return;
        }
        g_msgLen += static_cast<uint32_t>(offset);
    }
}
