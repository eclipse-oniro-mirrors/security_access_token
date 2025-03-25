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

#include "accesstoken_common_log.h"

#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <string>
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

constexpr uint32_t MAX_ERROR_MESSAGE_LEN = 4096;
static __thread uint32_t g_msgLen = 0;
static __thread char g_errMsg[MAX_ERROR_MESSAGE_LEN + 1];

uint32_t GetThreadErrorMsgLen(void)
{
    return g_msgLen;
}

const char *GetThreadErrorMsg(void)
{
    return g_errMsg;
}

void ClearThreadErrorMsg(void)
{
    (void)memset_s(g_errMsg, MAX_ERROR_MESSAGE_LEN + 1, 0, MAX_ERROR_MESSAGE_LEN + 1);
    g_msgLen = 0;
}

void AppendThreadErrMsg(unsigned int domain, const char *tag,
    const uint8_t *buff, uint32_t buffLen)
{
    if (g_msgLen + buffLen >= MAX_ERROR_MESSAGE_LEN) {
        LOGE(domain, tag, "buff will overflow!"
            "g_msgLen = %{public}u, buffLen = %{public}u", g_msgLen, buffLen);
        return;
    }
    if (memcpy_s(g_errMsg + g_msgLen, MAX_ERROR_MESSAGE_LEN - g_msgLen, buff, buffLen) != EOK) {
        LOGE(domain, tag, "memcpy_s fail!"
            "g_msgLen = %{public}u, buffLen = %{public}u", g_msgLen, buffLen);
        return;
    }
    g_msgLen += buffLen;
}

static bool ReplaceSubstring(unsigned int domain, const char *tag,
    const char *format, char result[MAX_ERROR_MESSAGE_LEN])
{
    std::string formatString(format);
    std::string::size_type pos;
    while ((pos = formatString.find(LOG_PUBLIC)) != std::string::npos) {
        formatString.replace(pos, strlen(LOG_PUBLIC), "");
    }
    if (memcpy_s(result, MAX_ERROR_MESSAGE_LEN, formatString.c_str(), formatString.size()) != EOK) {
        return false;
    }
    return true;
}

void AddEventMessage(unsigned int domain, const char *tag,
    const char *format, ...)
{
    va_list ap;

    if (g_msgLen == 0) {
        char newFormat[MAX_ERROR_MESSAGE_LEN] = {0};
        if (!ReplaceSubstring(domain, tag, format, newFormat)) {
            LOGE(domain, tag, "skip to add errMsg");
            return;
        }
        va_start(ap, format);
        char buff[MAX_ERROR_MESSAGE_LEN] = {0};
        int32_t buffLen = vsnprintf_s(buff, MAX_ERROR_MESSAGE_LEN, MAX_ERROR_MESSAGE_LEN - 1, newFormat, ap);
        va_end(ap);
        if (buffLen < 0) {
            LOGE(domain, tag, "vsnprintf_s fail! ret: %{public}d, newFormat:[%{public}s]", buffLen,
                newFormat);
            return;
        }
        if (g_msgLen + static_cast<uint32_t>(buffLen) >= MAX_ERROR_MESSAGE_LEN) {
            LOGE(domain, tag, "errMsg is almost full!");
            return;
        }

        if (memcpy_s(g_errMsg + g_msgLen, MAX_ERROR_MESSAGE_LEN, buff, buffLen) != EOK) {
            LOGE(domain, tag, "copy errMsg buff fail!");
            return;
        }
        g_msgLen += static_cast<uint32_t>(buffLen);
    } else {
        va_start(ap, format);
        char *funName = va_arg(ap, char *);
        uint32_t lineNo = va_arg(ap, uint32_t);
        va_end(ap);

        if (funName == nullptr) {
            LOGE(domain, tag, "Get funName fail!");
            return;
        }
        int32_t offset = sprintf_s(g_errMsg + g_msgLen, MAX_ERROR_MESSAGE_LEN - g_msgLen, " <%s[%u]",
            funName, lineNo);
        if (offset <= 0) {
            LOGE(domain, tag, "append call chain fail! offset: [%{public}d]", offset);
            return;
        }
        g_msgLen += static_cast<uint32_t>(offset);
    }
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS