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

#include "strcpy_wrapper.h"

static int g_strcpyCount = 0;
static int g_strcpyFailCount = -1;

void SetStrcpyFailCount(int count)
{
    g_strcpyCount = 0;
    g_strcpyFailCount = count;
}

void ResetStrcpyMock(void)
{
    g_strcpyCount = 0;
    g_strcpyFailCount = -1;
}

int GetStrcpyCount(void)
{
    return g_strcpyCount;
}

int __real_strcpy_s(char *strDest, size_t destMax, const char *strSrc);

int __wrap_strcpy_s(char *strDest, size_t destMax, const char *strSrc)
{
    g_strcpyCount++;
    if (g_strcpyFailCount > 0 && g_strcpyCount >= g_strcpyFailCount) {
        return -1;
    }
    return __real_strcpy_s(strDest, destMax, strSrc);
}
