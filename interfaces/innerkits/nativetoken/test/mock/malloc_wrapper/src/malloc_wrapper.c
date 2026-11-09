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

#include "malloc_wrapper.h"

static int g_mallocCount = 0;
static int g_failCount = -1;

void SetMallocFailCount(int count)
{
    g_mallocCount = 0;
    g_failCount = count;
}

void ResetMallocMock(void)
{
    g_mallocCount = 0;
    g_failCount = -1;
}

int GetMallocCount(void)
{
    return g_mallocCount;
}

void* __real_malloc(size_t size);

void* __wrap_malloc(size_t size)
{
    g_mallocCount++;
    if (g_failCount > 0 && g_mallocCount >= g_failCount) {
        return NULL;
    }
    return __real_malloc(size);
}
