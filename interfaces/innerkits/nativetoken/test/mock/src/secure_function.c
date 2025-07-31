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

#include <stdint.h>
#include <dlfcn.h>
#include <stdio.h>


int g_strcpyTime = 100;
static void *g_handle = NULL;

static void GetHandle(void)
{
    if (g_handle != NULL) {
        return;
    }
    g_handle = dlopen("libsec_shared.z.so", RTLD_LAZY);
}

int strcpy_s(char *strDest, size_t destMax, const char *strSrc)
{
    GetHandle();
    if (g_handle == NULL) {
        printf("dlopen failed\n");
    }
    if (g_strcpyTime == 0) {
        g_strcpyTime++;
        return -1;
    }

    static int (*func)(char *strDest, size_t destMax, const char *strSrc) = NULL;
    if (func == NULL) {
        func = (int (*)(char *strDest, size_t destMax, const char *strSrc))dlsym(g_handle, "strcpy_s");
    }
    if (func == NULL) {
        printf("dlsym strcpy_s failed\n");
        return -1;
    }

    return func(strDest, destMax, strSrc);
}