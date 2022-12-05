/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "cJSON.h"

#include <dlfcn.h>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int g_getArrayItemTime;
int g_getObjectItem;
int g_isStringTime;
int g_replaceItemInObjectTime;
int g_createNumberTime;
int g_createArrayTime;
int g_createStringTime;
int g_addItemToArray;
int g_addItemToObject;
int g_createObject;
int g_parse;
int g_getArraySize;
int g_printUnformatted;

#define CONST_TEN_TIMES 10
#define CONST_TWENTY_TIMES 20
#define CONST_THIRTY_TIMES 30
#define CONST_FORTY_TIMES 40
#define CONST_FIFTY_TIMES 50

static void* GetHandle(void)
{
#if defined(__LP64__)
    void* handle = dlopen("/system/lib64/libcjson.z.so", RTLD_LAZY);
#else
    void* handle = dlopen("/system/lib/libcjson.z.so", RTLD_LAZY);
#endif
    return handle;
}

cJSON* cJSON_GetObjectItem(const cJSON* const object, const char* const string)
{
    g_getObjectItem++;
    if (g_getObjectItem == 0 || g_getObjectItem == CONST_TEN_TIMES) { // CONST_TEN_TIMES times failed
        return NULL;
    }
    void* handle = GetHandle();
    if (handle == NULL) {
        return NULL;
    }
    cJSON* (*func)(const cJSON* const object, const char* const string);
    func = (cJSON* (*)(const cJSON* const object, const char* const string))dlsym(handle, "cJSON_GetObjectItem");
    if (func == NULL) {
        return NULL;
    }
    cJSON* res = func(object, string);
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return res;
}

cJSON_bool cJSON_IsNumber(const cJSON* const item)
{
    void* handle = GetHandle();
    if (handle == NULL) {
        return 0;
    }
    cJSON_bool (*func)(const cJSON* const item);
    func = (cJSON_bool (*)(const cJSON* const item))dlsym(handle, "cJSON_IsNumber");
    if (func == NULL) {
        return 0;
    }
    cJSON_bool res = func(item);
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return res;
}

cJSON_bool cJSON_IsString(const cJSON* const item)
{
    g_isStringTime++;
    if (g_isStringTime == 0) {
        return 0;
    }
    void* handle = GetHandle();
    if (handle == NULL) {
        return 0;
    }
    cJSON_bool (*func)(const cJSON* const item);
    func = (cJSON_bool (*)(const cJSON* const item))dlsym(handle, "cJSON_IsString");
    if (func == NULL) {
        return 0;
    }
    cJSON_bool res = func(item);
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return res;
}

double cJSON_GetNumberValue(const cJSON* const item)
{
    if (cJSON_IsNumber(item) == 0) {
        return (double)0;
    }

    return item->valuedouble;
}

int cJSON_GetArraySize(const cJSON* array)
{
    g_getArraySize++;
    if (g_getArraySize == 0 ||
        g_getArraySize == CONST_TEN_TIMES ||
        g_getArraySize == CONST_TWENTY_TIMES) {
        return 10000; // 10000 invalid
    }
    cJSON* child = NULL;
    size_t size = 0;
    if (array == NULL) {
        return 0;
    }
    child = array->child;
    while (child != NULL) {
        size++;
        child = child->next;
    }
    return (int)size;
}

cJSON* cJSON_CreateArray(void)
{
    g_createArrayTime++;
    if (g_createArrayTime == 0) {
        return NULL;
    }
    void* handle = GetHandle();
    if (handle == NULL) {
        return NULL;
    }
    cJSON* (*func)(void);
    func = (cJSON* (*)(void))dlsym(handle, "cJSON_CreateArray");
    if (func == NULL) {
        return NULL;
    }
    cJSON* res = func();
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return res;
}

cJSON* cJSON_CreateObject(void)
{
    g_createObject++;
    if (g_createObject == 0) {
        return NULL;
    }
    void* handle = GetHandle();
    if (handle == NULL) {
        return NULL;
    }
    cJSON* (*func)(void);
    func = (cJSON* (*)(void))dlsym(handle, "cJSON_CreateObject");
    if (func == NULL) {
        return NULL;
    }
    cJSON* res = func();
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return res;
}

cJSON* cJSON_CreateNumber(double num)
{
    g_createNumberTime++;
    if (g_createNumberTime == 0 ||
        g_createNumberTime == CONST_TEN_TIMES ||
        g_createNumberTime == CONST_TWENTY_TIMES ||
        g_createNumberTime == CONST_THIRTY_TIMES) {
        return NULL;
    }
    void* handle = GetHandle();
    if (handle == NULL) {
        return NULL;
    }
    cJSON* (*func)(double num);
    func = (cJSON* (*)(double num))dlsym(handle, "cJSON_CreateNumber");
    if (func == NULL) {
        return NULL;
    }
    cJSON* res = func(num);
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return res;
}

cJSON* cJSON_CreateString(const char *string)
{
    g_createStringTime++;
    if (g_createStringTime == 0 ||
        g_createStringTime == CONST_TEN_TIMES) {
        return NULL;
    }
    if (string != NULL && strcmp(string, "processUnique") == 0) {
        printf("processUnique failed\n");
        return NULL;
    }
    void* handle = GetHandle();
    if (handle == NULL) {
        return NULL;
    }
    cJSON* (*func)(const char *string);
    func = (cJSON* (*)(const char *string))dlsym(handle, "cJSON_CreateString");
    if (func == NULL) {
        return NULL;
    }
    cJSON* res = func(string);
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return res;
}

cJSON_bool cJSON_AddItemToArray(cJSON* array, cJSON* item)
{
    g_addItemToArray++;
    if (g_addItemToArray == 0) {
        return 0;
    }
    void* handle = GetHandle();
    if (handle == NULL) {
        return 0;
    }
    cJSON_bool (*func)(cJSON* array, cJSON* item);
    func = (cJSON_bool (*)(cJSON* array, cJSON* item))dlsym(handle, "cJSON_AddItemToArray");
    if (func == NULL) {
        return 0;
    }
    cJSON_bool res = func(array, item);
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return res;
}

void cJSON_Delete(cJSON* item)
{
    void* handle = GetHandle();
    if (handle == NULL) {
        return;
    }
    void (*func)(cJSON* item);
    func = (void (*)(cJSON* item))dlsym(handle, "cJSON_Delete");
    if (func == NULL) {
        return;
    }
    func(item);
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return;
}

cJSON_bool cJSON_AddItemToObject(cJSON*object, const char *string, cJSON* item)
{
    g_addItemToObject++;
    if (g_addItemToObject == 0 ||
        g_addItemToObject == CONST_TEN_TIMES ||
        g_addItemToObject == CONST_TWENTY_TIMES ||
        g_addItemToObject == CONST_THIRTY_TIMES ||
        g_addItemToObject == CONST_FORTY_TIMES ||
        g_addItemToObject == CONST_FIFTY_TIMES) {
        return 0;
    }
    void* handle = GetHandle();
    if (handle == NULL) {
        return 0;
    }
    cJSON_bool (*func)(cJSON*object, const char *string, cJSON* item);
    func = (cJSON_bool (*)(cJSON*object, const char *string, cJSON* item))dlsym(handle, "cJSON_AddItemToObject");
    if (func == NULL) {
        return 0;
    }
    cJSON_bool res = func(object, string, item);
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return res;
}

cJSON_bool cJSON_ReplaceItemInObject(cJSON*object, const char *string, cJSON*newitem)
{
    g_replaceItemInObjectTime++;
    if (g_replaceItemInObjectTime == 0 || g_replaceItemInObjectTime == CONST_TEN_TIMES) {
        return 0;
    }
    void* handle = GetHandle();
    if (handle == NULL) {
        return 0;
    }
    cJSON_bool (*func)(cJSON*object, const char *string, cJSON*newitem);
    func = (cJSON_bool (*)(cJSON*object, const char *string, cJSON*newitem))dlsym(handle, "cJSON_ReplaceItemInObject");
    if (func == NULL) {
        return 0;
    }
    cJSON_bool res = func(object, string, newitem);
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return res;
}

cJSON* cJSON_GetArrayItem(const cJSON* array, int index)
{
    g_getArrayItemTime++;
    if (g_getArrayItemTime == 0 ||
        g_getArrayItemTime == CONST_TEN_TIMES ||
        g_getArrayItemTime == CONST_TWENTY_TIMES) {
        return  NULL;
    }
    if (index < 0) {
        return NULL;
    }

    void* handle = GetHandle();
    if (handle == NULL) {
        return NULL;
    }
    cJSON* (*func)(const cJSON* array, int index);
    func = (cJSON* (*)(const cJSON* array, int index))dlsym(handle, "cJSON_GetArrayItem");
    if (func == NULL) {
        return NULL;
    }
    cJSON* res = func(array, index);
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return res;
}

cJSON* cJSON_Parse(const char *value)
{
    g_parse++;
    if (g_parse == 0 ||
        g_parse == CONST_TEN_TIMES) {
        return NULL;
    }
    void* handle = GetHandle();
    if (handle == NULL) {
        return NULL;
    }
    cJSON* (*func)(const char *value);
    func = (cJSON* (*)(const char *value))dlsym(handle, "cJSON_Parse");
    if (func == NULL) {
        return NULL;
    }
    cJSON* res = func(value);
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return res;
}

char* cJSON_PrintUnformatted(const cJSON* item)
{
    g_printUnformatted++;
    if (g_printUnformatted == 0) {
        return NULL;
    }
    void* handle = GetHandle();
    if (handle == NULL) {
        return NULL;
    }
    char* (*func)(const cJSON* item);
    func = (char* (*)(const cJSON* item))dlsym(handle, "cJSON_PrintUnformatted");
    if (func == NULL) {
        return NULL;
    }
    char* res = func(item);
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return res;
}

void cJSON_free(void* object)
{
    void* handle = GetHandle();
    if (handle == NULL) {
        return;
    }
    void (*func)(void* object);
    func = (void (*)(void* object))dlsym(handle, "cJSON_free");
    if (func == NULL) {
        return;
    }
    func(object);
    if (handle != NULL) {
        dlclose(handle);
        handle = NULL;
    }
    return;
}
