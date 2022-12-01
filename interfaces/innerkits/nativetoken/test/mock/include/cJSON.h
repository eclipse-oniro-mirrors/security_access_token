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

#ifndef CJSON__H
#define CJSON__H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

/* The cJSON structure: */
typedef int cJSON_bool;
typedef struct cJSON
{
    struct cJSON* next;
    struct cJSON* prev;
    struct cJSON* child;
    int type;
    char* valuestring;
    int valueint;
    double valuedouble;
    char* string;
} cJSON;

extern int g_getArrayItemTime;
extern int g_getObjectItem;
extern int g_isStringTime;
extern int g_createNumberTime;
extern int g_replaceItemInObjectTime;
extern int g_createArrayTime;
extern int g_createStringTime;
extern int g_addItemToArray;
extern int g_addItemToObject;
extern int g_createObject;
extern int g_parse;
extern int g_getArraySize;
extern int g_printUnformatted;

cJSON* cJSON_GetObjectItem(const cJSON* const object, const char* const string);
cJSON_bool cJSON_IsNumber(const cJSON* const item);
cJSON_bool cJSON_IsString(const cJSON* const item);
double cJSON_GetNumberValue(const cJSON* const item);
int cJSON_GetArraySize(const cJSON* array);
cJSON* cJSON_CreateArray(void);
cJSON* cJSON_CreateObject(void);
cJSON* cJSON_CreateNumber(double num);
cJSON* cJSON_CreateString(const char* string);
cJSON_bool cJSON_AddItemToArray(cJSON* array, cJSON* item);
void cJSON_Delete(cJSON* item);
cJSON_bool cJSON_AddItemToObject(cJSON* object, const char* string, cJSON* item);
cJSON_bool cJSON_ReplaceItemInObject(cJSON* object, const char* string, cJSON* newitem);
cJSON* cJSON_GetArrayItem(const cJSON* array, int index);
cJSON* cJSON_Parse(const char* value);
void cJSON_free(void* object);
char* cJSON_PrintUnformatted(const cJSON* item);

#ifdef __cplusplus
}
#endif

#endif
