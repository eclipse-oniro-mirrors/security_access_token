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
#include "nativetoken_json_oper.h"
#include <stdlib.h>
#include <string.h>
#include <securec.h>
#include "nativetoken_log.h"

void FreeStrArray(char **arr, int32_t num)
{
    for (int32_t i = 0; i <= num; i++) {
        if (arr[i] != NULL) {
            free(arr[i]);
            arr[i] = NULL;
        }
    }
}

uint32_t GetProcessNameFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode)
{
    cJSON *processNameJson = cJSON_GetObjectItem(cjsonItem, PROCESS_KEY_NAME);
    if (!cJSON_IsString(processNameJson) || (processNameJson->valuestring == NULL) ||
        (strlen(processNameJson->valuestring) > MAX_PROCESS_NAME_LEN)) {
        AT_LOG_ERROR("[ATLIB-%s]:processNameJson is invalid.", __func__);
        return ATRET_FAILED;
    }

    if (strcpy_s(tokenNode->processName, MAX_PROCESS_NAME_LEN + 1, processNameJson->valuestring) != EOK) {
        AT_LOG_ERROR("[ATLIB-%s]:strcpy_s failed.", __func__);
        return ATRET_FAILED;
    }
    return ATRET_SUCCESS;
}

uint32_t GetTokenIdFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode)
{
    cJSON *tokenIdJson = cJSON_GetObjectItem(cjsonItem, TOKENID_KEY_NAME);
    if ((!cJSON_IsNumber(tokenIdJson)) || (cJSON_GetNumberValue(tokenIdJson) <= 0)) {
        AT_LOG_ERROR("[ATLIB-%s]:tokenIdJson is invalid.", __func__);
        return ATRET_FAILED;
    }

    AtInnerInfo *atIdInfo = (AtInnerInfo *)&(tokenIdJson->valueint);
    if (atIdInfo->type != TOKEN_NATIVE_TYPE && atIdInfo->type != TOKEN_SHELL_TYPE) {
        AT_LOG_ERROR("[ATLIB-%s]:tokenId type is invalid.", __func__);
        return ATRET_FAILED;
    }

    tokenNode->tokenId = (NativeAtId)tokenIdJson->valueint;
    return ATRET_SUCCESS;
}

uint32_t GetAplFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode)
{
    cJSON *aplJson = cJSON_GetObjectItem(cjsonItem, APL_KEY_NAME);
    if (!cJSON_IsNumber(aplJson)) {
        AT_LOG_ERROR("[ATLIB-%s]:aplJson is invalid.", __func__);
        return ATRET_FAILED;
    }
    int32_t apl = cJSON_GetNumberValue(aplJson);
    if (apl <= 0 || apl > SYSTEM_CORE) {
        AT_LOG_ERROR("[ATLIB-%s]:apl = %d in file is invalid.", __func__, apl);
        return ATRET_FAILED;
    }
    tokenNode->apl = aplJson->valueint;
    return ATRET_SUCCESS;
}

uint32_t GetInfoArrFromJson(cJSON *cjsonItem, char *strArr[], int32_t *strNum, StrArrayAttr *attr)
{
    cJSON *strArrJson = cJSON_GetObjectItem(cjsonItem, attr->strKey);
    int32_t size = cJSON_GetArraySize(strArrJson);
    if (size > attr->maxStrNum) {
        AT_LOG_ERROR("[ATLIB-%s]:size = %d is invalid.", __func__, size);
        return ATRET_FAILED;
    }
    *strNum = size;

    for (int32_t i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(strArrJson, i);
        if ((item == NULL) || (!cJSON_IsString(item)) || (item->valuestring == NULL)) {
            AT_LOG_ERROR("[ATLIB-%s]:cJSON_GetArrayItem failed.", __func__);
            return ATRET_FAILED;
        }
        size_t length = strlen(item->valuestring);
        if (length > attr->maxStrLen) {
            AT_LOG_ERROR("[ATLIB-%s]:item length %zu is invalid.", __func__, length);
            return ATRET_FAILED;
        }
        strArr[i] = (char *)malloc(sizeof(char) * (length + 1));
        if (strArr[i] == NULL) {
            FreeStrArray(strArr, i - 1);
            AT_LOG_ERROR("[ATLIB-%s]:malloc invalid.", __func__);
            return ATRET_FAILED;
        }
        if (strcpy_s(strArr[i], length + 1, item->valuestring) != EOK) {
            FreeStrArray(strArr, i);
            AT_LOG_ERROR("[ATLIB-%s]:strcpy_s failed.", __func__);
            return ATRET_FAILED;
        }
    }
    return ATRET_SUCCESS;
}

static int32_t AddStrArrayInfo(cJSON *object, char* const strArray[], int32_t strNum, const char *strKey)
{
    cJSON *strJsonArr = cJSON_CreateArray();
    if (strJsonArr == NULL) {
        AT_LOG_ERROR("[ATLIB-%s]:CreateArray failed, strKey :%s.", __func__, strKey);
        return ATRET_FAILED;
    }
    for (int32_t i = 0; i < strNum; i++) {
        cJSON *item =  cJSON_CreateString(strArray[i]);
        if (item == NULL || !cJSON_AddItemToArray(strJsonArr, item)) {
            AT_LOG_ERROR("[ATLIB-%s]:AddItemToArray failed, strKey : %s.", __func__, strKey);
            cJSON_Delete(item);
            cJSON_Delete(strJsonArr);
            return ATRET_FAILED;
        }
    }
    if (!cJSON_AddItemToObject(object, strKey, strJsonArr)) {
        AT_LOG_ERROR("[ATLIB-%s]:AddItemToObject failed, strKey : %s.", __func__, strKey);
        cJSON_Delete(strJsonArr);
        return ATRET_FAILED;
    }
    return ATRET_SUCCESS;
}

int32_t SetNativeTokenJsonObject(const NativeTokenList *curr, cJSON *object)
{
    cJSON *item = cJSON_CreateString(curr->processName);
    if (item == NULL || !cJSON_AddItemToObject(object, PROCESS_KEY_NAME, item)) {
        AT_LOG_ERROR("[ATLIB-%s]:processName cJSON_AddItemToObject failed.", __func__);
        cJSON_Delete(item);
        return ATRET_FAILED;
    }

    item = cJSON_CreateNumber(curr->apl);
    if (item == NULL || !cJSON_AddItemToObject(object, APL_KEY_NAME, item)) {
        AT_LOG_ERROR("[ATLIB-%s]:APL cJSON_AddItemToObject failed.", __func__);
        cJSON_Delete(item);
        return ATRET_FAILED;
    }

    item = cJSON_CreateNumber(DEFAULT_AT_VERSION);
    if (item == NULL || !cJSON_AddItemToObject(object, VERSION_KEY_NAME, item)) {
        AT_LOG_ERROR("[ATLIB-%s]:version cJSON_AddItemToObject failed.", __func__);
        cJSON_Delete(item);
        return ATRET_FAILED;
    }

    item = cJSON_CreateNumber(curr->tokenId);
    if (item == NULL || !cJSON_AddItemToObject(object, TOKENID_KEY_NAME, item)) {
        AT_LOG_ERROR("[ATLIB-%s]:tokenId cJSON_AddItemToObject failed.", __func__);
        cJSON_Delete(item);
        return ATRET_FAILED;
    }

    item = cJSON_CreateNumber(0);
    if (item == NULL || !cJSON_AddItemToObject(object, TOKEN_ATTR_KEY_NAME, item)) {
        AT_LOG_ERROR("[ATLIB-%s]:tokenAttr cJSON_AddItemToObject failed.", __func__);
        cJSON_Delete(item);
        return ATRET_FAILED;
    }

    int32_t ret = AddStrArrayInfo(object, curr->dcaps, curr->dcapsNum, DCAPS_KEY_NAME);
    if (ret != ATRET_SUCCESS) {
        return ret;
    }

    ret = AddStrArrayInfo(object, curr->perms, curr->permsNum, PERMS_KEY_NAME);
    if (ret != ATRET_SUCCESS) {
        return ret;
    }

    ret = AddStrArrayInfo(object, curr->acls, curr->aclsNum, ACLS_KEY_NAME);
    return ret;
}

cJSON *CreateNativeTokenJsonObject(const NativeTokenList *curr)
{
    cJSON *object = cJSON_CreateObject();
    if (object == NULL) {
        AT_LOG_ERROR("[ATLIB-%s]:cJSON_CreateObject failed.", __func__);
        return NULL;
    }
    if (SetNativeTokenJsonObject(curr, object) != ATRET_SUCCESS) {
        cJSON_Delete(object);
        return NULL;
    }

    return object;
}

static uint32_t UpdateStrArrayType(char* const strArr[], int32_t strNum, const char *strKey, cJSON *record)
{
    cJSON *strArrJson = cJSON_CreateArray();
    if (strArrJson == NULL) {
        AT_LOG_ERROR("[ATLIB-%s]:cJSON_CreateArray failed.", __func__);
        return ATRET_FAILED;
    }
    for (int32_t i = 0; i < strNum; i++) {
        cJSON *item =  cJSON_CreateString(strArr[i]);
        if (item == NULL) {
            AT_LOG_ERROR("[ATLIB-%s]:cJSON_CreateString failed.", __func__);
            cJSON_Delete(strArrJson);
            return ATRET_FAILED;
        }
        if (!cJSON_AddItemToArray(strArrJson, item)) {
            AT_LOG_ERROR("[ATLIB-%s]:cJSON_AddItemToArray failed.", __func__);
            cJSON_Delete(item);
            cJSON_Delete(strArrJson);
            return ATRET_FAILED;
        }
    }
    if (cJSON_GetObjectItem(record, strKey) != NULL) {
        if (!cJSON_ReplaceItemInObject(record, strKey, strArrJson)) {
            AT_LOG_ERROR("[ATLIB-%s]:cJSON_ReplaceItemInObject failed.", __func__);
            cJSON_Delete(strArrJson);
            return ATRET_FAILED;
        }
    } else {
        if (!cJSON_AddItemToObject(record, strKey, strArrJson)) {
            AT_LOG_ERROR("[ATLIB-%s]:cJSON_AddItemToObject failed.", __func__);
            cJSON_Delete(strArrJson);
            return ATRET_FAILED;
        }
    }

    return ATRET_SUCCESS;
}

static uint32_t UpdateItemcontent(const NativeTokenList *tokenNode, cJSON *record)
{
    cJSON *itemApl =  cJSON_CreateNumber(tokenNode->apl);
    if (itemApl == NULL) {
        return ATRET_FAILED;
    }
    if (!cJSON_ReplaceItemInObject(record, APL_KEY_NAME, itemApl)) {
        cJSON_Delete(itemApl);
        AT_LOG_ERROR("[ATLIB-%s]:APL update failed.", __func__);
        return ATRET_FAILED;
    }

    uint32_t ret = UpdateStrArrayType(tokenNode->dcaps, tokenNode->dcapsNum, DCAPS_KEY_NAME, record);
    if (ret != ATRET_SUCCESS) {
        AT_LOG_ERROR("[ATLIB-%s]:dcaps update failed.", __func__);
        return ATRET_FAILED;
    }

    ret = UpdateStrArrayType(tokenNode->perms, tokenNode->permsNum, PERMS_KEY_NAME, record);
    if (ret != ATRET_SUCCESS) {
        AT_LOG_ERROR("[ATLIB-%s]:perms update failed.", __func__);
        return ATRET_FAILED;
    }

    ret = UpdateStrArrayType(tokenNode->acls, tokenNode->aclsNum, ACLS_KEY_NAME, record);
    if (ret != ATRET_SUCCESS) {
        AT_LOG_ERROR("[ATLIB-%s]:acls update failed.", __func__);
        return ATRET_FAILED;
    }
    return ATRET_SUCCESS;
}

uint32_t UpdateGoalItemFromRecord(const NativeTokenList *tokenNode, cJSON *record)
{
    int32_t arraySize = cJSON_GetArraySize(record);
    for (int32_t i = 0; i < arraySize; i++) {
        cJSON *cjsonItem = cJSON_GetArrayItem(record, i);
        if (cjsonItem == NULL) {
            AT_LOG_ERROR("[ATLIB-%s]:cJSON_GetArrayItem failed.", __func__);
            return ATRET_FAILED;
        }
        cJSON *processNameJson = cJSON_GetObjectItem(cjsonItem, PROCESS_KEY_NAME);
        if ((processNameJson == NULL) || (!cJSON_IsString(processNameJson)) || (processNameJson->valuestring == NULL)) {
            AT_LOG_ERROR("[ATLIB-%s]:processNameJson is null.", __func__);
            return ATRET_FAILED;
        }
        if (strcmp(processNameJson->valuestring, tokenNode->processName) == 0) {
            return UpdateItemcontent(tokenNode, cjsonItem);
        }
    }
    AT_LOG_ERROR("[ATLIB-%s]:cannot find process in config file.", __func__);
    return ATRET_FAILED;
}
