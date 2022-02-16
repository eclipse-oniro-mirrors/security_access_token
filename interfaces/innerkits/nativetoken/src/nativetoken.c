/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing ACCESSTOKENs and
 * limitations under the License.
 */
#include "nativetoken.h"
#include "nativetoken_kit.h"

NativeTokenList *g_tokenListHead;
int32_t g_isNativeTokenInited = 0;

int32_t GetFileBuff(const char *cfg, char **retBuff)
{
    struct stat fileStat;
    int32_t ret;

    char filePath[PATH_MAX_LEN + 1] = {0};
    if (realpath(cfg, filePath) == NULL) {
        if (errno == ENOENT) {
            /* file doesn't exist */
            *retBuff = NULL;
            return ATRET_SUCCESS;
        }
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:invalid filePath.", __func__);
        return ATRET_FAILED;
    }

    if (stat(filePath, &fileStat) != 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:stat file failed.", __func__);
        return ATRET_FAILED;
    }

    int32_t fileSize = (int32_t)fileStat.st_size;
    if ((fileSize < 0) || (fileSize > MAX_JSON_FILE_LEN)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:stat file size is invalid.", __func__);
        return ATRET_FAILED;
    }

    FILE *cfgFd = fopen(filePath, "r");
    if (cfgFd == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:fopen file failed.", __func__);
        return ATRET_FAILED;
    }

    char *buff = (char *)malloc((size_t)(fileSize + 1));
    if (buff == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:memory alloc failed.", __func__);
        fclose(cfgFd);
        return ATRET_FAILED;
    }

    if (fread(buff, (size_t)fileSize, 1, cfgFd) != 1) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:fread failed.", __func__);
        free(buff);
        buff = NULL;
        ret = ATRET_FAILED;
    } else {
        buff[fileSize] = '\0';
        *retBuff = buff;
        ret = ATRET_SUCCESS;
    }

    fclose(cfgFd);
    return ret;
}

void FreeDcaps(char *dcaps[MAX_DCAPS_NUM], int32_t num)
{
    for (int32_t i = 0; i <= num; i++) {
        if (dcaps[i] != NULL) {
            free(dcaps[i]);
            dcaps[i] = NULL;
        }
    }
}

uint32_t GetprocessNameFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode)
{
    cJSON *processNameJson = cJSON_GetObjectItem(cjsonItem, PROCESS_KEY_NAME);
    if (cJSON_IsString(processNameJson) == 0 || (strlen(processNameJson->valuestring) > MAX_PROCESS_NAME_LEN)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:processNameJson is invalid.", __func__);
        return ATRET_FAILED;
    }

    if (strcpy_s(tokenNode->processName, MAX_PROCESS_NAME_LEN + 1, processNameJson->valuestring) != EOK) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:strcpy_s failed.", __func__);
        return ATRET_FAILED;
    }
    return ATRET_SUCCESS;
}

uint32_t GetTokenIdFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode)
{
    cJSON *tokenIdJson = cJSON_GetObjectItem(cjsonItem, TOKENID_KEY_NAME);
    if ((cJSON_IsNumber(tokenIdJson) == 0) || (cJSON_GetNumberValue(tokenIdJson) <= 0)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:tokenIdJson is invalid.", __func__);
        return ATRET_FAILED;
    }
    tokenNode->tokenId = (NativeAtId)tokenIdJson->valueint;
    return ATRET_SUCCESS;
}

uint32_t GetAplFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode)
{
    cJSON *aplJson = cJSON_GetObjectItem(cjsonItem, APL_KEY_NAME);
    if (cJSON_IsNumber(aplJson) == 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:aplJson is invalid.", __func__);
        return ATRET_FAILED;
    }
    int apl = cJSON_GetNumberValue(aplJson);
    if (apl <= 0 || apl > SYSTEM_CORE) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:apl = %d in file is invalid.", __func__, apl);
        return ATRET_FAILED;
    }
    tokenNode->apl = aplJson->valueint;
    return ATRET_SUCCESS;
}

uint32_t GetDcapsInfoFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode)
{
    cJSON *dcapsJson = cJSON_GetObjectItem(cjsonItem, DCAPS_KEY_NAME);
    int32_t dcapSize = cJSON_GetArraySize(dcapsJson);

    tokenNode->dcapsNum = dcapSize;
    for (int32_t i = 0; i < dcapSize; i++) {
        cJSON *dcapItem = cJSON_GetArrayItem(dcapsJson, i);
        if (dcapItem == NULL) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_GetArrayItem failed.", __func__);
            return ATRET_FAILED;
        }
        size_t length = strlen(dcapItem->valuestring);
        if (cJSON_IsString(dcapItem) == 0 || (length > MAX_DCAP_LEN)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:dcapItem is invalid.", __func__);
            return ATRET_FAILED;
        }
        tokenNode->dcaps[i] = (char *)malloc(sizeof(char) * length);
        if (tokenNode->dcaps[i] == NULL) {
            FreeDcaps(tokenNode->dcaps, i - 1);
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:malloc invalid.", __func__);
            return ATRET_FAILED;
        }
        if (strcpy_s(tokenNode->dcaps[i], length + 1, dcapItem->valuestring) != EOK) {
            FreeDcaps(tokenNode->dcaps, i);
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:strcpy_s failed.", __func__);
            return ATRET_FAILED;
        }
    }
    return ATRET_SUCCESS;
}

int32_t GetTokenList(const cJSON *object)
{
    int32_t arraySize;
    int32_t i;
    uint32_t ret;
    NativeTokenList *tmp = NULL;

    if (object == NULL) {
        return ATRET_FAILED;
    }
    arraySize = cJSON_GetArraySize(object);
    for (i = 0; i < arraySize; i++) {
        tmp = (NativeTokenList *)malloc(sizeof(NativeTokenList));
        if (tmp == NULL) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:memory alloc failed.", __func__);
            return ATRET_FAILED;
        }
        cJSON *cjsonItem = cJSON_GetArrayItem(object, i);
        if (cjsonItem == NULL) {
            free(tmp);
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_GetArrayItem failed.", __func__);
            return ATRET_FAILED;
        }
        ret = GetprocessNameFromJson(cjsonItem, tmp);
        ret |= GetTokenIdFromJson(cjsonItem, tmp);
        ret |= GetAplFromJson(cjsonItem, tmp);
        ret |= GetDcapsInfoFromJson(cjsonItem, tmp);
        if (ret != ATRET_SUCCESS) {
            free(tmp);
            return ATRET_FAILED;
        }

        tmp->next = g_tokenListHead->next;
        g_tokenListHead->next = tmp;
    }
    return ATRET_SUCCESS;
}

int32_t ParseTokenInfoFromCfg(const char *filename)
{
    char *fileBuff = NULL;
    cJSON *record = NULL;
    int32_t ret;

    if (filename == NULL || filename[0] == '\0') {
        return ATRET_FAILED;
    }
    ret = GetFileBuff(filename, &fileBuff);
    if (ret != ATRET_SUCCESS) {
        return ret;
    }
    if (fileBuff == NULL) {
        return ATRET_SUCCESS;
    }
    record = cJSON_Parse(fileBuff);
    free(fileBuff);
    fileBuff = NULL;

    ret = GetTokenList(record);
    cJSON_Delete(record);

    return ret;
}

int32_t AtlibInit(void)
{
    g_tokenListHead = (NativeTokenList *)malloc(sizeof(NativeTokenList));
    if (g_tokenListHead == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:g_tokenListHead memory alloc failed.", __func__);
        return ATRET_FAILED;
    }
    g_tokenListHead->next = NULL;

    int32_t ret = ParseTokenInfoFromCfg(TOKEN_ID_CFG_FILE_PATH);
    if (ret != ATRET_SUCCESS) {
        free(g_tokenListHead);
        g_tokenListHead = NULL;
        return ret;
    }
    g_isNativeTokenInited = 1;

    return ATRET_SUCCESS;
}

int GetRandomTokenId(uint32_t *randNum)
{
    uint32_t random;
    int len;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return ATRET_FAILED;
    }
    len = read(fd, &random, sizeof(random));
    (void)close(fd);
    if (len != sizeof(random)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:read failed.", __func__);
        return ATRET_FAILED;
    }
    *randNum = random;
    return ATRET_SUCCESS;
}

NativeAtId CreateNativeTokenId(void)
{
    uint32_t rand;
    NativeAtId tokenId;
    AtInnerInfo *innerId = (AtInnerInfo *)(&tokenId);

    int ret = GetRandomTokenId(&rand);
    if (ret != ATRET_SUCCESS) {
        return 0;
    }

    innerId->reserved = 0;
    innerId->tokenUniqueId = rand & (0xFFFFFF);
    innerId->type = TOKEN_NATIVE_TYPE;
    innerId->version = 1;
    return tokenId;
}

int32_t GetAplLevel(const char *aplStr)
{
    if (aplStr == NULL) {
        return 0;
    }
    if (strcmp(aplStr, "system_core") == 0) {
        return SYSTEM_CORE; // system_core means apl level is 3
    }
    if (strcmp(aplStr, "system_basic") == 0) {
        return SYSTEM_BASIC; // system_basic means apl level is 2
    }
    if (strcmp(aplStr, "normal") == 0) {
        return NORMAL;
    }
    ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:aplStr is invalid.", __func__);
    return 0;
}
int32_t NeedSetUidGid(int16_t *uid, int16_t *gid, int *needSet)
{
    struct stat buf;
    if (stat(TOKEN_ID_CFG_FILE_PATH, &buf) == 0) {
        *needSet = 0;
        return ATRET_SUCCESS;
    }
    if (errno != ENOENT) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:stat file path is invalid %d.",
                              __func__, errno);
        return ATRET_FAILED;
    }
    if (stat(TOKEN_ID_CFG_DIR_PATH, &buf) != 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:stat folder path is invalid %d.",
                              __func__, errno);
        return ATRET_FAILED;
    }
    *uid = buf.st_uid;
    *gid = buf.st_gid;
    *needSet = 1;
    ACCESSTOKEN_LOG_INFO("[ATLIB-%s]:needSet is true.", __func__);
    return ATRET_SUCCESS;
}

void WriteToFile(const cJSON *root)
{
    int32_t strLen;
    int32_t writtenLen;

    char *jsonStr = NULL;
    jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_PrintUnformatted failed.", __func__);
        return;
    }

    do {
        int16_t uid;
        int16_t gid;
        int needSet = 0;
        if (NeedSetUidGid(&uid, &gid, &needSet) != ATRET_SUCCESS) {
            break;
        }
        int32_t fd = open(TOKEN_ID_CFG_FILE_PATH, O_RDWR | O_CREAT | O_TRUNC,
                          S_IRUSR | S_IWUSR | S_IRGRP);
        if (fd < 0) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:open failed.", __func__);
            break;
        }
        strLen = strlen(jsonStr);
        writtenLen = write(fd, (void *)jsonStr, (size_t)strLen);
        close(fd);
        if (writtenLen != strLen) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:write failed, writtenLen is %d.", __func__, writtenLen);
            break;
        }
        if ((needSet == 1) && chown(TOKEN_ID_CFG_FILE_PATH, uid, gid) != 0) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:chown failed, errno is %d.", __func__, errno);
            break;
        }
    } while (0);

    cJSON_free(jsonStr);
    return;
}

int32_t AddDcapsArray(cJSON *object, const NativeTokenList *curr)
{
    cJSON *dcapsArr = cJSON_CreateArray();
    if (dcapsArr == NULL) {
        return ATRET_FAILED;
    }
    for (int32_t i = 0; i < curr->dcapsNum; i++) {
        cJSON *item =  cJSON_CreateString(curr->dcaps[i]);
        if (item == NULL || !cJSON_AddItemToArray(dcapsArr, item)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:tokenAttr cJSON_AddItemToArray failed.", __func__);
            cJSON_Delete(item);
            cJSON_Delete(dcapsArr);
            return ATRET_FAILED;
        }
    }
    if (!cJSON_AddItemToObject(object, DCAPS_KEY_NAME, dcapsArr)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:dcaps cJSON_AddItemToObject failed.", __func__);
        cJSON_Delete(dcapsArr);
        return ATRET_FAILED;
    }
    return ATRET_SUCCESS;
}

static cJSON *CreateNativeTokenJsonObject(const NativeTokenList *curr)
{
    cJSON *object = cJSON_CreateObject();
    if (object == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_CreateObject failed.", __func__);
        return NULL;
    }

    cJSON *item = cJSON_CreateString(curr->processName);
    if (item == NULL || !cJSON_AddItemToObject(object, PROCESS_KEY_NAME, item)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:processName cJSON_AddItemToObject failed.", __func__);
        cJSON_Delete(item);
        cJSON_Delete(object);
        return NULL;
    }

    item = cJSON_CreateNumber(curr->apl);
    if (item == NULL || !cJSON_AddItemToObject(object, APL_KEY_NAME, item)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:APL cJSON_AddItemToObject failed.", __func__);
        cJSON_Delete(item);
        cJSON_Delete(object);
        return NULL;
    }

    item = cJSON_CreateNumber(DEFAULT_AT_VERSION);
    if (item == NULL || !cJSON_AddItemToObject(object, VERSION_KEY_NAME, item)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:version cJSON_AddItemToObject failed.", __func__);
        cJSON_Delete(item);
        cJSON_Delete(object);
        return NULL;
    }

    item = cJSON_CreateNumber(curr->tokenId);
    if (item == NULL || !cJSON_AddItemToObject(object, TOKENID_KEY_NAME, item)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:tokenId cJSON_AddItemToObject failed.", __func__);
        cJSON_Delete(item);
        cJSON_Delete(object);
        return NULL;
    }

    item = cJSON_CreateNumber(0);
    if (item == NULL || !cJSON_AddItemToObject(object, TOKEN_ATTR_KEY_NAME, item)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:tokenAttr cJSON_AddItemToObject failed.", __func__);
        cJSON_Delete(item);
        cJSON_Delete(object);
        return NULL;
    }
    int ret = AddDcapsArray(object, curr);
    if (ret != ATRET_SUCCESS) {
        cJSON_Delete(object);
    }
    return object;
}
 
void SaveTokenIdToCfg(const NativeTokenList *curr)
{
    char *fileBuff = NULL;
    cJSON *record = NULL;
    int32_t ret;

    ret = GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff);
    if (ret != ATRET_SUCCESS) {
        return;
    }

    if (fileBuff == NULL) {
        record = cJSON_CreateArray();
    } else {
        record = cJSON_Parse(fileBuff);
        free(fileBuff);
        fileBuff = NULL;
    }

    if (record == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:get record failed.", __func__);
        return;
    }

    cJSON *node = CreateNativeTokenJsonObject(curr);
    if (node == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:CreateNativeTokenJsonObject failed.", __func__);
        cJSON_Delete(record);
        return;
    }
    cJSON_AddItemToArray(record, node);

    WriteToFile(record);
    cJSON_Delete(record);
    return;
}

uint32_t CheckProcessInfo(const char *processname, const char **dcaps,
                          int32_t dacpNum, const char *aplStr, int32_t *aplRet)
{
    if ((processname == NULL) || strlen(processname) > MAX_PROCESS_NAME_LEN
        || strlen(processname) == 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:processname is invalid.", __func__);
        return ATRET_FAILED;
    }

    if (((dcaps == NULL) && (dacpNum != 0)) || dacpNum > MAX_DCAPS_NUM || dacpNum < 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:dcaps is null or dacpNum is invalid.", __func__);
        return ATRET_FAILED;
    }
    for (int32_t i = 0; i < dacpNum; i++) {
        if (strlen(dcaps[i]) > MAX_DCAP_LEN) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:dcap length is invalid.", __func__);
            return ATRET_FAILED;
        }
    }

    int32_t apl = GetAplLevel(aplStr);
    if (apl == 0) {
        return ATRET_FAILED;
    }
    *aplRet = apl;
    return ATRET_SUCCESS;
}

int32_t NativeTokenIdCheck(NativeAtId tokenId)
{
    NativeTokenList *tokenNode = g_tokenListHead;
    while (tokenNode != NULL) {
        if (tokenNode->tokenId == tokenId) {
            return 1;
        }
        tokenNode = tokenNode->next;
    }
    return 0;
}

static uint32_t AddNewTokenToListAndCfgFile(const char *processname, const char **dcapsIn,
                                            int32_t dacpNumIn, int32_t aplIn, NativeAtId *tokenId)
{
    NativeTokenList *tokenNode;
    NativeAtId id;
    int32_t repeat;

    do {
        id = CreateNativeTokenId();
        repeat = NativeTokenIdCheck(id);
    } while (repeat == 1);

    tokenNode = (NativeTokenList *)malloc(sizeof(NativeTokenList));
    if (tokenNode == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:memory alloc failed.", __func__);
        return ATRET_FAILED;
    }
    tokenNode->tokenId = id;
    tokenNode->apl = aplIn;
    if (strcpy_s(tokenNode->processName, MAX_PROCESS_NAME_LEN + 1, processname) != EOK) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:strcpy_s failed.", __func__);
        free(tokenNode);
        return ATRET_FAILED;
    }
    tokenNode->dcapsNum = dacpNumIn;

    for (int32_t i = 0; i < dacpNumIn; i++) {
        tokenNode->dcaps[i] = (char *)malloc(sizeof(char) * (strlen(dcapsIn[i]) + 1));
        if (tokenNode->dcaps[i] != NULL &&
            (strcpy_s(tokenNode->dcaps[i], strlen(dcapsIn[i]) + 1, dcapsIn[i]) != EOK)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:copy dcapsIn[%d] failed.", __func__, i);
            FreeDcaps(tokenNode->dcaps, i);
            free(tokenNode);
            return ATRET_FAILED;
        }
    }
    tokenNode->next = g_tokenListHead->next;
    g_tokenListHead->next = tokenNode;

    *tokenId = id;

    SaveTokenIdToCfg(tokenNode);
    return ATRET_SUCCESS;
}

int32_t CompareProcessInfo(NativeTokenList *tokenNode, const char **dcapsIn, int32_t dacpNumIn, int32_t aplIn)
{
    if (tokenNode->apl != aplIn) {
        return 1;
    }
    if (tokenNode->dcapsNum != dacpNumIn) {
        return 1;
    }
    for (int32_t i = 0; i < dacpNumIn; i++) {
        if (strcmp(tokenNode->dcaps[i], dcapsIn[i]) != 0) {
            return 1;
        }
    }
    return 0;
}

uint32_t UpdateTokenInfoInList(NativeTokenList *tokenNode, const char **dcapsIn, int32_t dacpNumIn, int32_t aplIn)
{
    tokenNode->apl = aplIn;

    for (int32_t i = 0; i < tokenNode->dcapsNum; i++) {
        free(tokenNode->dcaps[i]);
        tokenNode->dcaps[i] = NULL;
    }

    tokenNode->dcapsNum = dacpNumIn;
    for (int32_t i = 0; i < dacpNumIn; i++) {
        int32_t len = strlen(dcapsIn[i]) + 1;
        tokenNode->dcaps[i] = (char *)malloc(sizeof(char) * len);
        if (tokenNode->dcaps[i] != NULL && (strcpy_s(tokenNode->dcaps[i], len, dcapsIn[i]) != EOK)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:copy dcapsIn[%d] failed.", __func__, i);
            FreeDcaps(tokenNode->dcaps, i);
            return ATRET_FAILED;
        }
    }
    return ATRET_SUCCESS;
}

uint32_t UpdateItemcontent(const NativeTokenList *tokenNode, cJSON *record)
{
    cJSON *itemApl =  cJSON_CreateNumber(tokenNode->apl);
    if (itemApl == NULL) {
        return ATRET_FAILED;
    }
    if (!cJSON_ReplaceItemInObject(record, APL_KEY_NAME, itemApl)) {
        cJSON_Delete(itemApl);
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:APL update failed.", __func__);
        return ATRET_FAILED;
    }

    cJSON *dcapsArr = cJSON_CreateArray();
    if (dcapsArr == NULL) {
        return ATRET_FAILED;
    }
    for (int32_t i = 0; i < tokenNode->dcapsNum; i++) {
        cJSON *item =  cJSON_CreateString(tokenNode->dcaps[i]);
        if (item == NULL) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_CreateString failed.", __func__);
            cJSON_Delete(dcapsArr);
            return ATRET_FAILED;
        }
        if (!cJSON_AddItemToArray(dcapsArr, item)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_AddItemToArray failed.", __func__);
            cJSON_Delete(item);
            return ATRET_FAILED;
        }
    }
    if (!cJSON_ReplaceItemInObject(record, DCAPS_KEY_NAME, dcapsArr)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:dcaps update failed.", __func__);
        cJSON_Delete(dcapsArr);
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
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_GetArrayItem failed.", __func__);
            return ATRET_FAILED;
        }
        cJSON *processNameJson = cJSON_GetObjectItem(cjsonItem, PROCESS_KEY_NAME);
        if (processNameJson == NULL) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:processNameJson is null.", __func__);
            return ATRET_FAILED;
        }
        if (strcmp(processNameJson->valuestring, tokenNode->processName) == 0) {
            return UpdateItemcontent(tokenNode, cjsonItem);
        }
    }
    ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cannot find process in config file.", __func__);
    return ATRET_FAILED;
}

uint32_t UpdateTokenInfoInCfgFile(NativeTokenList *tokenNode)
{
    cJSON *record = NULL;
    char *fileBuff = NULL;
    uint32_t ret;

    if (GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff) != ATRET_SUCCESS) {
        return ATRET_FAILED;
    }

    if (fileBuff == NULL) {
        record = cJSON_CreateArray();
    } else {
        record = cJSON_Parse(fileBuff);
        free(fileBuff);
        fileBuff = NULL;
    }

    if (record == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:get record failed.", __func__);
        return ATRET_FAILED;
    }

    ret = UpdateGoalItemFromRecord(tokenNode, record);
    if (ret != ATRET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:UpdateGoalItemFromRecord failed.", __func__);
        cJSON_Delete(record);
        return ATRET_FAILED;
    }

    WriteToFile(record);
    cJSON_Delete(record);
    return ATRET_SUCCESS;
}

uint64_t GetAccessTokenId(const char *processname, const char **dcaps, int32_t dacpNum, const char *aplStr)
{
    NativeAtId tokenId = 0;
    uint64_t result = 0;
    int32_t apl;
    NativeAtIdEx *atPoint = (NativeAtIdEx *)(&result);

    if ((g_isNativeTokenInited == 0) && (AtlibInit() != ATRET_SUCCESS)) {
        return 0;
    }

    uint32_t ret = CheckProcessInfo(processname, dcaps, dacpNum, aplStr, &apl);
    if (ret != ATRET_SUCCESS) {
        return 0;
    }

    NativeTokenList *tokenNode = g_tokenListHead;
    while (tokenNode != NULL) {
        if (strcmp(tokenNode->processName, processname) == 0) {
            tokenId = tokenNode->tokenId;
            break;
        }
        tokenNode = tokenNode->next;
    }

    if (tokenNode == NULL) {
        ret = AddNewTokenToListAndCfgFile(processname, dcaps, dacpNum, apl, &tokenId);
    } else {
        int32_t needUpdate = CompareProcessInfo(tokenNode, dcaps, dacpNum, apl);
        if (needUpdate != 0) {
            ret = UpdateTokenInfoInList(tokenNode, dcaps, dacpNum, apl);
            ret |= UpdateTokenInfoInCfgFile(tokenNode);
        }
    }
    if (ret != ATRET_SUCCESS) {
        return 0;
    }

    atPoint->tokenId = tokenId;
    atPoint->tokenAttr = 0;
    return result;
}