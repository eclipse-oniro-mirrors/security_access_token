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
#include "nativetoken.h"
#include "nativetoken_kit.h"

NativeTokenList *g_tokenListHead;
int32_t g_isNativeTokenInited = 0;

int32_t GetFileBuff(const char *cfg, char **retBuff)
{
    struct stat fileStat;

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

    if (fileStat.st_size == 0) {
        *retBuff = NULL;
        return ATRET_SUCCESS;
    }

    if (fileStat.st_size > MAX_JSON_FILE_LEN) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:stat file size is invalid.", __func__);
        return ATRET_FAILED;
    }

    size_t fileSize = (unsigned)fileStat.st_size;

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

    if (fread(buff, fileSize, 1, cfgFd) != 1) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:fread failed.", __func__);
        free(buff);
        buff = NULL;
        fclose(cfgFd);
        return ATRET_FAILED;
    }
    buff[fileSize] = '\0';
    *retBuff = buff;
    fclose(cfgFd);
    return ATRET_SUCCESS;
}

static void FreeStrArray(char **arr, int32_t num)
{
    for (int32_t i = 0; i <= num; i++) {
        if (arr[i] != NULL) {
            free(arr[i]);
            arr[i] = NULL;
        }
    }
}

static uint32_t GetProcessNameFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode)
{
    cJSON *processNameJson = cJSON_GetObjectItem(cjsonItem, PROCESS_KEY_NAME);
    if (!cJSON_IsString(processNameJson) || (strlen(processNameJson->valuestring) > MAX_PROCESS_NAME_LEN)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:processNameJson is invalid.", __func__);
        return ATRET_FAILED;
    }

    if (strcpy_s(tokenNode->processName, MAX_PROCESS_NAME_LEN + 1, processNameJson->valuestring) != EOK) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:strcpy_s failed.", __func__);
        return ATRET_FAILED;
    }
    return ATRET_SUCCESS;
}

static uint32_t GetTokenIdFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode)
{
    cJSON *tokenIdJson = cJSON_GetObjectItem(cjsonItem, TOKENID_KEY_NAME);
    if ((!cJSON_IsNumber(tokenIdJson)) || (cJSON_GetNumberValue(tokenIdJson) <= 0)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:tokenIdJson is invalid.", __func__);
        return ATRET_FAILED;
    }

    AtInnerInfo *atIdInfo = (AtInnerInfo *)&(tokenIdJson->valueint);
    if (atIdInfo->type != TOKEN_NATIVE_TYPE) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:tokenId type is invalid.", __func__);
        return ATRET_FAILED;
    }

    tokenNode->tokenId = (NativeAtId)tokenIdJson->valueint;
    return ATRET_SUCCESS;
}

static uint32_t GetAplFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode)
{
    cJSON *aplJson = cJSON_GetObjectItem(cjsonItem, APL_KEY_NAME);
    if (!cJSON_IsNumber(aplJson)) {
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

static uint32_t GetInfoArrFromJson(cJSON *cjsonItem, char *strArr[], int *strNum, StrArrayAttr *attr)
{
    cJSON *strArrJson = cJSON_GetObjectItem(cjsonItem, attr->strKey);
    int32_t size = cJSON_GetArraySize(strArrJson);
    if (size > attr->maxStrNum) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:size = %d is invalid.", __func__, size);
        return ATRET_FAILED;
    }
    *strNum = size;

    for (int32_t i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(strArrJson, i);
        if ((item == NULL) || (!cJSON_IsString(item)) || (item->valuestring == NULL)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_GetArrayItem failed.", __func__);
            return ATRET_FAILED;
        }
        size_t length = strlen(item->valuestring);
        if (length > attr->maxStrLen) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:item length %zu is invalid.", __func__, length);
            return ATRET_FAILED;
        }
        strArr[i] = (char *)malloc(sizeof(char) * (length + 1));
        if (strArr[i] == NULL) {
            FreeStrArray(strArr, i - 1);
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:malloc invalid.", __func__);
            return ATRET_FAILED;
        }
        if (strcpy_s(strArr[i], length + 1, item->valuestring) != EOK) {
            FreeStrArray(strArr, i);
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:strcpy_s failed.", __func__);
            return ATRET_FAILED;
        }
    }
    return ATRET_SUCCESS;
}

static int32_t GetTokenList(const cJSON *object)
{
    uint32_t ret;
    NativeTokenList *tmp = NULL;
    StrArrayAttr attr;

    if (object == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:object is null.", __func__);
        return ATRET_FAILED;
    }
    int32_t arraySize = cJSON_GetArraySize(object);

    for (int32_t i = 0; i < arraySize; i++) {
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
        ret = GetProcessNameFromJson(cjsonItem, tmp);
        ret |= GetTokenIdFromJson(cjsonItem, tmp);
        ret |= GetAplFromJson(cjsonItem, tmp);

        attr.maxStrLen = MAX_DCAP_LEN;
        attr.maxStrNum = MAX_DCAPS_NUM;
        attr.strKey = DCAPS_KEY_NAME;
        ret |= GetInfoArrFromJson(cjsonItem, tmp->dcaps, &(tmp->dcapsNum), &attr);
        if (ret != ATRET_SUCCESS) {
            free(tmp);
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:GetInfoArrFromJson failed for dcaps.", __func__);
            return ATRET_FAILED;
        }

        attr.maxStrLen = MAX_PERM_LEN;
        attr.maxStrNum = MAX_PERM_NUM;
        attr.strKey = PERMS_KEY_NAME;
        ret = GetInfoArrFromJson(cjsonItem, tmp->perms, &(tmp->permsNum), &attr);
        if (ret != ATRET_SUCCESS) {
            free(tmp);
            FreeStrArray(tmp->dcaps, tmp->dcapsNum - 1);
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:GetInfoArrFromJson failed for perms.", __func__);
            return ATRET_FAILED;
        }

        tmp->next = g_tokenListHead->next;
        g_tokenListHead->next = tmp;
    }
    return ATRET_SUCCESS;
}

static int32_t ParseTokenInfo(void)
{
    char *fileBuff = NULL;
    cJSON *record = NULL;
    int32_t ret;

    ret = GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff);
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

static int32_t CreateCfgFile(void)
{
    int32_t fd = open(TOKEN_ID_CFG_FILE_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd < 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:open failed.", __func__);
        return ATRET_FAILED;
    }
    close(fd);
    fd = -1;

    struct stat buf;
    if (stat(TOKEN_ID_CFG_DIR_PATH, &buf) != 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:stat folder path is invalid %d.",
                              __func__, errno);
        return ATRET_FAILED;
    }
    if (chown(TOKEN_ID_CFG_FILE_PATH, buf.st_uid, buf.st_gid) != 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:chown failed, errno is %d.", __func__, errno);
        return ATRET_FAILED;
    }

    return ATRET_SUCCESS;
}

static int32_t AtlibInit(void)
{
    g_tokenListHead = (NativeTokenList *)malloc(sizeof(NativeTokenList));
    if (g_tokenListHead == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:g_tokenListHead memory alloc failed.", __func__);
        return ATRET_FAILED;
    }
    g_tokenListHead->next = NULL;

    int32_t ret = ParseTokenInfo();
    if (ret != ATRET_SUCCESS) {
        free(g_tokenListHead);
        g_tokenListHead = NULL;
        return ret;
    }

    if (g_tokenListHead->next == NULL) {
        if (CreateCfgFile() != ATRET_SUCCESS) {
            return ATRET_FAILED;
        }
    }
    g_isNativeTokenInited = 1;

    return ATRET_SUCCESS;
}

static int GetRandomTokenId(uint32_t *randNum)
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

static int32_t IsTokenUniqueIdExist(uint32_t tokenUniqueId)
{
    NativeTokenList *tokenNode = g_tokenListHead->next;
    while (tokenNode != NULL) {
        AtInnerInfo *existToken = (AtInnerInfo *)&(tokenNode->tokenId);
        if (tokenUniqueId == existToken->tokenUniqueId) {
            return 1;
        }
        tokenNode = tokenNode->next;
    }
    return 0;
}

static NativeAtId CreateNativeTokenId(void)
{
    uint32_t rand;
    NativeAtId tokenId;
    int32_t ret;
    AtInnerInfo *innerId = (AtInnerInfo *)(&tokenId);
    int32_t retry = MAX_RETRY_TIMES;

    while (retry > 0) {
        ret = GetRandomTokenId(&rand);
        if (ret != ATRET_SUCCESS) {
            return INVALID_TOKEN_ID;
        }
        if (IsTokenUniqueIdExist(rand & (TOKEN_RANDOM_MASK)) == 0) {
            break;
        }
        retry--;
    }
    if (retry == 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:retry times is 0.", __func__);
        return INVALID_TOKEN_ID;
    }

    innerId->reserved = 0;
    innerId->tokenUniqueId = rand & (TOKEN_RANDOM_MASK);
    innerId->type = TOKEN_NATIVE_TYPE;
    innerId->version = 1;
    return tokenId;
}

static int32_t GetAplLevel(const char *aplStr)
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

static void WriteToFile(const cJSON *root)
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
    } while (0);

    cJSON_free(jsonStr);
    return;
}

static int32_t AddStrArrayInfo(cJSON *object, char * const strArray[], int strNum, const char *strKey)
{
    cJSON *strJsonArr = cJSON_CreateArray();
    if (strJsonArr == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:CreateArray failed, strKey :%s.", __func__, strKey);
        return ATRET_FAILED;
    }
    for (int32_t i = 0; i < strNum; i++) {
        cJSON *item =  cJSON_CreateString(strArray[i]);
        if (item == NULL || !cJSON_AddItemToArray(strJsonArr, item)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:AddItemToArray failed, strKey : %s.", __func__, strKey);
            cJSON_Delete(item);
            cJSON_Delete(strJsonArr);
            return ATRET_FAILED;
        }
    }
    if (!cJSON_AddItemToObject(object, strKey, strJsonArr)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:AddItemToObject failed, strKey : %s.", __func__, strKey);
        cJSON_Delete(strJsonArr);
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

    int ret = AddStrArrayInfo(object, curr->dcaps, curr->dcapsNum, DCAPS_KEY_NAME);
    if (ret != ATRET_SUCCESS) {
        cJSON_Delete(object);
    }

    ret = AddStrArrayInfo(object, curr->perms, curr->permsNum, PERMS_KEY_NAME);
    if (ret != ATRET_SUCCESS) {
        cJSON_Delete(object);
    }
    return object;
}

static void SaveTokenIdToCfg(const NativeTokenList *curr)
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
        cJSON_Delete(record);
        return;
    }
    cJSON_AddItemToArray(record, node);

    WriteToFile(record);
    cJSON_Delete(record);
    return;
}

static uint32_t CheckStrArray(const char **strArray, int32_t strNum, int maxNum, uint32_t maxInfoLen)
{
    if (((strArray == NULL) && (strNum != 0)) ||
        (strNum > maxNum) || (strNum < 0)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:strArray is null or strNum is invalid.", __func__);
        return ATRET_FAILED;
    }
    for (int32_t i = 0; i < strNum; i++) {
        if ((strArray[i] == NULL) || (strlen(strArray[i]) > maxInfoLen) || (strlen(strArray[i]) == 0)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:strArray[%d] length is invalid.", __func__, i);
            return ATRET_FAILED;
        }
    }
    return ATRET_SUCCESS;
}

static uint32_t CheckProcessInfo(NativeTokenInfoParams *tokenInfo, int32_t *aplRet)
{
    if ((tokenInfo->processName == NULL) || strlen(tokenInfo->processName) > MAX_PROCESS_NAME_LEN ||
        strlen(tokenInfo->processName) == 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:processName is invalid.", __func__);
        return ATRET_FAILED;
    }
    uint32_t retDcap = CheckStrArray(tokenInfo->dcaps, tokenInfo->dcapsNum, MAX_DCAPS_NUM, MAX_DCAP_LEN);
    if (retDcap != ATRET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:dcaps is invalid.", __func__);
        return ATRET_FAILED;
    }
    uint32_t retPerm = CheckStrArray(tokenInfo->perms, tokenInfo->permsNum, MAX_PERM_NUM, MAX_PERM_LEN);
    if (retPerm != ATRET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:perms is invalid.", __func__);
        return ATRET_FAILED;
    }

    int32_t apl = GetAplLevel(tokenInfo->aplStr);
    if (apl == 0) {
        return ATRET_FAILED;
    }
    *aplRet = apl;
    return ATRET_SUCCESS;
}

static uint32_t CreateStrArray(int num, const char **strArr, char **strArrRes)
{
    for (int32_t i = 0; i < num; i++) {
        strArrRes[i] = (char *)malloc(sizeof(char) * (strlen(strArr[i]) + 1));
        if (strArrRes[i] == NULL ||
            (strcpy_s(strArrRes[i], strlen(strArr[i]) + 1, strArr[i]) != EOK)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:copy strArr[%d] failed.", __func__, i);
            FreeStrArray(strArrRes, i);
            return ATRET_FAILED;
        }
    }
    return ATRET_SUCCESS;
}

static uint32_t AddNewTokenToListAndFile(NativeTokenInfoParams *tokenInfo, int32_t aplIn, NativeAtId *tokenId)
{
    NativeTokenList *tokenNode;
    NativeAtId id;

    id = CreateNativeTokenId();
    if (id == INVALID_TOKEN_ID) {
        return ATRET_FAILED;
    }

    tokenNode = (NativeTokenList *)malloc(sizeof(NativeTokenList));
    if (tokenNode == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:memory alloc failed.", __func__);
        return ATRET_FAILED;
    }
    tokenNode->tokenId = id;
    tokenNode->apl = aplIn;
    if (strcpy_s(tokenNode->processName, MAX_PROCESS_NAME_LEN + 1, tokenInfo->processName) != EOK) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:strcpy_s failed.", __func__);
        free(tokenNode);
        return ATRET_FAILED;
    }
    tokenNode->dcapsNum = tokenInfo->dcapsNum;
    tokenNode->permsNum = tokenInfo->permsNum;

    if (CreateStrArray(tokenInfo->dcapsNum, tokenInfo->dcaps, tokenNode->dcaps) != ATRET_SUCCESS) {
        free(tokenNode);
        return ATRET_FAILED;
    }
    if (CreateStrArray(tokenInfo->permsNum, tokenInfo->perms, tokenNode->perms) != ATRET_SUCCESS) {
        FreeStrArray(tokenNode->dcaps, tokenInfo->dcapsNum - 1);
        free(tokenNode);
        return ATRET_FAILED;
    }

    tokenNode->next = g_tokenListHead->next;
    g_tokenListHead->next = tokenNode;

    *tokenId = id;

    SaveTokenIdToCfg(tokenNode);
    return ATRET_SUCCESS;
}

static int32_t CompareTokenInfo(NativeTokenList *tokenNode, const char **dcapsIn, int32_t dcapNumIn, int32_t aplIn)
{
    if (tokenNode->apl != aplIn) {
        return 1;
    }
    if (tokenNode->dcapsNum != dcapNumIn) {
        return 1;
    }
    for (int32_t i = 0; i < dcapNumIn; i++) {
        if (strcmp(tokenNode->dcaps[i], dcapsIn[i]) != 0) {
            return 1;
        }
    }
    return 0;
}

static int32_t ComparePermsInfo(NativeTokenList *tokenNode, const char **permsIn, int32_t permsNumIn)
{
    if (tokenNode->permsNum != permsNumIn) {
        return 1;
    }
    for (int32_t i = 0; i < permsNumIn; i++) {
        if (strcmp(tokenNode->perms[i], permsIn[i]) != 0) {
            return 1;
        }
    }
    return 0;
}

static uint32_t UpdateStrArrayInList(char *strArr[], int *strNum,
    const char **strArrNew, int strNumNew)
{
    for (int32_t i = 0; i < *strNum; i++) {
        free(strArr[i]);
        strArr[i] = NULL;
    }

    *strNum = strNumNew;
    for (int32_t i = 0; i < strNumNew; i++) {
        int32_t len = strlen(strArrNew[i]) + 1;
        strArr[i] = (char *)malloc(sizeof(char) * len);
        if (strArr[i] == NULL || (strcpy_s(strArr[i], len, strArrNew[i]) != EOK)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:copy strArr[%d] failed.", __func__, i);
            FreeStrArray(strArr, i);
            return ATRET_FAILED;
        }
    }
    return ATRET_SUCCESS;
}

static uint32_t UpdateTokenInfoInList(NativeTokenList *tokenNode, NativeTokenInfoParams *tokenInfo)
{
    tokenNode->apl = GetAplLevel(tokenInfo->aplStr);

    uint32_t ret = UpdateStrArrayInList(tokenNode->dcaps, &(tokenNode->dcapsNum),
        tokenInfo->dcaps, tokenInfo->dcapsNum);
    if (ret != ATRET_SUCCESS) {
        return ret;
    }
    ret = UpdateStrArrayInList(tokenNode->perms, &(tokenNode->permsNum),
        tokenInfo->perms, tokenInfo->permsNum);
    if (ret != ATRET_SUCCESS) {
        FreeStrArray(tokenNode->dcaps, tokenNode->dcapsNum);
    }
    return ret;
}

static uint32_t UpdateStrArrayType(char * const strArr[], int strNum, const char *strKey, cJSON *record)
{
    cJSON *strArrJson = cJSON_CreateArray();
    if (strArrJson == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_CreateArray failed.", __func__);
        return ATRET_FAILED;
    }
    for (int32_t i = 0; i < strNum; i++) {
        cJSON *item =  cJSON_CreateString(strArr[i]);
        if (item == NULL) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_CreateString failed.", __func__);
            cJSON_Delete(strArrJson);
            return ATRET_FAILED;
        }
        if (!cJSON_AddItemToArray(strArrJson, item)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_AddItemToArray failed.", __func__);
            cJSON_Delete(item);
            cJSON_Delete(strArrJson);
            return ATRET_FAILED;
        }
    }
    if (cJSON_GetObjectItem(record, strKey) != NULL) {
        if (!cJSON_ReplaceItemInObject(record, strKey, strArrJson)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_ReplaceItemInObject failed.", __func__);
            cJSON_Delete(strArrJson);
            return ATRET_FAILED;
        }
    } else {
        if (!cJSON_AddItemToObject(record, strKey, strArrJson)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_AddItemToObject failed.", __func__);
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
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:APL update failed.", __func__);
        return ATRET_FAILED;
    }

    uint32_t ret = UpdateStrArrayType(tokenNode->dcaps, tokenNode->dcapsNum, DCAPS_KEY_NAME, record);
    if (ret != ATRET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:dcaps update failed.", __func__);
        return ATRET_FAILED;
    }

    ret = UpdateStrArrayType(tokenNode->perms, tokenNode->permsNum, PERMS_KEY_NAME, record);
    if (ret != ATRET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:perms update failed.", __func__);
        return ATRET_FAILED;
    }
    return ATRET_SUCCESS;
}

static uint32_t UpdateGoalItemFromRecord(const NativeTokenList *tokenNode, cJSON *record)
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

static uint32_t UpdateInfoInCfgFile(NativeTokenList *tokenNode)
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

uint64_t GetAccessTokenId(NativeTokenInfoParams *tokenInfo)
{
    NativeAtId tokenId = 0;
    uint64_t result = 0;
    int32_t apl;
    NativeAtIdEx *atPoint = (NativeAtIdEx *)(&result);

    if ((g_isNativeTokenInited == 0) && (AtlibInit() != ATRET_SUCCESS)) {
        return INVALID_TOKEN_ID;
    }

    uint32_t ret = CheckProcessInfo(tokenInfo, &apl);
    if (ret != ATRET_SUCCESS) {
        return INVALID_TOKEN_ID;
    }

    NativeTokenList *tokenNode = g_tokenListHead->next;
    while (tokenNode != NULL) {
        if (strcmp(tokenNode->processName, tokenInfo->processName) == 0) {
            tokenId = tokenNode->tokenId;
            break;
        }
        tokenNode = tokenNode->next;
    }

    if (tokenNode == NULL) {
        ret = AddNewTokenToListAndFile(tokenInfo, apl, &tokenId);
    } else {
        int32_t needTokenUpdate = CompareTokenInfo(tokenNode, tokenInfo->dcaps, tokenInfo->dcapsNum, apl);
        int32_t needPermUpdate = ComparePermsInfo(tokenNode, tokenInfo->perms, tokenInfo->permsNum);
        if ((needTokenUpdate != 0) || (needPermUpdate != 0)) {
            ret = UpdateTokenInfoInList(tokenNode, tokenInfo);
            ret |= UpdateInfoInCfgFile(tokenNode);
        }
    }
    if (ret != ATRET_SUCCESS) {
        return INVALID_TOKEN_ID;
    }

    atPoint->tokenId = tokenId;
    atPoint->tokenAttr = 0;
    return result;
}