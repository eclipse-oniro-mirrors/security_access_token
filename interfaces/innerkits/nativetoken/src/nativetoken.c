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

#ifdef WITH_SELINUX
#include <policycoreutils.h>
#endif // WITH_SELINUX

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "securec.h"
#include "nativetoken_json_oper.h"
#include "nativetoken_kit.h"
#include "nativetoken_log.h"


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
        AT_LOG_ERROR("[ATLIB-%s]:invalid filePath.", __func__);
        return ATRET_FAILED;
    }

    if (stat(filePath, &fileStat) != 0) {
        AT_LOG_ERROR("[ATLIB-%s]:stat file failed.", __func__);
        return ATRET_FAILED;
    }

    if (fileStat.st_size == 0) {
        *retBuff = NULL;
        return ATRET_SUCCESS;
    }

    if (fileStat.st_size > MAX_JSON_FILE_LEN) {
        AT_LOG_ERROR("[ATLIB-%s]:stat file size is invalid.", __func__);
        return ATRET_FAILED;
    }

    size_t fileSize = (unsigned)fileStat.st_size;

    FILE *cfgFd = fopen(filePath, "r");
    if (cfgFd == NULL) {
        AT_LOG_ERROR("[ATLIB-%s]:fopen file failed.", __func__);
        return ATRET_FAILED;
    }

    char *buff = (char *)malloc((size_t)(fileSize + 1));
    if (buff == NULL) {
        AT_LOG_ERROR("[ATLIB-%s]:memory alloc failed.", __func__);
        fclose(cfgFd);
        return ATRET_FAILED;
    }

    if (fread(buff, fileSize, 1, cfgFd) != 1) {
        AT_LOG_ERROR("[ATLIB-%s]:fread failed.", __func__);
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

static void StrAttrSet(StrArrayAttr *attr, uint32_t maxStrLen, int32_t maxStrNum, const char *strKey)
{
    attr->maxStrLen = maxStrLen;
    attr->maxStrNum = maxStrNum;
    attr->strKey = strKey;
}

static int32_t GetNativeTokenFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode)
{
    uint32_t ret;
    StrArrayAttr attr;

    ret = GetProcessNameFromJson(cjsonItem, tokenNode);
    ret |= GetTokenIdFromJson(cjsonItem, tokenNode);
    ret |= GetAplFromJson(cjsonItem, tokenNode);

    StrAttrSet(&attr, MAX_DCAP_LEN, MAX_DCAPS_NUM, DCAPS_KEY_NAME);
    ret |= GetInfoArrFromJson(cjsonItem, tokenNode->dcaps, &(tokenNode->dcapsNum), &attr);
    if (ret != ATRET_SUCCESS) {
        AT_LOG_ERROR("[ATLIB-%s]:GetInfoArrFromJson failed for dcaps.", __func__);
        return ATRET_FAILED;
    }

    StrAttrSet(&attr, MAX_PERM_LEN, MAX_PERM_NUM, PERMS_KEY_NAME);
    ret = GetInfoArrFromJson(cjsonItem, tokenNode->perms, &(tokenNode->permsNum), &attr);
    if (ret != ATRET_SUCCESS) {
        FreeStrArray(tokenNode->dcaps, tokenNode->dcapsNum - 1);
        AT_LOG_ERROR("[ATLIB-%s]:GetInfoArrFromJson failed for perms.", __func__);
        return ATRET_FAILED;
    }

    StrAttrSet(&attr, MAX_PERM_LEN, MAX_PERM_NUM, ACLS_KEY_NAME);
    ret = GetInfoArrFromJson(cjsonItem, tokenNode->acls, &(tokenNode->aclsNum), &attr);
    if (ret != ATRET_SUCCESS) {
        FreeStrArray(tokenNode->dcaps, tokenNode->dcapsNum - 1);
        FreeStrArray(tokenNode->perms, tokenNode->permsNum - 1);
        AT_LOG_ERROR("[ATLIB-%s]:GetInfoArrFromJson failed for acls.", __func__);
        return ATRET_FAILED;
    }
    return ATRET_SUCCESS;
}

static int32_t GetTokenList(const cJSON *object)
{
    NativeTokenList *tmp = NULL;

    if (object == NULL) {
        AT_LOG_ERROR("[ATLIB-%s]:object is null.", __func__);
        return ATRET_FAILED;
    }
    int32_t arraySize = cJSON_GetArraySize(object);

    for (int32_t i = 0; i < arraySize; i++) {
        tmp = (NativeTokenList *)malloc(sizeof(NativeTokenList));
        if (tmp == NULL) {
            AT_LOG_ERROR("[ATLIB-%s]:memory alloc failed.", __func__);
            return ATRET_FAILED;
        }
        cJSON *cjsonItem = cJSON_GetArrayItem(object, i);
        if (cjsonItem == NULL) {
            free(tmp);
            AT_LOG_ERROR("[ATLIB-%s]:cJSON_GetArrayItem failed.", __func__);
            return ATRET_FAILED;
        }
        if (GetNativeTokenFromJson(cjsonItem, tmp) != ATRET_SUCCESS) {
            free(tmp);
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
        AT_LOG_ERROR("[ATLIB-%s]:open failed.", __func__);
        return ATRET_FAILED;
    }

#ifdef WITH_SELINUX
    Restorecon(TOKEN_ID_CFG_FILE_PATH);
#endif // WITH_SELINUX

    close(fd);
    fd = -1;

    struct stat buf;
    if (stat(TOKEN_ID_CFG_DIR_PATH, &buf) != 0) {
        AT_LOG_ERROR("[ATLIB-%s]:stat folder path is invalid %d.",
            __func__, errno);
        return ATRET_FAILED;
    }
    if (chown(TOKEN_ID_CFG_FILE_PATH, buf.st_uid, buf.st_gid) != 0) {
        AT_LOG_ERROR("[ATLIB-%s]:chown failed, errno is %d.", __func__, errno);
        return ATRET_FAILED;
    }

    return ATRET_SUCCESS;
}

int32_t AtlibInit(void)
{
    g_tokenListHead = (NativeTokenList *)malloc(sizeof(NativeTokenList));
    if (g_tokenListHead == NULL) {
        AT_LOG_ERROR("[ATLIB-%s]:g_tokenListHead memory alloc failed.", __func__);
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

static int32_t GetRandomTokenId(uint32_t *randNum)
{
    uint32_t random;
    ssize_t len;
    int32_t fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return ATRET_FAILED;
    }
    len = read(fd, &random, sizeof(random));
    (void)close(fd);

    if (len != sizeof(random)) {
        AT_LOG_ERROR("[ATLIB-%s]:read failed.", __func__);
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

static NativeAtId CreateNativeTokenId(const char *processName)
{
    uint32_t rand;
    NativeAtId tokenId;
    AtInnerInfo *innerId = (AtInnerInfo *)(&tokenId);
    int32_t retry = MAX_RETRY_TIMES;

    while (retry > 0) {
        if (GetRandomTokenId(&rand) != ATRET_SUCCESS) {
            return INVALID_TOKEN_ID;
        }
        if (IsTokenUniqueIdExist(rand & (TOKEN_RANDOM_MASK)) == 0) {
            break;
        }
        retry--;
    }
    if (retry == 0) {
        AT_LOG_ERROR("[ATLIB-%s]:retry times is 0.", __func__);
        return INVALID_TOKEN_ID;
    }

    innerId->reserved = 0;
    innerId->tokenUniqueId = rand & (TOKEN_RANDOM_MASK);
    innerId->version = 1;

    if (strcmp(processName, HDC_PROCESS_NAME) == 0) {
        innerId->type = TOKEN_SHELL_TYPE;
    } else {
        innerId->type = TOKEN_NATIVE_TYPE;
    }

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
    AT_LOG_ERROR("[ATLIB-%s]:aplStr is invalid.", __func__);
    return 0;
}

static void WriteToFile(const cJSON *root)
{
    char *jsonStr = NULL;
    jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == NULL) {
        AT_LOG_ERROR("[ATLIB-%s]:cJSON_PrintUnformatted failed.", __func__);
        return;
    }

    do {
        int32_t fd = open(TOKEN_ID_CFG_FILE_PATH, O_RDWR | O_CREAT | O_TRUNC,
                          S_IRUSR | S_IWUSR | S_IRGRP);
        if (fd < 0) {
            AT_LOG_ERROR("[ATLIB-%s]:open failed.", __func__);
            break;
        }
        size_t strLen = strlen(jsonStr);
        ssize_t writtenLen = write(fd, (void *)jsonStr, (size_t)strLen);
        close(fd);
        if (writtenLen < 0 || (size_t)writtenLen != strLen) {
            AT_LOG_ERROR("[ATLIB-%s]:write failed, writtenLen is %zu.", __func__, writtenLen);
            break;
        }
    } while (0);

    cJSON_free(jsonStr);
    return;
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
        AT_LOG_ERROR("[ATLIB-%s]:get record failed.", __func__);
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

static uint32_t CheckStrArray(const char **strArray, int32_t strNum, int32_t maxNum, uint32_t maxInfoLen)
{
    if (((strArray == NULL) && (strNum != 0)) ||
        (strNum > maxNum) || (strNum < 0)) {
        AT_LOG_ERROR("[ATLIB-%s]:strArray is null or strNum is invalid.", __func__);
        return ATRET_FAILED;
    }
    for (int32_t i = 0; i < strNum; i++) {
        if ((strArray[i] == NULL) || (strlen(strArray[i]) > maxInfoLen) || (strlen(strArray[i]) == 0)) {
            AT_LOG_ERROR("[ATLIB-%s]:strArray[%d] length is invalid.", __func__, i);
            return ATRET_FAILED;
        }
    }
    return ATRET_SUCCESS;
}

static uint32_t CheckProcessInfo(NativeTokenInfoParams *tokenInfo, int32_t *aplRet)
{
    if ((tokenInfo->processName == NULL) || strlen(tokenInfo->processName) > MAX_PROCESS_NAME_LEN ||
        strlen(tokenInfo->processName) == 0) {
        AT_LOG_ERROR("[ATLIB-%s]:processName is invalid.", __func__);
        return ATRET_FAILED;
    }
    uint32_t retDcap = CheckStrArray(tokenInfo->dcaps, tokenInfo->dcapsNum, MAX_DCAPS_NUM, MAX_DCAP_LEN);
    if (retDcap != ATRET_SUCCESS) {
        AT_LOG_ERROR("[ATLIB-%s]:dcaps is invalid.", __func__);
        return ATRET_FAILED;
    }
    uint32_t retPerm = CheckStrArray(tokenInfo->perms, tokenInfo->permsNum, MAX_PERM_NUM, MAX_PERM_LEN);
    if (retPerm != ATRET_SUCCESS) {
        AT_LOG_ERROR("[ATLIB-%s]:perms is invalid.", __func__);
        return ATRET_FAILED;
    }

    uint32_t retAcl = CheckStrArray(tokenInfo->acls, tokenInfo->aclsNum, MAX_PERM_NUM, MAX_PERM_LEN);
    if (retAcl != ATRET_SUCCESS) {
        AT_LOG_ERROR("[ATLIB-%s]:acls is invalid.", __func__);
        return ATRET_FAILED;
    }

    if (tokenInfo->aclsNum > tokenInfo->permsNum) {
        AT_LOG_ERROR("[ATLIB-%s]:aclsNum is invalid.", __func__);
        return ATRET_FAILED;
    }
    int32_t apl = GetAplLevel(tokenInfo->aplStr);
    if (apl == 0) {
        return ATRET_FAILED;
    }
    *aplRet = apl;
    return ATRET_SUCCESS;
}

static uint32_t CreateStrArray(int32_t num, const char **strArr, char **strArrRes)
{
    for (int32_t i = 0; i < num; i++) {
        strArrRes[i] = (char *)malloc(sizeof(char) * (strlen(strArr[i]) + 1));
        if (strArrRes[i] == NULL ||
            (strcpy_s(strArrRes[i], strlen(strArr[i]) + 1, strArr[i]) != EOK)) {
            AT_LOG_ERROR("[ATLIB-%s]:copy strArr[%d] failed.", __func__, i);
            FreeStrArray(strArrRes, i);
            return ATRET_FAILED;
        }
    }
    return ATRET_SUCCESS;
}

static uint32_t AddNewTokenToListAndFile(const NativeTokenInfoParams *tokenInfo,
    int32_t aplIn, NativeAtId *tokenId)
{
    NativeTokenList *tokenNode;
    NativeAtId id;

    id = CreateNativeTokenId(tokenInfo->processName);
    if (id == INVALID_TOKEN_ID) {
        return ATRET_FAILED;
    }

    tokenNode = (NativeTokenList *)malloc(sizeof(NativeTokenList));
    if (tokenNode == NULL) {
        AT_LOG_ERROR("[ATLIB-%s]:memory alloc failed.", __func__);
        return ATRET_FAILED;
    }
    tokenNode->tokenId = id;
    tokenNode->apl = aplIn;
    if (strcpy_s(tokenNode->processName, MAX_PROCESS_NAME_LEN + 1, tokenInfo->processName) != EOK) {
        AT_LOG_ERROR("[ATLIB-%s]:strcpy_s failed.", __func__);
        free(tokenNode);
        return ATRET_FAILED;
    }
    tokenNode->dcapsNum = tokenInfo->dcapsNum;
    tokenNode->permsNum = tokenInfo->permsNum;
    tokenNode->aclsNum = tokenInfo->aclsNum;

    if (CreateStrArray(tokenInfo->dcapsNum, tokenInfo->dcaps, tokenNode->dcaps) != ATRET_SUCCESS) {
        free(tokenNode);
        return ATRET_FAILED;
    }
    if (CreateStrArray(tokenInfo->permsNum, tokenInfo->perms, tokenNode->perms) != ATRET_SUCCESS) {
        FreeStrArray(tokenNode->dcaps, tokenInfo->dcapsNum - 1);
        free(tokenNode);
        return ATRET_FAILED;
    }
    if (CreateStrArray(tokenInfo->aclsNum, tokenInfo->acls, tokenNode->acls) != ATRET_SUCCESS) {
        FreeStrArray(tokenNode->dcaps, tokenInfo->dcapsNum - 1);
        FreeStrArray(tokenNode->perms, tokenInfo->permsNum - 1);
        free(tokenNode);
        return ATRET_FAILED;
    }

    tokenNode->next = g_tokenListHead->next;
    g_tokenListHead->next = tokenNode;

    *tokenId = id;

    SaveTokenIdToCfg(tokenNode);
    return ATRET_SUCCESS;
}

static int32_t CompareTokenInfo(const NativeTokenList *tokenNode,
                                const char **dcapsIn, int32_t dcapNumIn, int32_t aplIn)
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

static int32_t ComparePermsInfo(const NativeTokenList *tokenNode,
                                const char **permsIn, int32_t permsNumIn)
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

static uint32_t UpdateStrArrayInList(char *strArr[], int32_t *strNum,
    const char **strArrNew, int32_t strNumNew)
{
    for (int32_t i = 0; i < *strNum; i++) {
        free(strArr[i]);
        strArr[i] = NULL;
    }

    *strNum = strNumNew;
    for (int32_t i = 0; i < strNumNew; i++) {
        size_t len = strlen(strArrNew[i]) + 1;
        strArr[i] = (char *)malloc(sizeof(char) * len);
        if (strArr[i] == NULL || (strcpy_s(strArr[i], len, strArrNew[i]) != EOK)) {
            AT_LOG_ERROR("[ATLIB-%s]:copy strArr[%d] failed.", __func__, i);
            FreeStrArray(strArr, i);
            return ATRET_FAILED;
        }
    }
    return ATRET_SUCCESS;
}

static uint32_t UpdateTokenInfoInList(NativeTokenList *tokenNode,
                                      const NativeTokenInfoParams *tokenInfo)
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
        FreeStrArray(tokenNode->dcaps, tokenNode->dcapsNum - 1);
    }
    ret = UpdateStrArrayInList(tokenNode->acls, &(tokenNode->aclsNum),
        tokenInfo->acls, tokenInfo->aclsNum);
    if (ret != ATRET_SUCCESS) {
        FreeStrArray(tokenNode->dcaps, tokenNode->dcapsNum - 1);
        FreeStrArray(tokenNode->perms, tokenNode->permsNum - 1);
    }
    return ret;
}

static uint32_t UpdateInfoInCfgFile(const NativeTokenList *tokenNode)
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
        AT_LOG_ERROR("[ATLIB-%s]:get record failed.", __func__);
        return ATRET_FAILED;
    }

    ret = UpdateGoalItemFromRecord(tokenNode, record);
    if (ret != ATRET_SUCCESS) {
        AT_LOG_ERROR("[ATLIB-%s]:UpdateGoalItemFromRecord failed.", __func__);
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
