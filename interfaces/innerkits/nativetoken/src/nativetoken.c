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
#include "accesstoken_klog.h"
#include "hisysevent_common.h"
#include "nativetoken_hisysevent.h"
#include "nativetoken_json_oper.h"
#include "nativetoken_kit.h"
#include "securec.h"

NativeTokenList *g_tokenListHead;
int32_t g_isNativeTokenInited = 0;
const uint64_t g_nativeFdTag = 0xD005A01;

#define BREAK_IF_TRUE(cond) \
    if (cond) { \
        break; \
    }

uint32_t GetFileBuff(const char *cfg, char **retBuff)
{
    struct stat fileStat;

    char filePath[PATH_MAX_LEN + 1] = {0};
    if (realpath(cfg, filePath) == NULL) {
        if (errno == ENOENT) {
            /* file doesn't exist */
            *retBuff = NULL;
            return ATRET_SUCCESS;
        }
        LOGC("Invalid filePath, errno=%d.", errno);
        return GET_FILE_BUFF_FAILED;
    }

    if (stat(filePath, &fileStat) != 0) {
        LOGC("Failed to stat file, errno=%d.", errno);
        return GET_FILE_BUFF_FAILED;
    }

    if (fileStat.st_size == 0) {
        LOGI("Empty file");
        *retBuff = NULL;
        return ATRET_SUCCESS;
    }

    if (fileStat.st_size > MAX_JSON_FILE_LEN) {
        LOGC("Invalid size.");
        return GET_FILE_BUFF_FAILED;
    }

    size_t fileSize = (unsigned)fileStat.st_size;

    FILE *cfgFd = fopen(filePath, "r");
    if (cfgFd == NULL) {
        LOGC("Failed to fopen file, errno=%d.", errno);
        return GET_FILE_BUFF_FAILED;
    }

    char *buff = (char *)malloc((size_t)(fileSize + 1));
    if (buff == NULL) {
        LOGC("Failed to alloc memory for buffer.");
        (void)fclose(cfgFd);
        return GET_FILE_BUFF_FAILED;
    }
    size_t readSize = fread(buff, fileSize, 1, cfgFd);
    if (readSize != 1) {
        LOGC("Failed to fread, readSize=%zu, errno=%d.", readSize, errno);
        free(buff);
        buff = NULL;
        (void)fclose(cfgFd);
        return GET_FILE_BUFF_FAILED;
    }
    buff[fileSize] = '\0';
    *retBuff = buff;
    (void)fclose(cfgFd);
    return ATRET_SUCCESS;
}

static void StrAttrSet(StrArrayAttr *attr, uint32_t maxStrLen, int32_t maxStrNum, const char *strKey)
{
    attr->maxStrLen = maxStrLen;
    attr->maxStrNum = maxStrNum;
    attr->strKey = strKey;
}

static uint32_t GetNativeTokenFromJson(cJSON *cjsonItem, NativeTokenList *tokenNode)
{
    uint32_t ret;
    StrArrayAttr attr;

    ret = GetProcessNameFromJson(cjsonItem, tokenNode);
    if (ret != ATRET_SUCCESS) {
        LOGC("Failed to GetProcessNameFromJson.");
        return ATRET_FAILED;
    }
    ret = GetTokenIdFromJson(cjsonItem, tokenNode);
    if (ret != ATRET_SUCCESS) {
        LOGC("Failed to GetTokenIdFromJson.");
        return ATRET_FAILED;
    }
    ret = GetAplFromJson(cjsonItem, tokenNode);
    if (ret != ATRET_SUCCESS) {
        LOGC("Failed to GetAplFromJson.");
        return ATRET_FAILED;
    }

    StrAttrSet(&attr, MAX_DCAP_LEN, MAX_DCAPS_NUM, DCAPS_KEY_NAME);
    ret = GetInfoArrFromJson(cjsonItem, &tokenNode->dcaps, &(tokenNode->dcapsNum), &attr);
    if (ret != ATRET_SUCCESS) {
        LOGC("Failed to GetInfoArrFromJson for dcaps.");
        return ATRET_FAILED;
    }

    StrAttrSet(&attr, MAX_PERM_LEN, MAX_PERM_NUM, PERMS_KEY_NAME);
    ret = GetInfoArrFromJson(cjsonItem, &tokenNode->perms, &(tokenNode->permsNum), &attr);
    if (ret != ATRET_SUCCESS) {
        FreeStrArray(&tokenNode->dcaps, tokenNode->dcapsNum - 1);
        LOGC("Failed to GetInfoArrFromJsonfor perms.");
        return ATRET_FAILED;
    }

    StrAttrSet(&attr, MAX_PERM_LEN, MAX_PERM_NUM, ACLS_KEY_NAME);
    ret = GetInfoArrFromJson(cjsonItem, &tokenNode->acls, &(tokenNode->aclsNum), &attr);
    if (ret != ATRET_SUCCESS) {
        FreeStrArray(&tokenNode->dcaps, tokenNode->dcapsNum - 1);
        FreeStrArray(&tokenNode->perms, tokenNode->permsNum - 1);
        LOGC("Failed to GetInfoArrFromJsonfor acls.");
        return ATRET_FAILED;
    }
    return ATRET_SUCCESS;
}

static void FreeTokenNode(NativeTokenList **node)
{
    if (node == NULL || *node == NULL) {
        return;
    }
    FreeStrArray(&(*node)->dcaps, (*node)->dcapsNum - 1);
    FreeStrArray(&(*node)->perms, (*node)->permsNum - 1);
    FreeStrArray(&(*node)->perms, (*node)->permsNum - 1);
    free(*node);
    *node = NULL;
}

static void RemoveNodeFromList(NativeTokenList **node)
{
    if (node == NULL || *node == NULL || g_tokenListHead == NULL) {
        return;
    }
    NativeTokenList *tmp = g_tokenListHead;
    while (tmp != NULL) {
        if (tmp->next == *node) {
            tmp->next = (*node)->next;
            FreeTokenNode(node);
            return;
        }
        tmp = tmp->next;
    }
}

static void FreeTokenList(void)
{
    if (g_tokenListHead == NULL) {
        return;
    }
    NativeTokenList *tmp = g_tokenListHead->next;
    while (tmp != NULL) {
        NativeTokenList *toFreeNode = tmp;
        tmp = tmp->next;
        FreeTokenNode(&toFreeNode);
    }
    g_tokenListHead->next = NULL;
}

static uint32_t GetTokenList(const cJSON *object)
{
    NativeTokenList *tmp = NULL;

    if (object == NULL) {
        LOGC("Oobject is null.");
        return GET_TOKEN_LIST_FAILED;
    }
    int32_t arraySize = cJSON_GetArraySize(object);
    if (arraySize <= 0) {
        LOGC("Empty array.");
        return GET_TOKEN_LIST_FAILED;
    }

    for (int32_t i = 0; i < arraySize; i++) {
        tmp = (NativeTokenList *)malloc(sizeof(NativeTokenList));
        if (tmp == NULL) {
            LOGC("Failed to alloc memory for node.");
            FreeTokenList();
            return GET_TOKEN_LIST_FAILED;
        }
        cJSON *cjsonItem = cJSON_GetArrayItem(object, i);
        if (cjsonItem == NULL) {
            free(tmp);
            FreeTokenList();
            LOGC("Failed to cJSON_GetArrayItem.");
            return GET_TOKEN_LIST_FAILED;
        }
        if (GetNativeTokenFromJson(cjsonItem, tmp) != ATRET_SUCCESS) {
            free(tmp);
            FreeTokenList();
            LOGC("Failed to GetNativeTokenFromJson.");
            return GET_TOKEN_LIST_FAILED;
        }

        tmp->next = g_tokenListHead->next;
        g_tokenListHead->next = tmp;
    }
    return ATRET_SUCCESS;
}

static uint32_t ParseTokenInfo(void)
{
    char *fileBuff = NULL;
    cJSON *record = NULL;
    uint32_t ret;

    ret = GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff);
    if (ret != ATRET_SUCCESS) {
        LOGC("Failed to read nativetoken.json to buffer, ret=%d.", ret);
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

static uint32_t ClearOrCreateCfgFile(void)
{
    int32_t fd = open(TOKEN_ID_CFG_FILE_PATH, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd < 0) {
        LOGC("Failed to open file, errno=%d.", errno);
        return CLEAR_CREATE_FILE_FAILED;
    }
    fdsan_exchange_owner_tag(fd, 0, g_nativeFdTag);

#ifdef WITH_SELINUX
    Restorecon(TOKEN_ID_CFG_FILE_PATH);
#endif // WITH_SELINUX

    (void)fdsan_close_with_tag(fd, g_nativeFdTag);
    fd = -1;

    struct stat buf;
    if (stat(TOKEN_ID_CFG_DIR_PATH, &buf) != 0) {
        LOGC("Failed to stat file, errno=%d.", errno);
        return CLEAR_CREATE_FILE_FAILED;
    }
    if (chown(TOKEN_ID_CFG_FILE_PATH, buf.st_uid, buf.st_gid) != 0) {
        LOGC("Failed to chown file, errno=%d.", errno);
        return CLEAR_CREATE_FILE_FAILED;
    }

    return ATRET_SUCCESS;
}

uint32_t AtlibInit(void)
{
    g_tokenListHead = (NativeTokenList *)malloc(sizeof(NativeTokenList));
    if (g_tokenListHead == NULL) {
        LOGC("Faile to alloc memory for g_tokenListHead.");
        return MALLOC_FAILED;
    }
    g_tokenListHead->next = NULL;
    int32_t isClearOrCreate = 0;

    int32_t ret = ParseTokenInfo();
    if (ret != ATRET_SUCCESS) {
        ReportNativeTokenExceptionEvent(NATIVE_TOKEN_INIT, ret, GetThreadErrorMsg());
        ClearThreadErrorMsg();
        if (g_tokenListHead->next != NULL) {
            FreeTokenList();
        }
        ret = ClearOrCreateCfgFile();
        if (ret != ATRET_SUCCESS) {
            LOGC("Failed to ClearOrCreateCfgFile.");
            free(g_tokenListHead);
            g_tokenListHead = NULL;
            return ret;
        }
        isClearOrCreate = 1;
    }

    if (g_tokenListHead->next == NULL) {
        if (isClearOrCreate == 0) {
            ret = ClearOrCreateCfgFile();
            if (ret != ATRET_SUCCESS) {
                LOGC("Failed to ClearOrCreateCfgFile.");
                free(g_tokenListHead);
                g_tokenListHead = NULL;
                return ret;
            }
        }
    }
    g_isNativeTokenInited = 1;

    return ATRET_SUCCESS;
}

static uint32_t GetRandomTokenId(uint32_t *randNum)
{
    uint32_t random;
    ssize_t len;
    int32_t fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        LOGC("Failed to open urandom, errno=%d.", errno);
        return ATRET_FAILED;
    }
    fdsan_exchange_owner_tag(fd, 0, g_nativeFdTag);
    len = read(fd, &random, sizeof(random));
    (void)fdsan_close_with_tag(fd, g_nativeFdTag);

    if (len != sizeof(random)) {
        LOGC("Faild to read, len(%" PRIdPTR "", len);
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
            LOGC("Failed to GetRandomTokenId.");
            return INVALID_TOKEN_ID;
        }
        if (IsTokenUniqueIdExist(rand & (TOKEN_RANDOM_MASK)) == 0) {
            break;
        }
        retry--;
    }
    if (retry == 0) {
        LOGC("Failed to get unique tokenId.");
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
    LOGC("Invalid aplStr(%s).", aplStr);
    return 0;
}

static uint32_t WriteToFile(const cJSON *root)
{
    char *jsonStr = NULL;
    jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == NULL) {
        LOGC("Failed to cJSON_PrintUnformatted.");
        return ATRET_FAILED;
    }
    uint32_t ret = ATRET_SUCCESS;

    do {
        int32_t fd = open(TOKEN_ID_CFG_FILE_PATH, O_RDWR | O_CREAT | O_TRUNC,
                          S_IRUSR | S_IWUSR | S_IRGRP);
        if (fd < 0) {
            LOGC("Failed to open file, errno(%d).", errno);
            ret = ATRET_FAILED;
            break;
        }
        fdsan_exchange_owner_tag(fd, 0, g_nativeFdTag);
        size_t strLen = strlen(jsonStr);
        ssize_t writtenLen = write(fd, (void *)jsonStr, (size_t)strLen);
        if (fsync(fd) != 0) {
            LOGE("Failed to fsync, errno=%d.", errno);
        }
        (void)fdsan_close_with_tag(fd, g_nativeFdTag);
        if (writtenLen < 0 || (size_t)writtenLen != strLen) {
            LOGC("Failed to write, writtenLen=%zu.", writtenLen);
            ret = ATRET_FAILED;
            break;
        }
    } while (0);

    cJSON_free(jsonStr);
    return ret;
}

static uint32_t SaveTokenIdToCfg(const NativeTokenList *curr)
{
    char *fileBuff = NULL;
    cJSON *record = NULL;
    uint32_t ret;

    ret = GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff);
    if (ret != ATRET_SUCCESS) {
        LOGC("Failed to GetFileBuff, ret=%d.", ret);
        return ret;
    }

    if (fileBuff == NULL) {
        record = cJSON_CreateArray();
    } else {
        record = cJSON_Parse(fileBuff);
        free(fileBuff);
        fileBuff = NULL;
    }

    if (record == NULL) {
        LOGC("Failed to get record.");
        return SAVE_CONTENT_TO_CFG_FAILED;
    }

    cJSON *node = CreateNativeTokenJsonObject(curr);
    if (node == NULL) {
        LOGC("Failed to CreateNativeTokenJsonObject.");
        cJSON_Delete(record);
        return SAVE_CONTENT_TO_CFG_FAILED;
    }
    if (!cJSON_AddItemToArray(record, node)) {
        LOGC("Failed to cJSON_AddItemToArray.");
        cJSON_Delete(node);
        cJSON_Delete(record);
        return SAVE_CONTENT_TO_CFG_FAILED;
    }

    if (WriteToFile(record) != ATRET_SUCCESS) {
        LOGC("Failed to WriteToFile.");
        cJSON_Delete(record);
        return SAVE_CONTENT_TO_CFG_FAILED;
    }
    cJSON_Delete(record);
    return ATRET_SUCCESS;
}

static uint32_t CheckStrArray(const char **strArray, int32_t strNum, int32_t maxNum, uint32_t maxInfoLen)
{
    if ((strArray == NULL) && (strNum != 0)) {
        LOGC("StrArray is null but strNum != 0.");
        return ATRET_FAILED;
    }
    if ((strNum > maxNum) || (strNum < 0)) {
        LOGC("Invalid strNum(%d).", strNum);
        return ATRET_FAILED;
    }
    for (int32_t i = 0; i < strNum; i++) {
        if (strArray[i] == NULL) {
            LOGC("StrArray[%d] is null.", i);
            return ATRET_FAILED;
        }
        size_t len = strlen(strArray[i]);
        if ((len > maxInfoLen) || (len == 0)) {
            LOGC("Invalid strArray[%d] length(%zu).", i, len);
            return ATRET_FAILED;
        }
    }
    return ATRET_SUCCESS;
}

static uint32_t CheckProcessName(const char *processName)
{
    if (processName == NULL) {
        LOGC("ProcessName is null.");
        return ATRET_FAILED;
    }

    size_t len = strlen(processName);
    if (len > MAX_PROCESS_NAME_LEN || len == 0) {
        LOGC("Invalid processName, length(%zu).", len);
        return ATRET_FAILED;
    }
    return ATRET_SUCCESS;
}

static uint32_t CheckProcessInfo(NativeTokenInfoParams *tokenInfo, int32_t *aplRet)
{
    if (CheckProcessName(tokenInfo->processName) != ATRET_SUCCESS) {
        LOGC("Invalid processName.");
        return PROCESS_NAME_INVALID;
    }

    uint32_t retDcap = CheckStrArray(tokenInfo->dcaps, tokenInfo->dcapsNum, MAX_DCAPS_NUM, MAX_DCAP_LEN);
    if (retDcap != ATRET_SUCCESS) {
        LOGC("Invalid dcaps.");
        return DCAPS_INVALID;
    }
    uint32_t retPerm = CheckStrArray(tokenInfo->perms, tokenInfo->permsNum, MAX_PERM_NUM, MAX_PERM_LEN);
    if (retPerm != ATRET_SUCCESS) {
        LOGC("Invalid perms.");
        return PERMS_INVALID;
    }

    uint32_t retAcl = CheckStrArray(tokenInfo->acls, tokenInfo->aclsNum, MAX_PERM_NUM, MAX_PERM_LEN);
    if (retAcl != ATRET_SUCCESS) {
        LOGC("Invalid acls.");
        return ACLS_INVALID;
    }

    if (tokenInfo->aclsNum > tokenInfo->permsNum) {
        LOGC("Invalid aclsNum(%d) or permsNum(%d).", tokenInfo->aclsNum, tokenInfo->permsNum);
        return ACL_GREATER_THAN_PERMS;
    }
    int32_t apl = GetAplLevel(tokenInfo->aplStr);
    if (apl == 0) {
        LOGC("Invalid aplStr(%s).", tokenInfo->aplStr);
        return APL_INVALID;
    }
    *aplRet = apl;
    return ATRET_SUCCESS;
}

static uint32_t CreateStrArray(int32_t num, const char **strArr, char ***strArrRes)
{
    if (num > MAX_PERM_NUM) {
        LOGC("Oversize array, size=%d.", num);
        return ATRET_FAILED;
    }
    if (num == 0) {
        *strArrRes = NULL;
        return ATRET_SUCCESS;
    }
    *strArrRes = (char **)malloc(num * sizeof(char *));
    if (*strArrRes == NULL) {
        LOGC("Failed to alloc memory for strArray.");
        return ATRET_FAILED;
    }
    for (int32_t i = 0; i < num; i++) {
        size_t length = strlen(strArr[i]);
        (*strArrRes)[i] = (char *)malloc(sizeof(char) * length + 1);
        if ((*strArrRes)[i] == NULL ||
            (strcpy_s((*strArrRes)[i], length + 1, strArr[i]) != EOK)) {
            LOGC("Failed to copy strArr[%d].", i);
            FreeStrArray(strArrRes, i);
            return ATRET_FAILED;
        }
        (*strArrRes)[i][length] = '\0';
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
        LOGC("Failed to get new native tokenId.");
        return CREATE_NATIVETOKEN_ID_FAILED;
    }

    tokenNode = (NativeTokenList *)malloc(sizeof(NativeTokenList));
    if (tokenNode == NULL) {
        LOGC("Failed to alloc memory for tokenNode.");
        return MALLOC_FAILED;
    }
    tokenNode->tokenId = id;
    tokenNode->apl = aplIn;
    if (strcpy_s(tokenNode->processName, MAX_PROCESS_NAME_LEN + 1, tokenInfo->processName) != EOK) {
        LOGC("Failed to copy process name.");
        free(tokenNode);
        return STRCPY_FAILED;
    }
    tokenNode->dcapsNum = tokenInfo->dcapsNum;
    tokenNode->permsNum = tokenInfo->permsNum;
    tokenNode->aclsNum = tokenInfo->aclsNum;

    if (CreateStrArray(tokenInfo->dcapsNum, tokenInfo->dcaps, &tokenNode->dcaps) != ATRET_SUCCESS) {
        LOGC("Failed to CreateStrArray for dcaps.");
        free(tokenNode);
        return CREATE_ARRAY_FAILED;
    }
    if (CreateStrArray(tokenInfo->permsNum, tokenInfo->perms, &tokenNode->perms) != ATRET_SUCCESS) {
        LOGC("Failed to CreateStrArray for perms.");
        FreeStrArray(&tokenNode->dcaps, tokenInfo->dcapsNum - 1);
        free(tokenNode);
        return CREATE_ARRAY_FAILED;
    }
    if (CreateStrArray(tokenInfo->aclsNum, tokenInfo->acls, &tokenNode->acls) != ATRET_SUCCESS) {
        LOGC("Failed to CreateStrArray for acls.");
        FreeStrArray(&tokenNode->dcaps, tokenInfo->dcapsNum - 1);
        FreeStrArray(&tokenNode->perms, tokenInfo->permsNum - 1);
        free(tokenNode);
        return CREATE_ARRAY_FAILED;
    }

    tokenNode->next = g_tokenListHead->next;
    g_tokenListHead->next = tokenNode;

    *tokenId = id;

    return SaveTokenIdToCfg(tokenNode);
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

static uint32_t UpdateStrArrayInList(char **strArr[], int32_t *strNum,
    const char **strArrNew, int32_t strNumNew)
{
    if (strNum == NULL) {
        LOGC("StrNum is null.");
        return ATRET_FAILED;
    }

    FreeStrArray(strArr, *strNum - 1);

    *strNum = strNumNew;

    return CreateStrArray(strNumNew, strArrNew, strArr);
}

static uint32_t UpdateTokenInfoInList(NativeTokenList *tokenNode,
                                      const NativeTokenInfoParams *tokenInfo)
{
    tokenNode->apl = GetAplLevel(tokenInfo->aplStr);

    uint32_t ret = UpdateStrArrayInList(&tokenNode->dcaps, &(tokenNode->dcapsNum),
        tokenInfo->dcaps, tokenInfo->dcapsNum);
    if (ret != ATRET_SUCCESS) {
        LOGC("Failed to updateStrArray for dcaps.");
        return CREATE_ARRAY_FAILED;
    }
    ret = UpdateStrArrayInList(&tokenNode->perms, &(tokenNode->permsNum),
        tokenInfo->perms, tokenInfo->permsNum);
    if (ret != ATRET_SUCCESS) {
        LOGC("Failed to updateStrArray for perms.");
        FreeStrArray(&tokenNode->dcaps, tokenNode->dcapsNum - 1);
        return CREATE_ARRAY_FAILED;
    }
    ret = UpdateStrArrayInList(&tokenNode->acls, &(tokenNode->aclsNum),
        tokenInfo->acls, tokenInfo->aclsNum);
    if (ret != ATRET_SUCCESS) {
        LOGC("Failed to updateStrArray for acls.");
        FreeStrArray(&tokenNode->dcaps, tokenNode->dcapsNum - 1);
        FreeStrArray(&tokenNode->perms, tokenNode->permsNum - 1);
        return CREATE_ARRAY_FAILED;
    }
    return ret;
}

static uint32_t UpdateInfoInCfgFile(const NativeTokenList *tokenNode)
{
    cJSON *record = NULL;
    char *fileBuffer = NULL;
    uint32_t ret;
    ret = GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuffer);
    if (ret != ATRET_SUCCESS) {
        LOGC("Failed to GetFileBuff, ret=%d.", ret);
        return ret;
    }

    if (fileBuffer == NULL) {
        record = cJSON_CreateArray();
    } else {
        record = cJSON_Parse(fileBuffer);
        free(fileBuffer);
        fileBuffer = NULL;
    }

    if (record == NULL) {
        LOGC("Failed to get record.");
        return SAVE_CONTENT_TO_CFG_FAILED;
    }

    ret = UpdateGoalItemFromRecord(tokenNode, record);
    if (ret != ATRET_SUCCESS) {
        LOGC("Failed to UpdateGoalItemFromRecord.");
        cJSON_Delete(record);
        return SAVE_CONTENT_TO_CFG_FAILED;
    }

    if (WriteToFile(record) != ATRET_SUCCESS) {
        LOGC("Failed to WriteToFile.");
        cJSON_Delete(record);
        return SAVE_CONTENT_TO_CFG_FAILED;
    }
    cJSON_Delete(record);
    return ATRET_SUCCESS;
}


static uint32_t LockNativeTokenFile(int32_t *lockFileFd)
{
    int32_t fd = open(TOKEN_ID_CFG_FILE_LOCK_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd < 0) {
        LOGC("Failed to open native token file, errno=%d.", errno);
        return LOCK_FILE_FAILED;
    }
    fdsan_exchange_owner_tag(fd, 0, g_nativeFdTag);
#ifdef WITH_SELINUX
    Restorecon(TOKEN_ID_CFG_FILE_LOCK_PATH);
#endif // WITH_SELINUX
    struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0; // lock entire file
    int32_t ret = -1;
    for (int i = 0; i < MAX_RETRY_LOCK_TIMES; i++) {
        ret = fcntl(fd, F_SETLK, &lock);
        if (ret == -1) {
            LOGE("Failed to lock the file, try %d time, errno is %d.", i, errno);
            usleep(SLEEP_TIME);
        } else {
            break;
        }
    }
    if (ret == -1) {
        LOGC("Failed to lock the file, errno=%d.", errno);
        (void)fdsan_close_with_tag(fd, g_nativeFdTag);
        return LOCK_FILE_FAILED;
    }
    *lockFileFd = fd;
    return ATRET_SUCCESS;
}

static void UnlockNativeTokenFile(int32_t lockFileFd)
{
    if (lockFileFd < 0) {
        LOGE("Invalid fd.");
        return;
    }
    struct flock lock;
    lock.l_type = F_UNLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;

    if (fcntl(lockFileFd, F_SETLK, &lock) == -1) {
        LOGE("Failed to unlock file, errno=%d.", errno);
    }
    (void)fdsan_close_with_tag(lockFileFd, g_nativeFdTag);
}

static uint32_t UpdateNewTokenToListAndFile(NativeTokenInfoParams *tokenInfo, NativeTokenList *tokenNode, int32_t apl)
{
    uint32_t ret = ATRET_SUCCESS;
    int32_t needTokenUpdate = CompareTokenInfo(tokenNode, tokenInfo->dcaps, tokenInfo->dcapsNum, apl);
    int32_t needPermUpdate = ComparePermsInfo(tokenNode, tokenInfo->perms, tokenInfo->permsNum);
    if ((needTokenUpdate != 0) || (needPermUpdate != 0)) {
        ret = UpdateTokenInfoInList(tokenNode, tokenInfo);
        if (ret != ATRET_SUCCESS) {
            LOGC("Failed to UpdateTokenInfoInList, ret=%u.", ret);
            RemoveNodeFromList(&tokenNode);
            ReportNativeTokenExceptionEvent(UPDATE_NODE, ret, GetThreadErrorMsg());
            return ret;
        }
        ret = UpdateInfoInCfgFile(tokenNode);
        if (ret != ATRET_SUCCESS) {
            LOGC("Failed to UpdateInfoInCfgFile, ret=%u.", ret);
        }
    }
    return ret;
}

uint64_t GetAccessTokenId(NativeTokenInfoParams *tokenInfo)
{
    NativeAtId tokenId = 0;
    uint64_t result = 0;
    int32_t apl;
    NativeAtIdEx *atPoint = (NativeAtIdEx *)(&result);
    int32_t fd = -1;
    int32_t sceneCode = -1;
    uint32_t ret = ATRET_SUCCESS;
    ClearThreadErrorMsg();
    do {
        ret = LockNativeTokenFile(&fd);
        sceneCode = NATIVE_TOKEN_INIT;
        BREAK_IF_TRUE(ret != ATRET_SUCCESS);

        if (g_isNativeTokenInited == 0) {
            ret = AtlibInit();
            sceneCode = NATIVE_TOKEN_INIT;
            BREAK_IF_TRUE(ret != ATRET_SUCCESS);
        }
        ret = CheckProcessInfo(tokenInfo, &apl);
        sceneCode = CHECK_PROCESS_INFO;
        BREAK_IF_TRUE(ret != ATRET_SUCCESS);

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
            sceneCode = ADD_NODE;
            BREAK_IF_TRUE(ret != ATRET_SUCCESS);
        } else {
            ret = UpdateNewTokenToListAndFile(tokenInfo, tokenNode, apl);
            sceneCode = UPDATE_NODE;
            BREAK_IF_TRUE(ret != ATRET_SUCCESS);
        }
    } while (0);
    UnlockNativeTokenFile(fd);
    if (ret != ATRET_SUCCESS) {
        ReportNativeTokenExceptionEvent(sceneCode, (int32_t)ret, GetThreadErrorMsg());
        return INVALID_TOKEN_ID;
    }
    atPoint->tokenId = tokenId;
    atPoint->tokenAttr = 0;
    return result;
}

