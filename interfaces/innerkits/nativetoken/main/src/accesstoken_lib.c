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

#include "accesstoken_lib.h"
#include "accesstokenlib_kit.h"

NativeTokenQueue *g_tokenQueueHead;
NativeTokenList *g_tokenListHead;
int g_isAtmExist;
int g_signalFd;
static pthread_mutex_t g_tokenQueueHeadLock = PTHREAD_MUTEX_INITIALIZER;

char *GetFileBuff(const char *cfg)
{
    char *buff = NULL;
    FILE *cfgFd = NULL;
    struct stat fileStat;
    int fileSize;

    if (stat(cfg, &fileStat) != 0) {
        ACCESSTOKEN_LOG_ERROR("stat file failed.");
        return NULL;
    }
    fileSize = (int)fileStat.st_size;
    if ((fileSize < 0) || (fileSize > MAX_JSON_FILE_LEN)) {
        ACCESSTOKEN_LOG_ERROR("stat file size is invalid.");
        return NULL;
    }

    cfgFd = fopen(cfg, "r");
    if (cfgFd == NULL) {
        ACCESSTOKEN_LOG_ERROR("fopen file failed.");
        return NULL;
    }

    buff = (char *)malloc((size_t)(fileSize + 1));
    if (buff == NULL) {
        ACCESSTOKEN_LOG_ERROR("memory alloc failed.");
        fclose(cfgFd);
        return NULL;
    }

    if (fread(buff, fileSize, 1, cfgFd) != 1) {
        ACCESSTOKEN_LOG_ERROR("fread failed.");
        free(buff);
        buff = NULL;
    } else {
        buff[fileSize] = '\0';
    }

    fclose(cfgFd);
    return buff;
}

int GetTokenList(const cJSON *object)
{
    if (object == NULL) {
        return ERR;
    }
    int arraySize = cJSON_GetArraySize(object);

    for (int i = 0; i < arraySize; i++) {
        cJSON *cjsonItem = cJSON_GetArrayItem(object, i);
        cJSON *processNameJson = cJSON_GetObjectItem(cjsonItem, "processName");
        cJSON *tokenIdJson = cJSON_GetObjectItem(cjsonItem, "tokenId");
        if (cJSON_IsString(processNameJson) == 0 || (strlen(processNameJson->valuestring) > MAX_PROCESS_NAME_LEN)) {
            ACCESSTOKEN_LOG_ERROR("processNameJson is invalid.");
            return ERR;
        }
        if ((cJSON_IsNumber(tokenIdJson) == 0) || (cJSON_GetNumberValue(tokenIdJson) <= 0)) {
            ACCESSTOKEN_LOG_ERROR("tokenIdJson is invalid.");
            return ERR;
        }

        NativeTokenList *tmp = (NativeTokenList *)malloc(sizeof(NativeTokenList));
        if (tmp == NULL) {
            ACCESSTOKEN_LOG_ERROR("memory alloc failed.");
            return ERR;
        }
        (void)strcpy_s(tmp->processName, MAX_PROCESS_NAME_LEN, processNameJson->valuestring);
        tmp->tokenId = tokenIdJson->valueint;
        tmp->next = g_tokenListHead->next;
        g_tokenListHead->next = tmp;
    }
    return SUCCESS;
}

int ParseTokenInfoCfg(const char *filename)
{
    char *fileBuff;
    cJSON *record;
    int ret;

    if (filename == NULL || filename[0] == '\0') {
        return ERR;
    }
    fileBuff = GetFileBuff(filename);
    if (fileBuff == NULL) {
        return ERR;
    }
    record = cJSON_Parse(fileBuff);
    free(fileBuff);
    fileBuff = NULL;

    ret = GetTokenList(record);
    cJSON_Delete(record);

    return ret;
}

int AtlibInit(void)
{
    g_tokenListHead = (NativeTokenList *)malloc(sizeof(NativeTokenList));
    if (g_tokenListHead == NULL) {
        ACCESSTOKEN_LOG_ERROR("g_tokenListHead memory alloc failed.");
        return ERR;
    }
    g_tokenListHead->next = NULL;

    g_tokenQueueHead = (NativeTokenQueue *)malloc(sizeof(NativeTokenQueue));
    if (g_tokenQueueHead == NULL) {
        free(g_tokenListHead);
        ACCESSTOKEN_LOG_ERROR("g_tokenQueueHead memory alloc failed.");
        return ERR;
    }
    g_tokenQueueHead->next = NULL;
    g_isAtmExist = 0;

    return ParseTokenInfoCfg(TOKEN_ID_CFG_PATH);
}

int GetRandomTokenId(unsigned int *randNum)
{
    unsigned int random;
    int len;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        return ERR;
    }
    len = read(fd, &random, sizeof(random));
    (void)close(fd);
    if (len != sizeof(random)) {
        ACCESSTOKEN_LOG_ERROR("read failed.");
        return ERR;
    }
    *randNum = random;
    return SUCCESS;
}

NativeAtId CreateNativeTokenId(const char *processName)
{
    unsigned int rand;
    NativeAtId tokenId;
    AtInnerInfo *innerId = (AtInnerInfo *)(&tokenId);

    if (GetRandomTokenId(&rand) == ERR) {
        return 0;
    }

    innerId->reserved = 0;
    innerId->tokenUniqueId = rand & (0xFFFFFF);
    innerId->type = TOKEN_NATIVE_TYPE;
    innerId->version = 1;
    return tokenId;
}

int TriggerTransfer()
{
    int ret;
    static const uint64_t increment = 1;
    ret = write(g_signalFd, &increment, sizeof(increment));
    if (ret == -1) {
        ACCESSTOKEN_LOG_ERROR("TriggerTransfer write failed.");
        return ERR;
    }
    return SUCCESS;
}

int TokenInfoSave(const NativeTokenQueue *node)
{
    if (node->apl == 0) {
        return ERR;
    }
    NativeTokenQueue *curr;
    curr = (NativeTokenQueue *)malloc(sizeof(NativeTokenQueue));
    if (curr == NULL) {
        ACCESSTOKEN_LOG_ERROR("memory alloc failed.");
        return ERR;
    }
    curr->apl = node->apl;
    curr->processName = node->processName;
    curr->tokenId = node->tokenId;
    curr->flag = node->flag;
    curr->dcaps = node->dcaps;
    curr->dcapsNum = node->dcapsNum;

    pthread_mutex_lock(&g_tokenQueueHeadLock);
    curr->next = g_tokenQueueHead->next;
    g_tokenQueueHead->next = curr;
    pthread_mutex_unlock(&g_tokenQueueHeadLock);

    if (g_isAtmExist == 1) {
        return TriggerTransfer();
    }
    return SUCCESS;
}

int GetAplLevel(const char *aplStr)
{
    if (strcmp(aplStr, "system_core") == 0) {
        return 3; // system_core means apl level is 3
    }
    if (strcmp(aplStr, "system_basic") == 0) {
        return 2; // system_basic means apl level is 2
    }
    if (strcmp(aplStr, "normal") == 0) {
        return 1;
    }
    return 0;
}

uint64_t GetAccessTokenId(const char *processname, const char **dcap, int dacpNum, const char *aplStr)
{
    NativeAtId tokenId;
    NativeTokenList *tokenNode = g_tokenListHead;
    NativeTokenQueue tmp;

    int exist = 0;
    int ret;
    uint64_t result = 0;
    NativeAtIdEx *atPoint = (NativeAtIdEx *)(&result);

    while (tokenNode != NULL) {
        if (strcmp(tokenNode->processName, processname) == 0) {
            exist = 1;
            tokenId = tokenNode->tokenId;
            break;
        }
        tokenNode = tokenNode->next;
    }

    if (exist == 0) {
        tokenId = CreateNativeTokenId(processname);
        tokenNode = (NativeTokenList *)malloc(sizeof(NativeTokenList));
        if (tokenNode == NULL) {
            ACCESSTOKEN_LOG_ERROR("memory alloc failed.");
            return 0;
        }
        (void)strcpy_s(tokenNode->processName, MAX_PROCESS_NAME_LEN, processname);
        tokenNode->tokenId = tokenId;
        tokenNode->next = g_tokenListHead->next;
        g_tokenListHead->next = tokenNode;
        ACCESSTOKEN_LOG_INFO("tokenNode->tokenId :%d, tokenNode->processName: %s\n", tokenNode->tokenId, tokenNode->processName);
    }

    TOKEN_QUEUE_NODE_INFO_SET(tmp, aplStr, processname, tokenId, exist, dcap, dacpNum);
    ret = TokenInfoSave(&tmp);
    if (ret == 0) {
        return result;
    }
    atPoint->tokenId = tokenId;
    atPoint->tokenAttr = 0;
    return result;
}

int SendString(const char *str, int fd)
{
    int writtenSize;
    int len = strlen(str);

    writtenSize = write(fd, str, len);
    if (len != writtenSize) {
        ACCESSTOKEN_LOG_ERROR("SendString write failed.");
        return ERR;
    }
    return SUCCESS;
}

void WriteToFile(const cJSON *root)
{
    char *jsonStr;
    jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == NULL) {
        ACCESSTOKEN_LOG_ERROR("cJSON_PrintUnformatted failed.");
        return;
    }
    ACCESSTOKEN_LOG_INFO("jsonStr %s.\n", jsonStr);

    do {
        int fd = open(TOKEN_ID_CFG_PATH, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            break;
        }
        int strLen = strlen(jsonStr);
        int writtenLen = write(fd, (void *)jsonStr, strLen);
        close(fd);
        if (writtenLen != strLen) {
            ACCESSTOKEN_LOG_ERROR("write failed.");
            break;
        }
    } while (0);

    cJSON_free(jsonStr);
    return;
}

int ExistNewTokenInfo(const NativeTokenQueue *head)
{
    const NativeTokenQueue *iter = head;
    while (iter != NULL) {
        if (iter->flag == 0) {
            return 1;
        }
        iter = iter->next;
    }
    return 0;
}
void SaveTokenIdToCfg(const NativeTokenQueue *head)
{
    const NativeTokenQueue *iter = head;
    char *fileBuff;
    cJSON *record;
    int ret;

    ret = ExistNewTokenInfo(head);
    if (ret == 0) {
        ACCESSTOKEN_LOG_INFO("there is no new info.\n");
        return;
    }
    fileBuff = GetFileBuff(TOKEN_ID_CFG_PATH);
    if (fileBuff == NULL) {
        return;
    }

    record = cJSON_Parse(fileBuff);
    free(fileBuff);
    fileBuff = NULL;

    if (record == NULL) {
        ACCESSTOKEN_LOG_ERROR("cJSON_Parse failed.");
        return;
    }

    while (iter != NULL) {
        if (iter->flag == 1) {
            continue;
        }
        cJSON *node = cJSON_CreateObject();
        if (node == NULL) {
            ACCESSTOKEN_LOG_ERROR("cJSON_CreateObject failed.");
            cJSON_Delete(record);
            return;
        }
        cJSON_AddItemToObject(node, "processName", cJSON_CreateString(iter->processName));
        cJSON_AddItemToObject(node, "tokenId", cJSON_CreateNumber(iter->tokenId));
        cJSON_AddItemToArray(record, node);
        iter = iter->next;
    }
    WriteToFile(record);
    cJSON_Delete(record);
    return;
}

char * GetStringToBeSync(NativeTokenQueue *head)
{
    if (head == NULL) {
        return NULL;
    }

    cJSON *array = cJSON_CreateArray();
    if (array == NULL) {
        return NULL;
    }

    NativeTokenQueue *curr = head;
    while (curr != 0) {
        cJSON *object = cJSON_CreateObject();
        if (object == NULL) {
            cJSON_Delete(array);
            return NULL;
        }
        cJSON_AddItemToObject(object, "processName", cJSON_CreateString(curr->processName));
        cJSON_AddItemToObject(object, "APL", cJSON_CreateNumber(curr->apl));
        cJSON_AddItemToObject(object, "version", cJSON_CreateNumber(DEFAULT_AT_VERSION));
        cJSON_AddItemToObject(object, "tokenId", cJSON_CreateNumber(curr->tokenId));
        cJSON_AddItemToObject(object, "tokenAttr", cJSON_CreateNumber(0));

        cJSON *dcapsArr = cJSON_CreateArray();
        if (dcapsArr == NULL) {
            cJSON_Delete(array);
            return NULL;
        }
        for (int i = 0; i < curr->dcapsNum; i++) {
            cJSON_AddItemToArray(dcapsArr, cJSON_CreateString(curr->dcaps[i]));
        }
        cJSON_AddItemToObject(object, "dcaps", dcapsArr);
        cJSON_AddItemToArray(array, object);

        NativeTokenQueue *node;
        node = curr;
        curr = curr->next;
        free(node);
        node = NULL;
    }

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        cJSON_Delete(array);
        return NULL;
    }

    cJSON_AddItemToObject(root, TRANSFER_KEY_WORDS, array);

    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == NULL) {
        cJSON_Delete(root);
        return NULL;
    }

    char *str = (char *)malloc(sizeof(char) * (strlen(jsonStr) + 1));
    if (str == NULL) {
        cJSON_free(jsonStr);
        cJSON_Delete(root);
        return NULL;
    }

    (void)strcpy_s(str, strlen(jsonStr) + 1, jsonStr);
    cJSON_free(jsonStr);
    cJSON_Delete(root);
    return str;
}

int SyncToAtm(void)
{
    int result;
    struct sockaddr_un addr;
    int fd;
    char *str;

    /* get data to be processed */
    pthread_mutex_lock(&g_tokenQueueHeadLock);
    NativeTokenQueue *begin = g_tokenQueueHead->next;
    g_tokenQueueHead->next = NULL;
    pthread_mutex_unlock(&g_tokenQueueHeadLock);

    /* update the token file */
    SaveTokenIdToCfg(begin);

    str = GetStringToBeSync(begin);
    if (str == NULL) {
        return SUCCESS;
    }

    /* set socket */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    (void)memset_s(&addr, sizeof(struct sockaddr_un), 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    if (memcpy_s(addr.sun_path, sizeof(addr.sun_path), SOCKET_FILE, sizeof(addr.sun_path) - 1) != EOK) {
        ACCESSTOKEN_LOG_ERROR("memcpy_s failed.");
        return ERR;
    }
    result = connect(fd, (struct sockaddr *)&addr, sizeof(addr)); // 建立socket后默认connect()函数为阻塞连接状态
    if (result != 0) {
        ACCESSTOKEN_LOG_ERROR("connect failed %d.", result);
        return ERR;
    }

    result = SendString(str, fd);
    free(str);
    close(fd);
    return result;
}

void *ThreadTransferFunc(const void *args)
{
    uint64_t result;

    /*
    getpram
    */

    g_signalFd = eventfd(0, 0);
    if (g_signalFd == -1) {
        ACCESSTOKEN_LOG_ERROR("eventfd failed.");
        return NULL;
    }

    g_isAtmExist = 1;
    while (1) {
        int ret;
        ret = read(g_signalFd, &result, sizeof(uint64_t));
        if (ret == -1) {
            ACCESSTOKEN_LOG_ERROR("read failed.");
            continue;
        }
        ret = SyncToAtm();
        if (ret == -1) {
            ACCESSTOKEN_LOG_ERROR("SyncToAtm failed.");
        }
    }
    return NULL;
}
