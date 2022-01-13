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
#include "parameter.h"
#include "random.h"

NativeTokenQueue *g_tokenQueueHead;
NativeTokenList *g_tokenListHead;
int32_t g_isAtmExist;
int32_t g_signalFd;
static pthread_mutex_t g_tokenQueueHeadLock = PTHREAD_MUTEX_INITIALIZER;

char *GetFileBuff(const char *cfg)
{
    char *buff = NULL;
    FILE *cfgFd = NULL;
    struct stat fileStat;
    int32_t fileSize;

    if (stat(cfg, &fileStat) != 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:stat file failed.", __func__);
        return NULL;
    }
    fileSize = (int32_t)fileStat.st_size;
    if ((fileSize < 0) || (fileSize > MAX_JSON_FILE_LEN)) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:stat file size is invalid.", __func__);
        return NULL;
    }

    char filePath[PATH_MAX_LEN + 1] = {0};
    if (realpath(cfg, filePath) == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:invalid filePath.", __func__);
        return NULL;
    }

    cfgFd = fopen(filePath, "r");
    if (cfgFd == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:fopen file failed.", __func__);
        return NULL;
    }

    buff = (char *)malloc((size_t)(fileSize + 1));
    if (buff == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:memory alloc failed.", __func__);
        fclose(cfgFd);
        return NULL;
    }

    if (fread(buff, fileSize, 1, cfgFd) != 1) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:fread failed.", __func__);
        free(buff);
        buff = NULL;
    } else {
        buff[fileSize] = '\0';
    }

    fclose(cfgFd);
    return buff;
}

int32_t GetTokenList(const cJSON *object)
{
    cJSON *cjsonItem = NULL;
    int32_t arraySize;
    int32_t i;
    cJSON *processNameJson = NULL;
    cJSON *tokenIdJson = NULL;
    NativeTokenList *tmp = NULL;

    if (object == NULL) {
        return ATRET_FAILED;
    }
    arraySize = cJSON_GetArraySize(object);
    for (i = 0; i < arraySize; i++) {
        cjsonItem = cJSON_GetArrayItem(object, i);
        processNameJson = cJSON_GetObjectItem(cjsonItem, "processName");
        tokenIdJson = cJSON_GetObjectItem(cjsonItem, "tokenId");
        if (cJSON_IsString(processNameJson) == 0 || (strlen(processNameJson->valuestring) > MAX_PROCESS_NAME_LEN)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:processNameJson is invalid.", __func__);
            return ATRET_FAILED;
        }
        if ((cJSON_IsNumber(tokenIdJson) == 0) || (cJSON_GetNumberValue(tokenIdJson) <= 0)) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:tokenIdJson is invalid.", __func__);
            return ATRET_FAILED;
        }

        tmp = (NativeTokenList *)malloc(sizeof(NativeTokenList));
        if (tmp == NULL) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:memory alloc failed.", __func__);
            return ATRET_FAILED;
        }
        if (strcpy_s(tmp->processName, MAX_PROCESS_NAME_LEN, processNameJson->valuestring) != EOK) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:strcpy_s failed.", __func__);
            free(tmp);
            return ATRET_FAILED;
        }
        tmp->tokenId = tokenIdJson->valueint;
        tmp->next = g_tokenListHead->next;
        g_tokenListHead->next = tmp;
    }
    return ATRET_SUCCESS;
}

int32_t ParseTokenInfoCfg(const char *filename)
{
    char *fileBuff = NULL;
    cJSON *record = NULL;
    int32_t ret;

    if (filename == NULL || filename[0] == '\0') {
        return ATRET_FAILED;
    }
    fileBuff = GetFileBuff(filename);
    if (fileBuff == NULL) {
        return ATRET_FAILED;
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

    g_tokenQueueHead = (NativeTokenQueue *)malloc(sizeof(NativeTokenQueue));
    if (g_tokenQueueHead == NULL) {
        free(g_tokenListHead);
        g_tokenListHead = NULL;
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:g_tokenQueueHead memory alloc failed.", __func__);
        return ATRET_FAILED;
    }
    g_tokenQueueHead->next = NULL;
    g_isAtmExist = 0;

    return ParseTokenInfoCfg(TOKEN_ID_CFG_PATH);
}

NativeAtId CreateNativeTokenId(void)
{
    uint32_t rand;
    NativeAtId tokenId;
    AtInnerInfo *innerId = (AtInnerInfo *)(&tokenId);

    rand = GetRandomUint32();

    innerId->reserved = 0;
    innerId->tokenUniqueId = rand & (0xFFFFFF);
    innerId->type = TOKEN_NATIVE_TYPE;
    innerId->version = 1;
    return tokenId;
}

int32_t TriggerTransfer()
{
    int32_t ret;
    static const uint64_t increment = 1;
    ret = write(g_signalFd, &increment, sizeof(increment));
    if (ret == -1) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:TriggerTransfer write failed.", __func__);
        return ATRET_FAILED;
    }
    return ATRET_SUCCESS;
}

int32_t TokenInfoSave(const NativeTokenQueue *node)
{
    if (node->apl == 0) {
        return ATRET_FAILED;
    }
    NativeTokenQueue *curr;
    curr = (NativeTokenQueue *)malloc(sizeof(NativeTokenQueue));
    if (curr == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:memory alloc failed.", __func__);
        return ATRET_FAILED;
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
    return ATRET_SUCCESS;
}

int32_t GetAplLevel(const char *aplStr)
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
    ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:aplStr is invalid.", __func__);
    return 0;
}

int32_t SendString(const char *str, int32_t fd)
{
    int32_t writtenSize;
    int32_t len = strlen(str);

    writtenSize = write(fd, str, len);
    if (len != writtenSize) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:SendString write failed.", __func__);
        return ATRET_FAILED;
    }
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
        int32_t fd = open(TOKEN_ID_CFG_PATH, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:open failed.", __func__);
            break;
        }
        strLen = strlen(jsonStr);
        writtenLen = write(fd, (void *)jsonStr, strLen);
        close(fd);
        if (writtenLen != strLen) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:write failed, writtenLen is %d.", __func__, writtenLen);
            break;
        }
    } while (0);

    cJSON_free(jsonStr);
    return;
}

int32_t ExistNewTokenInfo(const NativeTokenQueue *head)
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
    char *fileBuff = NULL;
    cJSON *record = NULL;
    int32_t ret;

    ret = ExistNewTokenInfo(head);
    if (ret == 0) {
        ACCESSTOKEN_LOG_INFO("[ATLIB-%s]:there is no new info.", __func__);
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
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_Parse failed.", __func__);
        return;
    }

    while (iter != NULL) {
        if (iter->flag == 1) {
            iter = iter->next;
            continue;
        }
        cJSON *node = cJSON_CreateObject();
        if (node == NULL) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_CreateObject failed.", __func__);
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

static cJSON *CreateNativeTokenJsonObject(const NativeTokenQueue *curr)
{
    cJSON *object = cJSON_CreateObject();
    if (object == NULL) {
        return NULL;
    }
    cJSON *item = cJSON_CreateString(curr->processName);
    if (item == NULL || !cJSON_AddItemToObject(object, "processName", item)) {
        cJSON_Delete(item);
        return NULL;
    }

    item = cJSON_CreateNumber(curr->apl);
    if (item == NULL || !cJSON_AddItemToObject(object, "APL", item)) {
        cJSON_Delete(item);
        return NULL;
    }

    item = cJSON_CreateNumber(DEFAULT_AT_VERSION);
    if (item == NULL || !cJSON_AddItemToObject(object, "version", item)) {
        cJSON_Delete(item);
        return NULL;
    }

    item = cJSON_CreateNumber(curr->tokenId);
    if (item == NULL || !cJSON_AddItemToObject(object, "tokenId", item)) {
        cJSON_Delete(item);
        return NULL;
    }

    item = cJSON_CreateNumber(0);
    if (item == NULL || !cJSON_AddItemToObject(object, "tokenAttr", item)) {
        cJSON_Delete(item);
        return NULL;
    }

    cJSON *dcapsArr = cJSON_CreateArray();
    if (dcapsArr == NULL) {
        return NULL;
    }
    for (int32_t i = 0; i < curr->dcapsNum; i++) {
        item =  cJSON_CreateString(curr->dcaps[i]);
        if (item == NULL || !cJSON_AddItemToArray(dcapsArr, item)) {
            cJSON_Delete(item);
            cJSON_Delete(dcapsArr);
            return NULL;
        }
    }
    if (!cJSON_AddItemToObject(object, "dcaps", dcapsArr)) {
        cJSON_Delete(dcapsArr);
        return NULL;
    }

    return object;
}

static char *GetStrFromJson(const cJSON *root)
{
    char *jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_PrintUnformatted failed.", __func__);
        return NULL;
    }

    char *str = (char *)malloc(sizeof(char) * (strlen(jsonStr) + 1));
    if (str == NULL) {
        cJSON_free(jsonStr);
        return NULL;
    }

    if (strcpy_s(str, strlen(jsonStr) + 1, jsonStr) != EOK) {
        free(str);
        str = NULL;
    }
    cJSON_free(jsonStr);
    return str;
}

static char *GetStringToBeSync(NativeTokenQueue *head)
{
    cJSON *object = NULL;
    NativeTokenQueue *node = NULL;

    cJSON *array = cJSON_CreateArray();
    if (array == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_CreateArray failed.", __func__);
        return NULL;
    }

    NativeTokenQueue *curr = head;
    while (curr != 0) {
        object = CreateNativeTokenJsonObject(curr);
        if (object == NULL) {
            cJSON_Delete(array);
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:CreateNativeTokenJsonObject failed.", __func__);
            return NULL;
        }
        if (!cJSON_AddItemToArray(array, object)) {
            cJSON_Delete(object);
            cJSON_Delete(array);
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_AddItemToArray failed.", __func__);
            return NULL;
        }
        node = curr;
        curr = curr->next;
        free(node);
        node = NULL;
    }

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        cJSON_Delete(array);
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:cJSON_CreateObject failed.", __func__);
        return NULL;
    }

    if (!cJSON_AddItemToObject(root, TRANSFER_KEY_WORDS, array)) {
        cJSON_Delete(root);
        cJSON_Delete(array);
        return NULL;
    }
    char *str = GetStrFromJson(root);
    cJSON_Delete(root);
    return str;
}

static int32_t SyncToAtm(void)
{
    int32_t result;
    struct sockaddr_un addr;
    int32_t fd = -1;
    char *str = NULL;

    pthread_mutex_lock(&g_tokenQueueHeadLock);
    NativeTokenQueue *begin = g_tokenQueueHead->next;
    g_tokenQueueHead->next = NULL;
    pthread_mutex_unlock(&g_tokenQueueHeadLock);

    if (begin == NULL) {
        ACCESSTOKEN_LOG_INFO("[ATLIB-%s]:noting to be sent.", __func__);
        return ATRET_SUCCESS;
    }

    SaveTokenIdToCfg(begin);

    str = GetStringToBeSync(begin);
    if (str == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:str is null.", __func__);
        return ATRET_FAILED;
    }

    do {
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            result = ATRET_FAILED;
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:socket failed.", __func__);
            break;
        }
        (void)memset_s(&addr, sizeof(struct sockaddr_un), 0, sizeof(struct sockaddr_un));
        addr.sun_family = AF_UNIX;
        if (strncpy_s(addr.sun_path, sizeof(addr.sun_path), SOCKET_FILE, sizeof(addr.sun_path) - 1) != EOK) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:strncpy_s failed.", __func__);
            close(fd);
            result = ATRET_FAILED;
            break;
        }
        result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        if (result != 0) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:connect failed. errno %d", __func__, errno);
            close(fd);
            result = ATRET_FAILED;
            break;
        }
        ACCESSTOKEN_LOG_INFO("[ATLIB-%s]:str is to be sent %s.", __func__, str);
        result = SendString(str, fd);
        close(fd);
    } while (0);

    free(str);
    return result;
}

void *ThreadTransferFunc(const void *args)
{
    int32_t ret;
    uint64_t result;

    /* getpram */
    while (1) {
        char buffer[MAX_PARAMTER_LEN] = {0};
        ret = GetParameter(SYSTEM_PROP_NATIVE_RECEPTOR, "false", buffer, MAX_PARAMTER_LEN - 1);
        if (ret > 0 && !strncmp(buffer, "true", strlen("true"))) {
            break;
        }
        ACCESSTOKEN_LOG_INFO("[ATLIB-%s]: %s get failed.", __func__, SYSTEM_PROP_NATIVE_RECEPTOR);
        sleep(1);
    }

    g_signalFd = eventfd(0, 0);
    if (g_signalFd == -1) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:eventfd failed.", __func__);
        return NULL;
    }

    g_isAtmExist = 1;

    while (1) {
        ret = read(g_signalFd, &result, sizeof(uint64_t));
        if (ret == -1) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:read failed.", __func__);
            continue;
        }

        ret = SyncToAtm();
        if (ret != ATRET_SUCCESS) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:SyncToAtm failed.", __func__);
        }
    }
    return NULL;
}

int32_t CheckProcessInfo(const char *processname, const char **dcaps, int32_t dacpNum, const char *aplStr)
{
    if ((processname == NULL) || strlen(processname) > MAX_PROCESS_NAME_LEN
        || strlen(processname) == 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:processname is invalid.", __func__);
        return ATRET_FAILED;
    }

    if ((dcaps == NULL) || dacpNum > MAX_DCAPS_NUM || dacpNum < 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:dcaps is null or dacpNum is invalid.", __func__);
        return ATRET_FAILED;
    }
    for (int i = 0; i < dacpNum; i++) {
        if (strlen(dcaps[i]) > MAX_DCAP_LEN) {
            ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:dcap length is invalid.", __func__);
            return ATRET_FAILED;
        }
    }

    if (aplStr == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:aplStr is null.", __func__);
        return ATRET_FAILED;
    }
    return ATRET_SUCCESS;
}

static int32_t AddNewNativeTokenToList(const char *processname, NativeAtId *tokenId)
{
    NativeTokenList *tokenNode;
    NativeAtId id;
    id = CreateNativeTokenId();
    tokenNode = (NativeTokenList *)malloc(sizeof(NativeTokenList));
    if (tokenNode == NULL) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:memory alloc failed.", __func__);
        return ATRET_FAILED;
    }
    if (strcpy_s(tokenNode->processName, MAX_PROCESS_NAME_LEN, processname) != EOK) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:strcpy_s failed.", __func__);
        free(tokenNode);
        return ATRET_FAILED;
    }
    tokenNode->tokenId = id;
    tokenNode->next = g_tokenListHead->next;
    g_tokenListHead->next = tokenNode;

    *tokenId = id;
    return ATRET_SUCCESS;
}

uint64_t GetAccessTokenId(const char *processname, const char **dcaps, int32_t dacpNum, const char *aplStr)
{
    NativeAtId tokenId;
    NativeTokenList *tokenNode = g_tokenListHead;
    NativeTokenQueue tmp = {0};
    pthread_t tid;
    int32_t exist = 0;
    uint64_t result = 0;
    NativeAtIdEx *atPoint = (NativeAtIdEx *)(&result);

    int32_t ret = CheckProcessInfo(processname, dcaps, dacpNum, aplStr);
    if (ret != ATRET_SUCCESS) {
        return 0;
    }
    int32_t apl = GetAplLevel(aplStr);
    if (apl == 0) {
        return 0;
    }

    if (strcmp("foundation", processname) == 0) {
        (void)pthread_create(&tid, 0, (void*)ThreadTransferFunc, NULL);
    }

    while (tokenNode != NULL) {
        if (strcmp(tokenNode->processName, processname) == 0) {
            exist = 1;
            tokenId = tokenNode->tokenId;
            break;
        }
        tokenNode = tokenNode->next;
    }

    if (tokenNode == NULL) {
        ret = AddNewNativeTokenToList(processname, &tokenId);
        if (ret != ATRET_SUCCESS) {
            return 0;
        }
    }

    TOKEN_QUEUE_NODE_INFO_SET(tmp, apl, processname, tokenId, exist, dcaps, dacpNum);
    ret = TokenInfoSave(&tmp);
    if (ret != 0) {
        return result;
    }
    atPoint->tokenId = tokenId;
    atPoint->tokenAttr = 0;
    return result;
}
