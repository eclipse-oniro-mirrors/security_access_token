/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "accesstoken_klog.h"
#include "nativetoken_hisysevent.h"
#include "nativetoken_json_oper.h"
#include "nativetoken_kit.h"
#include "perm_setproc_c.h"
#include "securec.h"
#include "spm_setproc.h"
#include "accesstoken_file_util.h"
#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
#include "config_policy_utils.h"
#endif

NativeTokenList *g_tokenListHead;
int32_t g_isNativeTokenInited = 0;
const uint64_t g_nativeFdTag = 0xD005A01;
static const uint32_t SPM_PERM_ARRAY_SIZE = 64;
static const uint32_t UINT32_BITS_NUM = 32;
static const int32_t MAX_KERNEL_OPERATE_TRY_TIMES = 2;
static const mode_t FILE_DAC_MASK = 0777;

#define PERMISSION_DEFINITION_EXT_FILE "/etc/access_token/accesstoken_permission_definition_ext.txt"

#define KERN_PERM_TYPE_BOOL 1
#define KERN_PERM_TYPE_INT  2
#define KERN_PERM_DENIED    0
#define KERN_PERM_GRANTED   1

#define BREAK_IF_TRUE(cond) \
    if (cond) { \
        break; \
    }

static void TryRemoveInvalidConfigPath(const char *path)
{
    struct stat fileStat;
    if (lstat(path, &fileStat) != 0) {
        LOGC("lstat path(%s)  errno=%d.", path, errno);
        return;
    }
    if (S_ISREG(fileStat.st_mode)) {
        return;
    }
    LOGI("Start removing invalid config path(%s).", path);
    if (S_ISDIR(fileStat.st_mode)) {
        if (rmdir(path) != 0) {
            LOGC("Failed to remove directory(%s), errno=%d.", path, errno);
        }
        return;
    }
    if (unlink(path) == 0) {
        return;
    }
    LOGC("Failed to remove non-regular config node, errno=%d.", errno);
}

static uint32_t FixFilePermission(const char *filePath, const struct stat *fileStat)
{
    // nativetoken.json has two readers: init (root) and accesstoken (non-root).
    // Fix owner/group/DAC so accesstoken can read after init.
    const char *lastSlash = strrchr(filePath, '/');
    if (lastSlash == NULL || lastSlash == filePath) {
        LOGC("Invalid file path, no parent dir.");
        return GET_FILE_BUFF_FAILED;
    }
    char parentDir[PATH_MAX_LEN + 1] = {0};
    size_t dirLen = (size_t)(lastSlash - filePath);
    if (dirLen >= sizeof(parentDir) - 1) {
        LOGC("Parent dir path too long.");
        return GET_FILE_BUFF_FAILED;
    }
    if (memcpy_s(parentDir, sizeof(parentDir), filePath, dirLen) != EOK) {
        LOGC("Failed to copy parent dir.");
        return GET_FILE_BUFF_FAILED;
    }
    parentDir[dirLen] = '\0';

    struct stat dirStat;
    if (stat(parentDir, &dirStat) != 0) {
        LOGC("Failed to stat parent dir, errno=%d.", errno);
        return GET_FILE_BUFF_FAILED;
    }
    if (fileStat->st_uid != dirStat.st_uid || fileStat->st_gid != dirStat.st_gid) {
        LOGC("Config file owner/group mismatch with parent dir, fixing. uid=%u/%u, gid=%u/%u.",
             fileStat->st_uid, dirStat.st_uid, fileStat->st_gid, dirStat.st_gid);
        if (chown(filePath, dirStat.st_uid, dirStat.st_gid) != 0) {
            LOGC("Failed to chown config file, errno=%d.", errno);
            return GET_FILE_BUFF_FAILED;
        }
    }
    mode_t expectMode = S_IRUSR | S_IWUSR | S_IRGRP;
    if ((fileStat->st_mode & FILE_DAC_MASK) != expectMode) {
        LOGC("Config file DAC mode mismatch, fixing. mode=%o/%o.",
             fileStat->st_mode & FILE_DAC_MASK, expectMode);
        if (chmod(filePath, expectMode) != 0) {
            LOGC("Failed to chmod config file, errno=%d.", errno);
            return GET_FILE_BUFF_FAILED;
        }
    }
    if (GetThreadErrorMsgLen() > 0) {
        ReportNativeTokenExceptionEvent(NATIVE_TOKEN_INIT, GET_FILE_BUFF_FAILED, GetThreadErrorMsg());
        ClearThreadErrorMsg();
    }
    return ATRET_SUCCESS;
}

uint32_t GetFileBuff(const char *cfg, char **retBuff)
{
    struct stat fileStat;

    if ((cfg == NULL) || (retBuff == NULL)) {
        LOGC("Invalid config file path.");
        return GET_FILE_BUFF_FAILED;
    }
    if ((lstat(cfg, &fileStat) == 0) && S_ISLNK(fileStat.st_mode)) {
        LOGC("Config file path is a symbolic link.");
        return GET_FILE_BUFF_FAILED;
    }

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
    if (!S_ISREG(fileStat.st_mode)) {
        LOGC("Config path is not a regular file.");
        return GET_FILE_BUFF_FAILED;
    }
    if (FixFilePermission(filePath, &fileStat) != ATRET_SUCCESS) {
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
    ret = GetUidFromJson(cjsonItem, tokenNode);
    if (ret != ATRET_SUCCESS) {
        LOGC("Failed to GetUidFromJson.");
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
    FreeStrArray(&(*node)->acls, (*node)->aclsNum - 1);
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

static uint32_t ReadAndParseFile(cJSON **record)
{
    char *fileBuff = NULL;
    *record = NULL;

    bool mainMissingOrEmpty = false;
    uint32_t ret = GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff);
    if (ret == ATRET_SUCCESS && fileBuff == NULL) {
        LOGI("Main nativetoken.json is missing or empty, trying backup.");
        ret = GET_FILE_BUFF_FAILED;
        mainMissingOrEmpty = true;
    }
    if (ret == ATRET_SUCCESS && fileBuff != NULL) {
        *record = cJSON_Parse(fileBuff);
        free(fileBuff);
        fileBuff = NULL;
        if (*record != NULL) {
            return ATRET_SUCCESS;
        }
        LOGC("Failed to parse main nativetoken.json, trying backup.");
        ret = GET_TOKEN_LIST_FAILED;
    } else if (!mainMissingOrEmpty) {
        LOGC("Failed to read main nativetoken.json, ret=%d.", ret);
    }

    char bakPath[PATH_MAX_LEN + 1] = {0};
    if (GetBakFilePath(TOKEN_ID_CFG_FILE_PATH, bakPath, sizeof(bakPath)) != 0) {
        LOGC("Failed to construct backup path.");
        return ret;
    }
    uint32_t bakRet = GetFileBuff(bakPath, &fileBuff);
    if (bakRet != ATRET_SUCCESS || fileBuff == NULL) {
        if (mainMissingOrEmpty && bakRet == ATRET_SUCCESS && fileBuff == NULL) {
            // Both main and backup are missing/empty — empty config (first install)
            return ATRET_SUCCESS;
        }
        LOGC("Failed to read backup nativetoken.json, bakRet=%d.", bakRet);
        return ret;
    }
    *record = cJSON_Parse(fileBuff);
    if (*record == NULL) {
        free(fileBuff);
        fileBuff = NULL;
        LOGC("Failed to parse both main and backup nativetoken.json.");
        return ret;
    }

    TryRemoveInvalidConfigPath(TOKEN_ID_CFG_FILE_PATH);
    int32_t utilRet = AtomicWriteFile(TOKEN_ID_CFG_FILE_PATH, fileBuff, strlen(fileBuff),
        S_IRUSR | S_IWUSR | S_IRGRP);
    LOGC("Restore main nativetoken.json from backup, ret=%d.", utilRet);
    free(fileBuff);
    fileBuff = NULL;
    return ATRET_SUCCESS;
}

static uint32_t ParseTokenInfo(void)
{
    cJSON *record = NULL;
    uint32_t ret = ReadAndParseFile(&record);
    if (record == NULL) {
        return ret;
    }
    ret = GetTokenList(record);
    cJSON_Delete(record);
    return ret;
}

static uint32_t ClearOrCreateCfgFile(void)
{
    TryRemoveInvalidConfigPath(TOKEN_ID_CFG_FILE_PATH);
    char bakPath[PATH_MAX_LEN + 1] = {0};
    if (GetBakFilePath(TOKEN_ID_CFG_FILE_PATH, bakPath, sizeof(bakPath)) == 0) {
        if (unlink(bakPath) != 0) {
            (void)rmdir(bakPath);
        }
    }
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

static void EnablePermissionDefinitionExt(void)
{
#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
    CfgDir *dirs = GetCfgDirList();
    if (dirs == NULL) {
        LOGE("Failed to get config dir list.");
        return;
    }
    char filePath[PATH_MAX_LEN + 1] = {0};
    char line[MAX_PERM_LEN + 1] = {0};
    for (uint32_t i = 0; i < MAX_CFG_POLICY_DIRS_CNT; ++i) {
        if (dirs->paths[i] == NULL) {
            continue;
        }
        int32_t len = snprintf_s(filePath, sizeof(filePath), sizeof(filePath) - 1, "%s%s",
            dirs->paths[i], PERMISSION_DEFINITION_EXT_FILE);
        if (len < 0) {
            continue;
        }
        FILE *file = fopen(filePath, "r");
        if (file == NULL) {
            continue;
        }
        while (fgets(line, sizeof(line), file) != NULL) {
            size_t lineLen = strlen(line);
            while ((lineLen > 0) && isspace((unsigned char)line[lineLen - 1])) {
                line[--lineLen] = '\0';
            }
            char *permName = line;
            while (isspace((unsigned char)*permName)) {
                ++permName;
            }
            lineLen = strlen(permName);
            if ((lineLen > 0) && !SetPermissionEnabled(permName, true)) {
                LOGW("Permission in ext file is invalid %s.", permName);
            }
        }
        (void)fclose(file);
    }
    FreeCfgDirList(dirs);
#else
    return;
#endif
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

    uint32_t ret = ParseTokenInfo();
    if (ret != ATRET_SUCCESS) {
        ReportNativeTokenExceptionEvent(NATIVE_TOKEN_INIT, (int32_t)ret, GetThreadErrorMsg());
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
    EnablePermissionDefinitionExt();
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
        LOGC("Failed to read, len(%" PRIdPTR "", len);
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

    int32_t utilRet = AtomicWriteFile(TOKEN_ID_CFG_FILE_PATH, jsonStr, strlen(jsonStr),
        S_IRUSR | S_IWUSR | S_IRGRP);
    if (utilRet != 0) {
        LOGC("Failed to AtomicWriteFile, ret=%d.", utilRet);
        ret = ATRET_FAILED;
    }

    cJSON_free(jsonStr);
    return ret;
}

static uint32_t SaveTokenIdToCfg(const NativeTokenList *curr)
{
    cJSON *record = NULL;
    uint32_t ret = ReadAndParseFile(&record);
    if (record == NULL) {
        if (ret == ATRET_SUCCESS) {
            record = cJSON_CreateArray();
        } else {
            LOGC("Failed to read token config, ret=%d.", ret);
            return SAVE_CONTENT_TO_CFG_FAILED;
        }
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

static uint32_t CheckKernPerms(int32_t permsNum, const KernelPermissionList *kernPerms)
{
    if (kernPerms->permsNum < 0 || kernPerms->permsNum > MAX_PERM_NUM) {
        LOGC("Invalid kernPerms permsNum(%d).", kernPerms->permsNum);
        return KERNPERMS_INVALID;
    }
    if (kernPerms->perms == NULL && kernPerms->permsNum > 0) {
        LOGC("kernPerms perms is null but permsNum(%d) != 0.", kernPerms->permsNum);
        return KERNPERMS_INVALID;
    }
    if (permsNum > MAX_PERM_NUM - kernPerms->permsNum) {
        LOGC("Combined count(%d + %d) exceeds MAX_PERM_NUM(%d).",
            permsNum, kernPerms->permsNum, MAX_PERM_NUM);
        return KERNPERMS_INVALID;
    }
    for (int32_t i = 0; i < kernPerms->permsNum; ++i) {
        if (kernPerms->perms[i].permissionName == NULL) {
            LOGC("Invalid kernPerms[%d] permissionName is null.", i);
            return KERNPERMS_INVALID;
        }
        size_t permLen = strlen(kernPerms->perms[i].permissionName);
        if (permLen == 0 || permLen > MAX_PERM_LEN) {
            LOGC("Invalid kernPerms[%d] permissionName length(%zu).", i, permLen);
            return KERNPERMS_INVALID;
        }
        if (kernPerms->perms[i].type == KERN_PERM_TYPE_BOOL &&
            kernPerms->perms[i].valueNum != KERN_PERM_DENIED &&
            kernPerms->perms[i].valueNum != KERN_PERM_GRANTED) {
            LOGC("Invalid kernPerms[%d] valueNum(%d) for bool type.", i, kernPerms->perms[i].valueNum);
            return KERNPERMS_INVALID;
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

    uint32_t retKernPerm = CheckKernPerms(tokenInfo->permsNum, &(tokenInfo->kernPerms));
    if (retKernPerm != ATRET_SUCCESS) {
        return KERNPERMS_INVALID;
    }

    if (tokenInfo->aclsNum > tokenInfo->permsNum + tokenInfo->kernPerms.permsNum) {
        LOGC("Invalid aclsNum(%d) or permsNum(%d) + kernPermsNum(%d).",
            tokenInfo->aclsNum, tokenInfo->permsNum, tokenInfo->kernPerms.permsNum);
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

static void FreeKernPermArray(PermNameWithValue *perms)
{
    if (perms != NULL) {
        free(perms);
    }
}

static bool ShouldSkipKernPerm(const PermNameWithValue *entry, const PermNameWithValue *perms,
    int32_t cnt, int32_t index)
{
    if (entry->type != KERN_PERM_TYPE_BOOL && entry->type != KERN_PERM_TYPE_INT) {
        LOGE("Invalid kernPerms type(%d), skip.", entry->type);
        return true;
    }
    for (int32_t j = index + 1; j < cnt; j++) {
        if (strcmp(entry->permissionName, perms[j].permissionName) == 0) {
            return true;
        }
    }
    if (entry->type == KERN_PERM_TYPE_BOOL && entry->valueNum == KERN_PERM_DENIED) {
        return true;
    }
    if (!IsPermissionKernelEffect(entry->permissionName)) {
        LOGE("kernPerm not found or not kernel effect, permission=%{public}s, skip.", entry->permissionName);
        return true;
    }
    return false;
}

static uint32_t DedupFilterKernPerms(const KernelPermissionList *src,
    PermNameWithValue **dst, int32_t *dstNum)
{
    *dst = NULL;
    *dstNum = 0;
    if (src->permsNum <= 0) {
        return ATRET_SUCCESS;
    }
    *dst = (PermNameWithValue *)malloc(src->permsNum * sizeof(PermNameWithValue));
    if (*dst == NULL) {
        LOGE("Failed to alloc memory for kernPerms filter.");
        return MALLOC_FAILED;
    }
    for (int32_t i = 0; i < src->permsNum; ++i) {
        if (ShouldSkipKernPerm(&src->perms[i], src->perms, src->permsNum, i)) {
            continue;
        }
        (*dst)[*dstNum] = src->perms[i];
        (*dstNum)++;
    }
    return ATRET_SUCCESS;
}

static uint32_t CreatePermsWithKernPerms(const NativeTokenInfoParams *tokenInfo, NativeTokenList *tokenNode,
    NativeTokenInfoParams *filteredInfo)
{
    uint32_t ret = DedupFilterKernPerms(&tokenInfo->kernPerms,
        &filteredInfo->kernPerms.perms, &filteredInfo->kernPerms.permsNum);
    if (ret != ATRET_SUCCESS) {
        return ret;
    }
    int32_t totalNum = tokenInfo->permsNum + filteredInfo->kernPerms.permsNum;
    if (totalNum == 0) {
        tokenNode->perms = NULL;
        tokenNode->permsNum = 0;
        return ATRET_SUCCESS;
    }
    tokenNode->perms = (char **)malloc(totalNum * sizeof(char *));
    if (tokenNode->perms == NULL) {
        LOGE("Failed to alloc memory for perms array.");
        return MALLOC_FAILED;
    }
    int32_t idx = 0;
    for (int32_t i = 0; i < tokenInfo->permsNum; ++i) {
        size_t len = strlen(tokenInfo->perms[i]);
        char *name = (char *)malloc(len + 1);
        if (name == NULL || strcpy_s(name, len + 1, tokenInfo->perms[i]) != EOK) {
            LOGE("Failed to copy perms[%d].", i);
            free(name);
            FreeStrArray(&tokenNode->perms, idx - 1);
            return CREATE_ARRAY_FAILED;
        }
        tokenNode->perms[idx++] = name;
    }
    for (int32_t i = 0; i < filteredInfo->kernPerms.permsNum; ++i) {
        size_t len = strlen(filteredInfo->kernPerms.perms[i].permissionName);
        char *name = (char *)malloc(len + 1);
        if (name == NULL || strcpy_s(name, len + 1, filteredInfo->kernPerms.perms[i].permissionName) != EOK) {
            LOGE("Failed to copy kernPerm[%d].", i);
            free(name);
            FreeStrArray(&tokenNode->perms, idx - 1);
            return CREATE_ARRAY_FAILED;
        }
        tokenNode->perms[idx++] = name;
    }
    tokenNode->permsNum = totalNum;
    return ATRET_SUCCESS;
}

static uint32_t CreateTokenNode(const NativeTokenInfoParams *tokenInfo,
    int32_t aplIn, NativeTokenList **tokenNode)
{
    NativeAtId id = CreateNativeTokenId(tokenInfo->processName);
    if (id == INVALID_TOKEN_ID) {
        LOGC("Failed to get new native tokenId.");
        return CREATE_NATIVETOKEN_ID_FAILED;
    }

    *tokenNode = (NativeTokenList *)malloc(sizeof(NativeTokenList));
    if (*tokenNode == NULL) {
        LOGC("Failed to alloc memory for tokenNode.");
        return MALLOC_FAILED;
    }
    (*tokenNode)->tokenId = id;
    (*tokenNode)->apl = aplIn;
    (*tokenNode)->uid = tokenInfo->uid;
    (*tokenNode)->dcapsNum = tokenInfo->dcapsNum;
    (*tokenNode)->permsNum = tokenInfo->permsNum + tokenInfo->kernPerms.permsNum;
    (*tokenNode)->aclsNum = tokenInfo->aclsNum;
    if (strcpy_s((*tokenNode)->processName, MAX_PROCESS_NAME_LEN + 1,
        tokenInfo->processName) != EOK) {
        LOGC("Failed to copy process name.");
        free(*tokenNode);
        *tokenNode = NULL;
        return STRCPY_FAILED;
    }
    return ATRET_SUCCESS;
}

static uint32_t AddNewTokenToListAndFile(const NativeTokenInfoParams *tokenInfo,
    int32_t aplIn, NativeAtId *tokenId, NativeTokenInfoParams *filteredInfo)
{
    NativeTokenList *tokenNode = NULL;
    uint32_t ret = CreateTokenNode(tokenInfo, aplIn, &tokenNode);
    if (ret != ATRET_SUCCESS) {
        return ret;
    }

    if (CreateStrArray(tokenInfo->dcapsNum, tokenInfo->dcaps, &tokenNode->dcaps) != ATRET_SUCCESS) {
        LOGC("Failed to CreateStrArray for dcaps.");
        free(tokenNode);
        return CREATE_ARRAY_FAILED;
    }
    if (CreatePermsWithKernPerms(tokenInfo, tokenNode, filteredInfo) != ATRET_SUCCESS) {
        LOGC("Failed to CreatePermsWithKernPerms.");
        FreeStrArray(&tokenNode->dcaps, tokenInfo->dcapsNum - 1);
        free(tokenNode);
        return CREATE_ARRAY_FAILED;
    }
    if (CreateStrArray(tokenInfo->aclsNum, tokenInfo->acls, &tokenNode->acls) != ATRET_SUCCESS) {
        LOGC("Failed to CreateStrArray for acls.");
        FreeStrArray(&tokenNode->dcaps, tokenInfo->dcapsNum - 1);
        FreeStrArray(&tokenNode->perms, tokenNode->permsNum - 1);
        free(tokenNode);
        return CREATE_ARRAY_FAILED;
    }

    tokenNode->next = g_tokenListHead->next;
    g_tokenListHead->next = tokenNode;
    *tokenId = tokenNode->tokenId;
    return SaveTokenIdToCfg(tokenNode);
}

static bool IsTokenInfoSame(const NativeTokenList *tokenNode,
                            const char **dcapsIn, int32_t dcapNumIn, int32_t aplIn)
{
    if (tokenNode->apl != aplIn) {
        return false;
    }
    if (tokenNode->dcapsNum != dcapNumIn) {
        return false;
    }
    for (int32_t i = 0; i < dcapNumIn; i++) {
        if (strcmp(tokenNode->dcaps[i], dcapsIn[i]) != 0) {
            return false;
        }
    }
    return true;
}

static bool IsPermsInfoSame(const NativeTokenList *tokenNode,
                            const char **permsIn, int32_t permsNumIn,
                            const KernelPermissionList *kernPerms)
{
    int32_t totalNum = permsNumIn + kernPerms->permsNum;
    if (tokenNode->permsNum != totalNum) {
        return false;
    }
    for (int32_t i = 0; i < permsNumIn; ++i) {
        if (strcmp(tokenNode->perms[i], permsIn[i]) != 0) {
            return false;
        }
    }
    for (int32_t i = 0; i < kernPerms->permsNum; ++i) {
        if (strcmp(tokenNode->perms[permsNumIn + i], kernPerms->perms[i].permissionName) != 0) {
            return false;
        }
    }
    return true;
}

static bool IsAclsInfoSame(const NativeTokenList *tokenNode,
                           const char **aclsIn, int32_t aclsNumIn)
{
    if (tokenNode->aclsNum != aclsNumIn) {
        return false;
    }
    if (aclsNumIn == 0) {
        return true;
    }
    if ((tokenNode->acls == NULL) || (aclsIn == NULL)) {
        return false;
    }
    for (int32_t i = 0; i < aclsNumIn; i++) {
        if (strcmp(tokenNode->acls[i], aclsIn[i]) != 0) {
            return false;
        }
    }
    return true;
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
    const NativeTokenInfoParams *tokenInfo, NativeTokenInfoParams *filteredInfo)
{
    tokenNode->apl = GetAplLevel(tokenInfo->aplStr);
    tokenNode->uid = tokenInfo->uid;

    uint32_t ret = UpdateStrArrayInList(&tokenNode->dcaps, &(tokenNode->dcapsNum),
        tokenInfo->dcaps, tokenInfo->dcapsNum);
    if (ret != ATRET_SUCCESS) {
        LOGC("Failed to updateStrArray for dcaps.");
        return CREATE_ARRAY_FAILED;
    }
    FreeStrArray(&tokenNode->perms, tokenNode->permsNum - 1);
    tokenNode->permsNum = 0;
    if (CreatePermsWithKernPerms(tokenInfo, tokenNode, filteredInfo) != ATRET_SUCCESS) {
        LOGC("Failed to CreatePermsWithKernPerms.");
        return CREATE_ARRAY_FAILED;
    }
    ret = UpdateStrArrayInList(&tokenNode->acls, &(tokenNode->aclsNum),
        tokenInfo->acls, tokenInfo->aclsNum);
    if (ret != ATRET_SUCCESS) {
        LOGC("Failed to updateStrArray for acls.");
        FreeStrArray(&tokenNode->perms, tokenNode->permsNum - 1);
        return CREATE_ARRAY_FAILED;
    }

    return ATRET_SUCCESS;
}

static uint32_t UpdateInfoInCfgFile(const NativeTokenList *tokenNode)
{
    cJSON *record = NULL;
    uint32_t ret = ReadAndParseFile(&record);
    if (record == NULL) {
        if (ret == ATRET_SUCCESS) {
            record = cJSON_CreateArray();
        } else {
            LOGC("Failed to read token config, ret=%d.", ret);
            return SAVE_CONTENT_TO_CFG_FAILED;
        }
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
    TryRemoveInvalidConfigPath(TOKEN_ID_CFG_FILE_LOCK_PATH);
    int32_t fd = open(TOKEN_ID_CFG_FILE_LOCK_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd < 0) {
        LOGC("Failed to open native token file, errno=%d!", errno);
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
    for (int i = 0; i < MAX_RETRY_LOCK_TIMES; ++i) {
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

static uint32_t UpdateNewTokenToListAndFile(NativeTokenInfoParams *tokenInfo, NativeTokenList *tokenNode,
    int32_t apl, NativeTokenInfoParams *filteredInfo)
{
    uint32_t ret = ATRET_SUCCESS;
    if (!IsTokenInfoSame(tokenNode, tokenInfo->dcaps, tokenInfo->dcapsNum, apl) ||
        !IsPermsInfoSame(tokenNode, tokenInfo->perms, tokenInfo->permsNum, &tokenInfo->kernPerms) ||
        !IsAclsInfoSame(tokenNode, tokenInfo->acls, tokenInfo->aclsNum) ||
        (tokenNode->uid != tokenInfo->uid)) {
        ret = UpdateTokenInfoInList(tokenNode, tokenInfo, filteredInfo);
        if (ret != ATRET_SUCCESS) {
            LOGC("Failed to UpdateTokenInfoInList, ret=%u.", ret);
            RemoveNodeFromList(&tokenNode);
            ReportNativeTokenExceptionEvent(UPDATE_NODE, (int32_t)ret, GetThreadErrorMsg());
            return ret;
        }
        ret = UpdateInfoInCfgFile(tokenNode);
        if (ret != ATRET_SUCCESS) {
            LOGC("Failed to UpdateInfoInCfgFile, ret=%u.", ret);
        }
    }
    return ret;
}

static bool IsKernelSupportSpm()
{
    static bool isSupportSpm = false;
    static bool hasChecked = false;
    if (hasChecked) {
        return isSupportSpm;
    }
    uint32_t version = 0;
    int32_t ret = SpmGetVersion(&version);
    isSupportSpm = (ret != ENOTSUP) ? true : false;
    hasChecked = true;
    return isSupportSpm;
}

static void BuildSpmPerms(const NativeTokenInfoParams *tokenInfo, int32_t apl, uint32_t perms[SPM_PERM_ARRAY_SIZE])
{
    for (int32_t i = 0; i < tokenInfo->permsNum; ++i) {
        uint32_t opCode = 0;
        if (!IsNativePermissionAvailable(tokenInfo->perms[i], apl, tokenInfo->acls, tokenInfo->aclsNum, &opCode)) {
            LOGW("Permission %s is not available for native token, skip.", tokenInfo->perms[i]);
            continue;
        }

        uint32_t index = opCode / UINT32_BITS_NUM;
        if (index >= SPM_PERM_ARRAY_SIZE) {
            LOGE("Opcode out of range, opcode=%{public}u.", opCode);
            continue;
        }
        perms[index] |= ((uint32_t)1 << (opCode % UINT32_BITS_NUM));
    }

    for (int32_t i = 0; i < tokenInfo->kernPerms.permsNum; ++i) {
        uint32_t opCode = 0;
        if (!IsNativePermissionAvailable(tokenInfo->kernPerms.perms[i].permissionName, apl, tokenInfo->acls,
            tokenInfo->aclsNum, &opCode)) {
            LOGE("kernPerm is not available, permission=%{public}s.",
                tokenInfo->kernPerms.perms[i].permissionName);
            continue;
        }
        uint32_t index = opCode / UINT32_BITS_NUM;
        if (index >= SPM_PERM_ARRAY_SIZE) {
            LOGE("Opcode out of range, opcode=%{public}u.", opCode);
            continue;
        }
        perms[index] |= ((uint32_t)1 << (opCode % UINT32_BITS_NUM));
    }
}

static void BuildSpmData(const NativeTokenInfoParams *tokenInfo, uint32_t tokenId, int32_t apl, SpmData *spmData,
    uint32_t perms[SPM_PERM_ARRAY_SIZE])
{
    if ((tokenInfo == NULL) || (spmData == NULL) || (perms == NULL)) {
        return;
    }

    (void)memset_s(spmData, sizeof(SpmData), 0, sizeof(SpmData));
    (void)memset_s(perms, sizeof(uint32_t) * SPM_PERM_ARRAY_SIZE, 0, sizeof(uint32_t) * SPM_PERM_ARRAY_SIZE);
    BuildSpmPerms(tokenInfo, apl, perms);

    spmData->uid = (uint32_t)tokenInfo->uid;
    spmData->tokenid = tokenId;
    spmData->tokenidAttr = 0;
    spmData->index = 0;
    spmData->apl = (uint16_t)apl;
    spmData->distributionType = 0;
    spmData->idType = 0;
    spmData->ownerid = 0;
    spmData->perms.buf = (char *)perms;
    spmData->perms.bufSize = (uint32_t)(sizeof(uint32_t) * SPM_PERM_ARRAY_SIZE);
    spmData->extendPerms.buf = NULL;
    spmData->extendPerms.bufSize = 0;
    spmData->name.buf = (char *)tokenInfo->processName;
    spmData->name.bufSize = (uint32_t)strlen(tokenInfo->processName) + 1;
}

static uint32_t PrepareAccessTokenId(NativeTokenInfoParams *tokenInfo, NativeAtId *tokenId, int32_t *apl,
    int32_t *sceneCode, NativeTokenInfoParams *filteredInfo)
{
    int32_t fd = -1;
    uint32_t ret = ATRET_SUCCESS;

    do {
        ret = LockNativeTokenFile(&fd);
        *sceneCode = NATIVE_TOKEN_INIT;
        BREAK_IF_TRUE(ret != ATRET_SUCCESS);

        if (g_isNativeTokenInited == 0) {
            ret = AtlibInit();
            *sceneCode = NATIVE_TOKEN_INIT;
            BREAK_IF_TRUE(ret != ATRET_SUCCESS);
        }
        ret = CheckProcessInfo(tokenInfo, apl);
        *sceneCode = CHECK_PROCESS_INFO;
        BREAK_IF_TRUE(ret != ATRET_SUCCESS);

        NativeTokenList *tokenNode = g_tokenListHead->next;
        while (tokenNode != NULL) {
            if (strcmp(tokenNode->processName, tokenInfo->processName) == 0) {
                *tokenId = tokenNode->tokenId;
                break;
            }
            tokenNode = tokenNode->next;
        }

        if (tokenNode == NULL) {
            ret = AddNewTokenToListAndFile(tokenInfo, *apl, tokenId, filteredInfo);
            *sceneCode = ADD_NODE;
            BREAK_IF_TRUE(ret != ATRET_SUCCESS);
        } else {
            ret = UpdateNewTokenToListAndFile(tokenInfo, tokenNode, *apl, filteredInfo);
            *sceneCode = UPDATE_NODE;
            BREAK_IF_TRUE(ret != ATRET_SUCCESS);
        }
    } while (0);
    UnlockNativeTokenFile(fd);
    return ret;
}

static int32_t TrySpmAddEntries(SpmData *spmData)
{
    if (!IsKernelSupportSpm()) {
        return ATRET_SUCCESS;
    }
    SpmData *entries[] = { spmData };
    uint8_t idxErr = 0;
    int32_t ret = ATRET_SUCCESS;

    for (int32_t i = 0; i < MAX_KERNEL_OPERATE_TRY_TIMES; ++i) {
        ret = SpmAddEntries(entries, 1, &idxErr);
        if (ret == ATRET_SUCCESS || ret == ENOTSUP || ret == EEXIST) {
            return ATRET_SUCCESS;
        }
    }
    LOGC("Failed to add native SPM entry to kernel, process name=%s, tokenId=%u, ret=%d, idxErr=%u.",
        spmData->name.buf, spmData->tokenid, ret, idxErr);
    ReportNativeTokenExceptionEvent(ADD_SPM_DATA_TO_KERNEL, ret, GetThreadErrorMsg());
    ClearThreadErrorMsg();
    return ATRET_FAILED;
}

static int32_t TryAddPermissionToKernel(const SpmData *spmData)
{
    int32_t ret = ATRET_SUCCESS;
    for (int32_t i = 0; i < MAX_KERNEL_OPERATE_TRY_TIMES; ++i) {
        ret = AddPermissionToKernel(spmData->tokenid, spmData->perms.buf, spmData->perms.bufSize);
        if (ret == ATRET_SUCCESS) {
            return ret;
        }
    }
    LOGC("Failed to add native permission list to kernel, process name=%s, tokenId=%u, ret=%d.",
        spmData->name.buf, spmData->tokenid, ret);
    ReportNativeTokenExceptionEvent(ADD_PERM_TO_KERNEL, ret, GetThreadErrorMsg());
    ClearThreadErrorMsg();
    return ATRET_FAILED;
}

static void SyncNativeTokenToKernel(const NativeTokenInfoParams *tokenInfo, NativeAtId tokenId, int32_t apl)
{
    SpmData spmData;
    uint32_t perms[SPM_PERM_ARRAY_SIZE];

    BuildSpmData(tokenInfo, tokenId, apl, &spmData, perms);
    (void)TrySpmAddEntries(&spmData);
    (void)TryAddPermissionToKernel(&spmData);
}

uint64_t GetAccessTokenId(NativeTokenInfoParams *tokenInfo)
{
    if (tokenInfo == NULL) {
        LOGC("Native token info is null.");
        return 0;
    }
    NativeAtId tokenId = 0;
    uint64_t result = 0;
    int32_t apl = 0;
    int32_t sceneCode = -1;
    NativeAtIdEx *atPoint = (NativeAtIdEx *)(&result);

    ClearThreadErrorMsg();
    NativeTokenInfoParams filteredInfo = *tokenInfo;
    filteredInfo.kernPerms.perms = NULL;
    filteredInfo.kernPerms.permsNum = 0;
    uint32_t ret = PrepareAccessTokenId(tokenInfo, &tokenId, &apl, &sceneCode, &filteredInfo);
    if (ret != ATRET_SUCCESS) {
        ReportNativeTokenExceptionEvent(sceneCode, (int32_t)ret, GetThreadErrorMsg());
        result = INVALID_TOKEN_ID;
    } else {
        atPoint->tokenId = tokenId;
        atPoint->tokenAttr = 0;
        SyncNativeTokenToKernel(&filteredInfo, tokenId, apl);
    }

    FreeKernPermArray(filteredInfo.kernPerms.perms);
    return result;
}
