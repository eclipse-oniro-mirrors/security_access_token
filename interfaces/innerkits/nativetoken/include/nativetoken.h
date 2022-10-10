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

#include <stdint.h>

#ifndef NATIVE_TOKEN_H
#define NATIVE_TOKEN_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PROCESS_NAME_LEN 256
#define TOKEN_ID_CFG_FILE_PATH "/data/service/el0/access_token/nativetoken.json"
#define TOKEN_ID_CFG_DIR_PATH "/data/service/el0/access_token"
#define TOKEN_NATIVE_TYPE 1
#define TOKEN_SHELL_TYPE 2
#define DEFAULT_AT_VERSION 1
#define TRANSFER_KEY_WORDS "NativeTokenInfo"
#define MAX_JSON_FILE_LEN 102400
#define MAX_DCAPS_NUM 32
#define MAX_DCAP_LEN 1024
#define MAX_PERM_NUM 64
#define MAX_PERM_LEN 256
#define MAX_PARAMTER_LEN 128
#define SYSTEM_PROP_NATIVE_RECEPTOR "rw.nativetoken.receptor.startup"
#define PATH_MAX_LEN 4096
#define MAX_RETRY_TIMES 1000
#define TOKEN_RANDOM_MASK ((1 << 20) - 1)

#define ATRET_FAILED 1
#define ATRET_SUCCESS 0

#define DCAPS_KEY_NAME  "dcaps"
#define PERMS_KEY_NAME  "permissions"
#define ACLS_KEY_NAME  "nativeAcls"
#define TOKENID_KEY_NAME "tokenId"
#define TOKEN_ATTR_KEY_NAME "tokenAttr"
#define APL_KEY_NAME "APL"
#define VERSION_KEY_NAME "version"
#define PROCESS_KEY_NAME "processName"
#define HDC_PROCESS_NAME "hdcd"

#define SYSTEM_CORE 3
#define SYSTEM_BASIC 2
#define NORMAL 1

#define INVALID_TOKEN_ID 0
typedef unsigned int NativeAtId;
typedef unsigned int NativeAtAttr;

typedef struct {
    unsigned int tokenUniqueId : 20;
    unsigned int reserved : 7;
    unsigned int type : 2;
    unsigned int version : 3;
} AtInnerInfo;

typedef struct {
    NativeAtId tokenId;
    NativeAtAttr tokenAttr;
} NativeAtIdEx;

typedef struct TokenList {
    NativeAtId tokenId;
    int32_t apl;
    char *dcaps[MAX_DCAPS_NUM];
    char *perms[MAX_PERM_NUM];
    char *acls[MAX_PERM_NUM];
    int32_t dcapsNum;
    int32_t permsNum;
    int32_t aclsNum;
    char processName[MAX_PROCESS_NAME_LEN + 1];
    struct TokenList *next;
} NativeTokenList;

typedef struct StrArrayAttribute {
    int32_t maxStrNum;
    uint32_t maxStrLen;
    const char *strKey;
} StrArrayAttr;

extern int32_t GetFileBuff(const char *cfg, char **retBuff);
extern int32_t AtlibInit(void);
#ifdef __cplusplus
}
#endif

#endif // NATIVE_TOKEN_H