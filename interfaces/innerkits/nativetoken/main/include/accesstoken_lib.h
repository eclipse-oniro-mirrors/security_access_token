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

#include <unistd.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "cJSON.h"
#include "securec.h"
#include "accesstoken_log.h"

#ifndef ACCESSTOKEN_LIB_H
#define ACCESSTOKEN_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PROCESS_NAME_LEN 256
#define TOKEN_ID_CFG_PATH "/data/token.json"
#define SOCKET_FILE "/data/token_unix_socket"
#define ERR 1
#define SUCCESS 0
#define TOKEN_NATIVE_TYPE 1
#define DEFAULT_AT_VERSION 1
#define TRANSFER_KEY_WORDS "NativeTokenInfo"
#define MAX_JSON_FILE_LEN 102400

typedef unsigned int NativeAtId;
typedef unsigned int NativeAtAttr;

typedef struct {
    unsigned int tokenUniqueId : 24;
    unsigned int reserved : 3;
    unsigned int type : 2;
    unsigned int version : 3;
} AtInnerInfo;

typedef struct {
    NativeAtId tokenId;
    NativeAtAttr tokenAttr;
} NativeAtIdEx;

typedef struct TokenList {
    NativeAtId tokenId;
    char processName[MAX_PROCESS_NAME_LEN];
    struct TokenList *next;
} NativeTokenList;

typedef struct TokenQueue {
    NativeAtId tokenId;
    int apl;
    const char *processName;
    const char **dcaps;
    int dcapsNum;
    int flag;
    struct TokenQueue *next;
} NativeTokenQueue;

#define TOKEN_QUEUE_NODE_INFO_SET(tmp, aplStr, processname, tokenId, exist, dcap, dacpNum) do { \
    (tmp).apl = GetAplLevel((aplStr)); \
    (tmp).processName = (processname); \
    (tmp).tokenId = (tokenId); \
    (tmp).flag = (exist); \
    (tmp).dcaps = (dcap); \
    (tmp).dcapsNum = (dacpNum); \
} while (0)

extern void *ThreadTransferFunc(const void *args);

#ifdef __cplusplus
}
#endif

#endif // ACCESSTOKEN_LIB_H
