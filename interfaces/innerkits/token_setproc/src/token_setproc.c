/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "token_setproc.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define    ACCESS_TOKENID_GET_TOKENID \
    _IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_TOKEN_ID, uint64_t)
#define    ACCESS_TOKENID_SET_TOKENID \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_TOKEN_ID, uint64_t)
#define    ACCESS_TOKENID_GET_FTOKENID \
    _IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_FTOKEN_ID, uint64_t)
#define    ACCESS_TOKENID_SET_FTOKENID \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_FTOKEN_ID, uint64_t)

#define INVAL_TOKEN_ID    0x0
#define TOKEN_ID_LOWMASK 0xffffffff

const uint64_t SET_PROC_FD_TAG = 0xD005A01;

uint64_t GetSelfTokenID(void)
{
    uint64_t token = INVAL_TOKEN_ID;
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return INVAL_TOKEN_ID;
    }
    fdsan_exchange_owner_tag(fd, 0, SET_PROC_FD_TAG);
    int ret = ioctl(fd, ACCESS_TOKENID_GET_TOKENID, &token);
    if (ret) {
        (void)fdsan_close_with_tag(fd, SET_PROC_FD_TAG);
        return INVAL_TOKEN_ID;
    }

    (void)fdsan_close_with_tag(fd, SET_PROC_FD_TAG);
    return token;
}

int SetSelfTokenID(uint64_t tokenID)
{
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, SET_PROC_FD_TAG);
    int ret = ioctl(fd, ACCESS_TOKENID_SET_TOKENID, &tokenID);
    if (ret) {
        (void)fdsan_close_with_tag(fd, SET_PROC_FD_TAG);
        return ret;
    }

    (void)fdsan_close_with_tag(fd, SET_PROC_FD_TAG);
    return ACCESS_TOKEN_OK;
}

uint64_t GetFirstCallerTokenID(void)
{
    uint64_t token = INVAL_TOKEN_ID;
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return INVAL_TOKEN_ID;
    }
    fdsan_exchange_owner_tag(fd, 0, SET_PROC_FD_TAG);
    int ret = ioctl(fd, ACCESS_TOKENID_GET_FTOKENID, &token);
    if (ret) {
        (void)fdsan_close_with_tag(fd, SET_PROC_FD_TAG);
        return INVAL_TOKEN_ID;
    }

    (void)fdsan_close_with_tag(fd, SET_PROC_FD_TAG);
    return token;
}

int SetFirstCallerTokenID(uint64_t tokenID)
{
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, SET_PROC_FD_TAG);
    int ret = ioctl(fd, ACCESS_TOKENID_SET_FTOKENID, &tokenID);
    if (ret) {
        (void)fdsan_close_with_tag(fd, SET_PROC_FD_TAG);
        return ret;
    }

    (void)fdsan_close_with_tag(fd, SET_PROC_FD_TAG);
    return ACCESS_TOKEN_OK;
}
