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
#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define    ACCESS_TOKEN_ID_IOCTL_BASE    'A'
#define PERMISSION_GRANTED (0)

enum {
    GET_TOKEN_ID = 1,
    SET_TOKEN_ID,
    GET_FTOKEN_ID,
    SET_FTOKEN_ID,
    ADD_PERMISSIONS,
    REMOVE_PERMISSIONS,
    GET_PERMISSION,
    SET_PERMISSION,
    ACCESS_TOKENID_MAX_NR,
};

#define PERM_GROUP_SIZE 32
#define MAX_PERM_SIZE 64
struct IoctlAddPermData {
    uint32_t token;
    uint32_t perm[MAX_PERM_SIZE];
};

struct IoctlSetGetPermData {
    uint32_t token;
    uint32_t opCode;
    bool isGranted;
};

#define    ACCESS_TOKENID_GET_TOKENID \
    _IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_TOKEN_ID, uint64_t)
#define    ACCESS_TOKENID_SET_TOKENID \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_TOKEN_ID, uint64_t)
#define    ACCESS_TOKENID_GET_FTOKENID \
    _IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_FTOKEN_ID, uint64_t)
#define    ACCESS_TOKENID_SET_FTOKENID \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_FTOKEN_ID, uint64_t)
#define    ACCESS_TOKENID_ADD_PERMISSIONS \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, ADD_PERMISSIONS, struct IoctlAddPermData)
#define    ACCESS_TOKENID_REMOVE_PERMISSIONS \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, REMOVE_PERMISSIONS, uint32_t)
#define    ACCESS_TOKENID_GET_PERMISSION \
    _IOWR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_PERMISSION, struct IoctlSetGetPermData)
#define    ACCESS_TOKENID_SET_PERMISSION \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_PERMISSION, struct IoctlSetGetPermData)


#define INVAL_TOKEN_ID    0x0
#define TOKEN_ID_LOWMASK 0xffffffff

#define TOKENID_DEVNODE "/dev/access_token_id"

uint64_t GetSelfTokenID(void)
{
    uint64_t token = INVAL_TOKEN_ID;
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return INVAL_TOKEN_ID;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_GET_TOKENID, &token);
    if (ret) {
        close(fd);
        return INVAL_TOKEN_ID;
    }

    close(fd);
    return token;
}

int SetSelfTokenID(uint64_t tokenID)
{
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_SET_TOKENID, &tokenID);
    if (ret) {
        close(fd);
        return ret;
    }

    close(fd);
    return ACCESS_TOKEN_OK;
}

uint64_t GetFirstCallerTokenID(void)
{
    uint64_t token = INVAL_TOKEN_ID;
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return INVAL_TOKEN_ID;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_GET_FTOKENID, &token);
    if (ret) {
        close(fd);
        return INVAL_TOKEN_ID;
    }

    close(fd);
    return token;
}


int SetFirstCallerTokenID(uint64_t tokenID)
{
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_SET_FTOKENID, &tokenID);
    if (ret) {
        close(fd);
        return ret;
    }

    close(fd);
    return ACCESS_TOKEN_OK;
}

int32_t AddPermissionToKernel(uint32_t tokenID, uint32_t* opCodeList, int32_t* statusList, uint32_t size)
{
    if (size == 0) {
        return ACCESS_TOKEN_OK;
    }
    if (opCodeList == NULL || statusList == NULL) {
        return ACCESS_TOKEN_PARAM_INVALID;
    }
    struct IoctlAddPermData data;
    data.token = tokenID;

    for (uint32_t i = 0; i < size; ++i) {
        uint32_t opCode = opCodeList[i];
        uint32_t idx = opCode / PERM_GROUP_SIZE;
        uint32_t bitIdx = opCode % PERM_GROUP_SIZE;
        if (statusList[i] == PERMISSION_GRANTED) {
            data.perm[idx] |= (uint32_t)0x01 << bitIdx;
        } else {
            data.perm[idx] &= ~((uint32_t)0x01 << bitIdx);
        }
    }

    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_ADD_PERMISSIONS, &data);
    if (ret) {
        close(fd);
        return errno;
    }

    close(fd);
    return ACCESS_TOKEN_OK;
}

int32_t RemovePermissionFromKernel(uint32_t tokenID)
{
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_REMOVE_PERMISSIONS, &tokenID);
    if (ret) {
        close(fd);
        return errno;
    }

    close(fd);
    return ACCESS_TOKEN_OK;
}

int32_t SetPermissionToKernel(uint32_t tokenID, int32_t opCode, bool status)
{
    struct IoctlSetGetPermData data = {
        .token = tokenID,
        .opCode = opCode,
        .isGranted = status,
    };

    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_SET_PERMISSION, &data);
    if (ret) {
        close(fd);
        return errno;
    }

    close(fd);
    return ACCESS_TOKEN_OK;
}

bool GetPermissionFromKernel(uint32_t tokenID, int32_t opCode)
{
    struct IoctlSetGetPermData data = {
        .token = tokenID,
        .opCode = opCode,
        .isGranted = false,
    };

    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return false;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_GET_PERMISSION, &data);
    if (ret) {
        close(fd);
        return false;
    }

    close(fd);
    return data.isGranted;
}
