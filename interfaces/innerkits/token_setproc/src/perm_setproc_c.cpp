/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "perm_setproc_c.h"

#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <cstdio>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {
constexpr uint64_t FD_TAG = 0xD005A01;

struct IoctlSetGetPermData {
    uint32_t token;
    uint32_t opCode;
    bool isGranted;
};

struct IoctlAddPermData {
    uint32_t token;
    uint32_t perm[MAX_PERM_BIT_MAP_SIZE] = {0};
};

struct IoctlGetAllPermData {
    uint32_t token;
    uint32_t perm[MAX_PERM_BIT_MAP_SIZE] = {0};
};
} // namespace

#define ACCESS_TOKENID_ADD_PERMISSIONS \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, ADD_PERMISSIONS, struct IoctlAddPermData)
#define ACCESS_TOKENID_REMOVE_PERMISSIONS \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, REMOVE_PERMISSIONS, uint32_t)
#define ACCESS_TOKENID_GET_PERMISSION \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, GET_PERMISSION, struct IoctlSetGetPermData)
#define ACCESS_TOKENID_SET_PERMISSION \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_PERMISSION, struct IoctlSetGetPermData)
#define ACCESS_TOKENID_GET_ALL_PERMISSIONS \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, GET_ALL_PERMISSIONS, struct IoctlGetAllPermData)

extern "C" int32_t AddPermissionToKernel(uint32_t tokenId, const char *perms, uint32_t permsSize)
{
    if (perms == nullptr || permsSize == 0 || permsSize % sizeof(uint32_t) != 0 ||
        permsSize / sizeof(uint32_t) > MAX_PERM_BIT_MAP_SIZE) {
        return ACCESS_TOKEN_PARAM_INVALID;
    }

    const auto *inputPerms = reinterpret_cast<const uint32_t *>(perms);
    IoctlAddPermData data = {};
    data.token = tokenId;
    const uint32_t bitmapSize = permsSize / sizeof(uint32_t);
    for (uint32_t index = 0; index < bitmapSize; ++index) {
        data.perm[index] = inputPerms[index];
    }

    int32_t fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, FD_TAG);
    int32_t ret = ioctl(fd, ACCESS_TOKENID_ADD_PERMISSIONS, &data);
    (void)fdsan_close_with_tag(fd, FD_TAG);
    if (ret != ACCESS_TOKEN_OK) {
        return errno;
    }

    return ACCESS_TOKEN_OK;
}

extern "C" int32_t RemovePermissionFromKernel(uint32_t tokenID)
{
    int32_t fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, FD_TAG);
    int32_t ret = ioctl(fd, ACCESS_TOKENID_REMOVE_PERMISSIONS, &tokenID);
    (void)fdsan_close_with_tag(fd, FD_TAG);
    if (ret != ACCESS_TOKEN_OK) {
        return errno;
    }

    return ACCESS_TOKEN_OK;
}

extern "C" int32_t SetPermissionToKernel(uint32_t tokenID, int32_t opCode, bool status)
{
    IoctlSetGetPermData data = {
        .token = tokenID,
        .opCode = static_cast<uint32_t>(opCode),
        .isGranted = status,
    };

    int32_t fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, FD_TAG);
    int32_t ret = ioctl(fd, ACCESS_TOKENID_SET_PERMISSION, &data);
    (void)fdsan_close_with_tag(fd, FD_TAG);
    if (ret != ACCESS_TOKEN_OK) {
        return errno;
    }

    return ACCESS_TOKEN_OK;
}

extern "C" int32_t GetPermissionFromKernel(uint32_t tokenID, int32_t opCode, bool *isGranted)
{
    if (isGranted == nullptr) {
        return ACCESS_TOKEN_PARAM_INVALID;
    }

    IoctlSetGetPermData data = {
        .token = tokenID,
        .opCode = static_cast<uint32_t>(opCode),
        .isGranted = false,
    };
    *isGranted = false;

    int32_t fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, FD_TAG);
    int32_t ret = ioctl(fd, ACCESS_TOKENID_GET_PERMISSION, &data);
    (void)fdsan_close_with_tag(fd, FD_TAG);
    if (ret < 0) {
        return errno;
    }
    *isGranted = (ret == 1);
    return ACCESS_TOKEN_OK;
}

extern "C" int32_t GetPermissionsFromKernel(uint32_t tokenId, uint32_t perms[MAX_PERM_BIT_MAP_SIZE])
{
    if (perms == nullptr) {
        return ACCESS_TOKEN_PARAM_INVALID;
    }

    IoctlGetAllPermData data = {
        .token = tokenId,
    };

    int32_t fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, FD_TAG);
    int32_t ret = ioctl(fd, ACCESS_TOKENID_GET_ALL_PERMISSIONS, &data);
    (void)fdsan_close_with_tag(fd, FD_TAG);
    if (ret < 0) {
        return errno;
    }
    for (uint32_t i = 0; i < MAX_PERM_BIT_MAP_SIZE; ++i) {
        perms[i] = data.perm[i];
    }
    return ACCESS_TOKEN_OK;
}
