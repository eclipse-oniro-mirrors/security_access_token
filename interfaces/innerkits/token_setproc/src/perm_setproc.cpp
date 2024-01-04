/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "perm_setproc.h"

#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
namespace OHOS {
namespace Security {
namespace AccessToken {
const uint32_t UINT32_T_BITS = 32;
const uint32_t MAX_PERM_SIZE = 64;
struct IoctlAddPermData {
    uint32_t token;
    uint32_t perm[MAX_PERM_SIZE] = { 0 };
};

struct IoctlSetGetPermData {
    uint32_t token;
    uint32_t opCode;
    bool isGranted;
};

#define    ACCESS_TOKENID_ADD_PERMISSIONS \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, ADD_PERMISSIONS, struct IoctlAddPermData)
#define    ACCESS_TOKENID_REMOVE_PERMISSIONS \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, REMOVE_PERMISSIONS, uint32_t)
#define    ACCESS_TOKENID_GET_PERMISSION \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, GET_PERMISSION, struct IoctlSetGetPermData)
#define    ACCESS_TOKENID_SET_PERMISSION \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_PERMISSION, struct IoctlSetGetPermData)

int32_t AddPermissionToKernel(
    uint32_t tokenID, const std::vector<uint32_t>& opCodeList, const std::vector<bool>& statusList)
{
    if (opCodeList.size() != statusList.size()) {
        return ACCESS_TOKEN_PARAM_INVALID;
    }
    size_t size = opCodeList.size();
    if (size == 0) {
        RemovePermissionFromKernel(tokenID);
        return ACCESS_TOKEN_OK;
    }
    struct IoctlAddPermData data;
    data.token = tokenID;

    for (uint32_t i = 0; i < size; ++i) {
        uint32_t opCode = opCodeList[i];
        uint32_t idx = opCode / UINT32_T_BITS;
        uint32_t bitIdx = opCode % UINT32_T_BITS;
        if (statusList[i]) { // granted
            data.perm[idx] |= static_cast<uint32_t>(0x01) << bitIdx;
        } else {
            data.perm[idx] &= ~(static_cast<uint32_t>(0x01) << bitIdx);
        }
    }

    int32_t fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    int32_t ret = ioctl(fd, ACCESS_TOKENID_ADD_PERMISSIONS, &data);
    close(fd);
    if (ret != ACCESS_TOKEN_OK) {
        return errno;
    }

    return ACCESS_TOKEN_OK;
}

int32_t RemovePermissionFromKernel(uint32_t tokenID)
{
    int32_t fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    int32_t ret = ioctl(fd, ACCESS_TOKENID_REMOVE_PERMISSIONS, &tokenID);
    close(fd);
    if (ret) {
        return errno;
    }

    return ACCESS_TOKEN_OK;
}

int32_t SetPermissionToKernel(uint32_t tokenID, int32_t opCode, bool status)
{
    struct IoctlSetGetPermData data = {
        .token = tokenID,
        .opCode = opCode,
        .isGranted = status,
    };

    int32_t fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    int32_t ret = ioctl(fd, ACCESS_TOKENID_SET_PERMISSION, &data);
    close(fd);
    if (ret != ACCESS_TOKEN_OK) {
        return errno;
    }

    return ACCESS_TOKEN_OK;
}

int32_t GetPermissionFromKernel(uint32_t tokenID, int32_t opCode, bool& isGranted)
{
    struct IoctlSetGetPermData data = {
        .token = tokenID,
        .opCode = opCode,
        .isGranted = false,
    };
    isGranted =  false;

    int32_t fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    int32_t ret = ioctl(fd, ACCESS_TOKENID_GET_PERMISSION, &data);
    close(fd);
    if (ret < 0) {
        return errno;
    }
    isGranted = (ret == 1);
    return ACCESS_TOKEN_OK;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
