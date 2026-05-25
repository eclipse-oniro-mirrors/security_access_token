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

#include <cstdint>
#include <vector>

#include "perm_setproc_c.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

int32_t AddPermissionToKernel(
    uint32_t tokenID, const std::vector<uint32_t>& opCodeList)
{
    uint32_t perms[MAX_PERM_BIT_MAP_SIZE] = {0};
    for (size_t i = 0; i < opCodeList.size(); ++i) {
        uint32_t opCode = opCodeList[i];
        uint32_t idx = opCode / UINT32_T_BITS;
        uint32_t bitIdx = opCode % UINT32_T_BITS;
        if (idx >= MAX_PERM_BIT_MAP_SIZE) {
            return ACCESS_TOKEN_PARAM_INVALID;
        }
        perms[idx] |= (static_cast<uint32_t>(0x01) << bitIdx);
    }

    return ::AddPermissionToKernel(tokenID, reinterpret_cast<const char *>(perms), sizeof(perms));
}

int32_t RemovePermissionFromKernel(uint32_t tokenID)
{
    return ::RemovePermissionFromKernel(tokenID);
}

int32_t SetPermissionToKernel(uint32_t tokenID, int32_t opCode, bool status)
{
    return ::SetPermissionToKernel(tokenID, opCode, status);
}

int32_t GetPermissionFromKernel(uint32_t tokenID, int32_t opCode, bool& isGranted)
{
    return ::GetPermissionFromKernel(tokenID, opCode, &isGranted);
}

int32_t GetPermissionsFromKernel(uint32_t tokenID, std::vector<uint32_t>& opCodeList)
{
    uint32_t perms[MAX_PERM_BIT_MAP_SIZE] = {0};
    opCodeList.clear();

    int32_t ret = ::GetPermissionsFromKernel(tokenID, perms, MAX_PERM_BIT_MAP_SIZE);
    if (ret != ACCESS_TOKEN_OK) {
        return ret;
    }

    for (uint32_t i = 0; i < MAX_PERM_BIT_MAP_SIZE; ++i) {
        if (perms[i] == 0) {
            continue;
        }
        for (uint32_t j = 0; j < UINT32_T_BITS; ++j) {
            if ((perms[i] & (static_cast<uint32_t>(0x01) << j)) != 0) {
                opCodeList.emplace_back(i * UINT32_T_BITS + j);
            }
        }
    }
    return ACCESS_TOKEN_OK;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
