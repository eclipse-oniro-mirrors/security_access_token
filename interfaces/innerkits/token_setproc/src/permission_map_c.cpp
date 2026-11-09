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

#include <cstring>
#include <string>

#include "permission_map.h"
#include "securec.h"

extern "C" bool TransferPermissionToOpcode(const char *permissionName, uint32_t *opCode)
{
    if ((permissionName == nullptr) || (opCode == nullptr)) {
        return false;
    }

    uint32_t permissionCode = 0;
    if (!OHOS::Security::AccessToken::TransferPermissionToOpcode(std::string(permissionName), permissionCode)) {
        return false;
    }
    *opCode = permissionCode;
    return true;
}

extern "C" bool TransferOpCodeToPermission(uint32_t opCode, char *permissionName, uint32_t nameSize)
{
    if (permissionName == nullptr || nameSize <= 1) {
        return false;
    }

    std::string permissionNameStr = OHOS::Security::AccessToken::TransferOpcodeToPermission(opCode);
    if (permissionNameStr.empty()) {
        return false;
    }
    if (permissionNameStr.size() > nameSize - 1) {
        return false;
    }
    if (strcpy_s(permissionName, nameSize, permissionNameStr.c_str()) != EOK) {
        return false;
    }
    return true;
}

extern "C" bool SetPermissionEnabled(const char *permissionName, bool isEnable)
{
    if (permissionName == nullptr) {
        return false;
    }
    return OHOS::Security::AccessToken::SetPermissionBriefEnabled(std::string(permissionName), isEnable);
}

extern "C" bool IsNativePermissionAvailable(const char *permissionName, int32_t apl,
    const char *const *acls, int32_t aclsNum, uint32_t *opCode)
{
    if ((permissionName == nullptr) || (opCode == nullptr)) {
        return false;
    }

    uint32_t code = 0;
    OHOS::Security::AccessToken::PermissionBriefDef briefDef;
    if (!OHOS::Security::AccessToken::GetPermissionBriefDef(std::string(permissionName), briefDef, code) ||
        !briefDef.isEnable) {
        return false;
    }
    if (apl < static_cast<int32_t>(briefDef.availableLevel)) {
        bool isInAcls = false;
        for (int32_t i = 0; i < aclsNum; ++i) {
            if ((acls != nullptr) && (acls[i] != nullptr) && (strcmp(acls[i], permissionName) == 0)) {
                isInAcls = true;
                break;
            }
        }
        if (!isInAcls) {
            return false;
        }
    }
    *opCode = code;
    return true;
}

extern "C" int32_t FilterKernelPermissions(
    uint32_t perms[MAX_PERM_BIT_MAP_SIZE], uint16_t *kernelPerms, uint32_t *permSize)
{
    constexpr uint32_t uint32Bits = 32;
    if ((perms == nullptr) || permSize == nullptr || *permSize == 0 || kernelPerms == nullptr) {
        return ACCESS_TOKEN_PARAM_INVALID;
    }

    uint32_t outputSize = 0;
    uint32_t maxPermSize = static_cast<uint32_t>(OHOS::Security::AccessToken::GetDefPermissionsSize());
    for (uint32_t wordIndex = 0; wordIndex < MAX_PERM_BIT_MAP_SIZE; ++wordIndex) {
        uint32_t word = perms[wordIndex];
        if (word == 0) {
            continue;
        }
        for (uint32_t bitIndex = 0; bitIndex < uint32Bits; ++bitIndex) {
            if ((word & (static_cast<uint32_t>(0x01) << bitIndex)) == 0) {
                continue;
            }

            uint32_t code = wordIndex * uint32Bits + bitIndex;
            if (code >= maxPermSize) {
                continue;
            }
            OHOS::Security::AccessToken::PermissionBriefDef briefDef;
            OHOS::Security::AccessToken::GetPermissionBriefDef(code, briefDef);
            if (!briefDef.isKernelEffect) {
                continue;
            }
            if (outputSize < *permSize) {
                kernelPerms[outputSize] = static_cast<uint16_t>(code);
            }

            outputSize++;
            if (outputSize > *permSize) {
                return ERANGE;
            }
        }
    }
    *permSize = outputSize;
    return ACCESS_TOKEN_OK;
}

extern "C" bool IsPermissionKernelEffect(const char *permissionName)
{
    if (permissionName == nullptr) {
        return false;
    }
    OHOS::Security::AccessToken::PermissionBriefDef briefDef;
    if (!OHOS::Security::AccessToken::GetPermissionBriefDef(std::string(permissionName), briefDef)) {
        return false;
    }
    return briefDef.isKernelEffect;
}
