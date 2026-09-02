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

#include "spm_setproc.h"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "access_token.h"
#include "securec.h"

namespace {
constexpr uint32_t MOCK_SPM_NAME_BUF_SIZE = 256;
int32_t g_spmGetEntryRet = -1;
bool g_spmDataNewReturnNull = false;
uint16_t g_spmApl = OHOS::Security::AccessToken::APL_NORMAL;
char g_spmName[MOCK_SPM_NAME_BUF_SIZE] = "mock_spm_native_process";
uint32_t g_spmGetEntryCallCount = 0;
uint32_t g_spmDataNewCallCount = 0;
} // namespace

extern "C" {
SpmData *SpmDataNew(uint32_t permBufSize, uint32_t extendPermBufSize, uint32_t nameBufSize)
{
    ++g_spmDataNewCallCount;
    if (g_spmDataNewReturnNull) {
        return nullptr;
    }
    SpmData *data = static_cast<SpmData *>(calloc(1, sizeof(SpmData)));
    if (data == nullptr) {
        return nullptr;
    }
    if (permBufSize > 0) {
        data->perms.buf = static_cast<char *>(calloc(permBufSize, 1));
        if (data->perms.buf == nullptr) {
            SpmDataFree(data);
            return nullptr;
        }
        data->perms.bufSize = permBufSize;
    }
    if (extendPermBufSize > 0) {
        data->extendPerms.buf = static_cast<char *>(calloc(extendPermBufSize, 1));
        if (data->extendPerms.buf == nullptr) {
            SpmDataFree(data);
            return nullptr;
        }
        data->extendPerms.bufSize = extendPermBufSize;
    }
    if (nameBufSize > 0) {
        data->name.buf = static_cast<char *>(calloc(nameBufSize, 1));
        if (data->name.buf == nullptr) {
            SpmDataFree(data);
            return nullptr;
        }
        data->name.bufSize = nameBufSize;
    }
    return data;
}

int SpmGetEntry(uint32_t tokenid, SpmData *entry)
{
    if (entry == NULL || entry->name.buf == NULL || entry->perms.buf == NULL || entry->extendPerms.buf == NULL) {
        return EINVAL;
    }
    ++g_spmGetEntryCallCount;
    if (g_spmGetEntryRet != 0) {
        return g_spmGetEntryRet;
    }
    if (entry == nullptr) {
        return EINVAL;
    }
    entry->uid = 0;
    entry->tokenid = tokenid;
    entry->tokenidAttr = 0;
    entry->index = 0;
    entry->apl = g_spmApl;
    entry->distributionType = 0;
    entry->idType = 0;
    entry->ownerid = 0;
    if (entry->name.buf != nullptr && entry->name.bufSize > 0) {
        size_t nameLen = strlen(g_spmName);
        size_t copySize = (nameLen < entry->name.bufSize) ? nameLen : (entry->name.bufSize - 1);
        if (memcpy_s(entry->name.buf, entry->name.bufSize, g_spmName, copySize) == EOK) {
            entry->name.buf[copySize] = '\0';
        }
    }
    return 0;
}

void SpmDataFree(SpmData *data)
{
    if (data == nullptr) {
        return;
    }
    free(data->perms.buf);
    free(data->extendPerms.buf);
    free(data->name.buf);
    free(data);
}
} // extern "C"

namespace OHOS {
namespace Security {
namespace AccessToken {
void ResetMockSpm()
{
    g_spmGetEntryRet = -1;
    g_spmDataNewReturnNull = false;
    g_spmApl = APL_NORMAL;
    if (memcpy_s(g_spmName, sizeof(g_spmName), "mock_spm_native_process", sizeof("mock_spm_native_process")) != EOK) {
        g_spmName[0] = '\0';
    }
    g_spmGetEntryCallCount = 0;
    g_spmDataNewCallCount = 0;
}

void SetMockSpmGetEntryRet(int32_t ret)
{
    g_spmGetEntryRet = ret;
}

void SetMockSpmDataNewReturnNull(bool returnNull)
{
    g_spmDataNewReturnNull = returnNull;
}

void SetMockSpmName(const char *name)
{
    if (name == nullptr) {
        return;
    }
    size_t nameLen = strlen(name) + 1;
    if (nameLen > MOCK_SPM_NAME_BUF_SIZE) {
        nameLen = MOCK_SPM_NAME_BUF_SIZE;
    }
    if (memcpy_s(g_spmName, sizeof(g_spmName), name, nameLen) == EOK) {
        g_spmName[MOCK_SPM_NAME_BUF_SIZE - 1] = '\0';
    }
}

void SetMockSpmApl(uint16_t apl)
{
    g_spmApl = apl;
}

uint32_t GetMockSpmGetEntryCallCount()
{
    return g_spmGetEntryCallCount;
}

uint32_t GetMockSpmDataNewCallCount()
{
    return g_spmDataNewCallCount;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
