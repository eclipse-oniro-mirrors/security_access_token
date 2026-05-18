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

#include "fake_token_setproc.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "securec.h"

#include "spm_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
FakeSpmKernelState g_fakeSpmKernelState;
}

FakeSpmKernelState& GetFakeSpmKernelState()
{
    return g_fakeSpmKernelState;
}

void ResetFakeSpmKernelState()
{
    g_fakeSpmKernelState = {};
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

using OHOS::Security::AccessToken::AccessTokenID;
using OHOS::Security::AccessToken::GetFakeSpmKernelState;
constexpr int32_t RET_FAILED = -1;

extern "C" {
int32_t AddPermissionToKernel(uint32_t tokenID, const std::vector<uint32_t>& opCodeList,
    const std::vector<bool>& statusList)
{
    (void)opCodeList;
    (void)statusList;
    auto& state = GetFakeSpmKernelState();
    state.addPermCallCount++;
    state.addPermTokenIds.emplace_back(tokenID);
    if (static_cast<size_t>(state.addPermCallCount) <= state.addPermRetSequence.size()) {
        return state.addPermRetSequence[state.addPermCallCount - 1];
    }
    return state.addPermRet;
}

int32_t RemovePermissionFromKernel(uint32_t tokenID)
{
    auto& state = GetFakeSpmKernelState();
    state.removePermCallCount++;
    state.removePermTokenIds.emplace_back(tokenID);
    return state.removePermRet;
}

int32_t SetPermissionToKernel(uint32_t tokenID, int32_t opCode, bool status)
{
    (void)tokenID;
    (void)opCode;
    (void)status;
    return 0;
}

int32_t GetPermissionFromKernel(uint32_t tokenID, int32_t opCode, bool& isGranted)
{
    (void)tokenID;
    (void)opCode;
    isGranted = false;
    return 0;
}

uint64_t GetSelfTokenID(void)
{
    return 0;
}

int SetSelfTokenID(uint64_t tokenID)
{
    (void)tokenID;
    return 0;
}

uint64_t GetFirstCallerTokenID(void)
{
    return 0;
}

int SetFirstCallerTokenID(uint64_t tokenID)
{
    (void)tokenID;
    return 0;
}

int SpmAddEntries(SpmData **entries, uint8_t cnt, uint8_t *idxErr)
{
    (void)entries;
    (void)cnt;
    auto& state = GetFakeSpmKernelState();
    state.addCallCount++;
    if (idxErr != nullptr) {
        *idxErr = state.addIdxErr;
    }
    if (static_cast<size_t>(state.addCallCount) <= state.addRetSequence.size()) {
        return state.addRetSequence[state.addCallCount - 1];
    }
    return state.addRet;
}

int SpmSetEntries(SpmData **entries, uint8_t cnt, uint8_t *idxErr)
{
    auto& state = GetFakeSpmKernelState();
    std::vector<AccessTokenID> tokenIds;
    tokenIds.reserve(cnt);
    for (uint8_t i = 0; i < cnt; ++i) {
        tokenIds.emplace_back(entries[i]->tokenid);
    }
    state.setTokenBatches.emplace_back(tokenIds);
    state.setCallCount++;
    if (idxErr != nullptr) {
        *idxErr = state.setIdxErr;
    }
    if (static_cast<size_t>(state.setCallCount) <= state.setRetSequence.size()) {
        return state.setRetSequence[state.setCallCount - 1];
    }
    return state.setRet;
}

int SpmGetEntry(uint32_t tokenid, SpmData *entry)
{
    auto& state = GetFakeSpmKernelState();
    int currentCall = state.getCallCount++;

    int32_t ret;
    if (static_cast<size_t>(currentCall) < state.getRetSequence.size()) {
        ret = state.getRetSequence[currentCall];
    } else {
        // 2: get expected result
        ret = (currentCall % 2 == 0) ? state.getRetOnCall0 : state.getRetOnCall1;
    }
    if (ret != 0) {
        return ret;
    }
    if (entry == nullptr) {
        return RET_FAILED;
    }
    entry->uid = 20100000; // 20100000: base uid
    entry->tokenid = tokenid;
    entry->tokenidAttr = 0;
    entry->index = 0;
    entry->apl = 0;
    entry->distributionType = 0;
    entry->idType = 2; // 2: idType
    entry->ownerid = 1;

    // Handle perms buffer
    if (entry->perms.buf != nullptr && entry->perms.bufSize > 0) {
        (void)memset_s(entry->perms.buf, entry->perms.bufSize, 0, entry->perms.bufSize);
    }

    // Handle extendPerms buffer
    if (entry->extendPerms.buf != nullptr && entry->extendPerms.bufSize > 0) {
        (void)memset_s(entry->extendPerms.buf, entry->extendPerms.bufSize, 0, entry->extendPerms.bufSize);
    }

    // Handle name buffer
    if (entry->name.buf != nullptr && entry->name.bufSize > 0) {
        const char* name = "mock.bundle";
        size_t copySize = std::min(strlen(name), static_cast<size_t>(entry->name.bufSize - 1));
        (void)memcpy_s(entry->name.buf, copySize, name, copySize);
        entry->name.buf[copySize] = '\0';
    }

    return 0;
}

int SpmRemoveEntry(uint32_t tokenid)
{
    auto& state = GetFakeSpmKernelState();
    state.removeCallCount++;
    state.removedTokenIds.emplace_back(tokenid);
    return state.removeRet;
}

int SpmIncUidRefCnt(uint32_t uid, uint32_t spawnid)
{
    (void)uid;
    (void)spawnid;
    return 0;
}

int SpmDecUidRefCnt(uint32_t uid, uint32_t spawnid)
{
    (void)uid;
    (void)spawnid;
    return 0;
}

int SpmGetUidRefCnt(uint32_t uid, uint64_t *refcnt)
{
    (void)uid;
    if (refcnt != nullptr) {
        *refcnt = 0;
    }
    return 0;
}

int SpmIncTokenidRefCnt(uint32_t tokenid, uint32_t spawnid)
{
    (void)tokenid;
    (void)spawnid;
    return 0;
}

int SpmDecTokenidRefCnt(uint32_t tokenid, uint32_t spawnid)
{
    (void)tokenid;
    (void)spawnid;
    return 0;
}

int SpmGetTokenidRefCnt(uint32_t tokenid, uint64_t *refcnt)
{
    (void)tokenid;
    if (refcnt != nullptr) {
        *refcnt = 0;
    }
    return 0;
}

int SpmGetVersion(uint32_t *version)
{
    if (version != nullptr) {
        *version = 1;
    }
    return 0;
}

int SpmClearSpawnidRefCnt(uint32_t spawnid)
{
    (void)spawnid;
    return 0;
}

SpmData* SpmDataNew(uint32_t permBufSize, uint32_t extendPermBufSize, uint32_t nameBufSize)
{
    SpmData* data = (SpmData*)calloc(1, sizeof(SpmData));
    if (data == NULL) {
        return nullptr;
    }

    if (permBufSize > 0) {
        data->perms.buf = (char*)calloc(permBufSize, 1);
        if (data->perms.buf == NULL) {
            SpmDataFree(data);
            return nullptr;
        }
        data->perms.bufSize = permBufSize;
    }

    if (extendPermBufSize > 0) {
        data->extendPerms.buf = (char*)calloc(extendPermBufSize, 1);
        if (data->extendPerms.buf == NULL) {
            SpmDataFree(data);
            return nullptr;
        }
        data->extendPerms.bufSize = extendPermBufSize;
    }

    if (nameBufSize > 0) {
        data->name.buf = (char*)calloc(nameBufSize, 1);
        if (data->name.buf == NULL) {
            SpmDataFree(data);
            return nullptr;
        }
        data->name.bufSize = nameBufSize;
    }

    return data;
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
}
