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

#include "fake_parent_hap_tokenid.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#if __has_include(<sys/fdsan.h>)
#include <sys/fdsan.h>
#endif

#include "securec.h"
#include "spm_setproc.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr uint32_t INVAL_TOKEN_ID = 0;
constexpr int32_t RET_FAILED = -1;
constexpr uint32_t MOCK_UID = 20100000;
constexpr uint32_t MOCK_ID_TYPE = 2;

#define ACCESS_TOKENID_GET_TOKENID \
    _IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_TOKEN_ID, uint64_t)
#define ACCESS_TOKENID_SET_TOKENID \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_TOKEN_ID, uint64_t)
#define ACCESS_TOKENID_GET_FTOKENID \
    _IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_FTOKEN_ID, uint64_t)
#define ACCESS_TOKENID_SET_FTOKENID \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_FTOKEN_ID, uint64_t)
}

FakeParentHapTokenIdState g_fakeParentHapTokenIdState;

FakeParentHapTokenIdState& GetFakeParentHapTokenIdState()
{
    return g_fakeParentHapTokenIdState;
}

void ResetFakeParentHapTokenIdState()
{
    g_fakeParentHapTokenIdState = {};
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

using OHOS::Security::AccessToken::GetFakeParentHapTokenIdState;
using OHOS::Security::AccessToken::INVAL_TOKEN_ID;
using OHOS::Security::AccessToken::RET_FAILED;
using OHOS::Security::AccessToken::MOCK_UID;
using OHOS::Security::AccessToken::MOCK_ID_TYPE;

extern "C" int32_t GetParentHapTokenID(uint32_t bin, uint64_t *parent)
{
    if (bin == INVAL_TOKEN_ID || parent == nullptr) {
        return ACCESS_TOKEN_PARAM_INVALID;
    }

    auto& state = OHOS::Security::AccessToken::GetFakeParentHapTokenIdState();
    state.callCount++;
    state.lastBinTokenID = bin;
    if (state.ret == ACCESS_TOKEN_OK) {
        *parent = state.parentHapTokenID;
    }
    return state.ret;
}

extern "C" uint64_t GetSelfTokenID(void)
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

extern "C" int SetSelfTokenID(uint64_t tokenID)
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
    OHOS::Security::AccessToken::GetFakeParentHapTokenIdState().selfTokenID = tokenID;
    return ACCESS_TOKEN_OK;
}

extern "C" uint64_t GetFirstCallerTokenID(void)
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

extern "C" int SetFirstCallerTokenID(uint64_t tokenID)
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
    OHOS::Security::AccessToken::GetFakeParentHapTokenIdState().firstCallerTokenID = tokenID;
    return ACCESS_TOKEN_OK;
}

extern "C" int SpmAddEntries(SpmData **entries, uint8_t cnt, uint8_t *idxErr)
{
    (void)entries;
    (void)cnt;
    if (idxErr != nullptr) {
        *idxErr = 0;
    }
    return ACCESS_TOKEN_OK;
}

extern "C" int SpmSetEntries(SpmData **entries, uint8_t cnt, uint8_t *idxErr)
{
    (void)entries;
    (void)cnt;
    if (idxErr != nullptr) {
        *idxErr = 0;
    }
    return ACCESS_TOKEN_OK;
}

extern "C" int SpmGetEntry(uint32_t tokenid, SpmData *entry)
{
    if (entry == nullptr) {
        return RET_FAILED;
    }

    entry->uid = MOCK_UID;
    entry->tokenid = tokenid;
    entry->tokenidAttr = 0;
    entry->index = 0;
    entry->apl = 0;
    entry->distributionType = 0;
    entry->idType = MOCK_ID_TYPE;
    entry->ownerid = 1;

    if (entry->perms.buf != nullptr && entry->perms.bufSize > 0) {
        (void)memset_s(entry->perms.buf, entry->perms.bufSize, 0, entry->perms.bufSize);
    }
    if (entry->extendPerms.buf != nullptr) {
        entry->extendPerms.bufSize = 0;
    }
    if (entry->name.buf != nullptr && entry->name.bufSize > 0) {
        const char* name = "mock.bundle";
        size_t copySize = std::min(strlen(name), static_cast<size_t>(entry->name.bufSize - 1));
        (void)memcpy_s(entry->name.buf, entry->name.bufSize, name, copySize);
        entry->name.buf[copySize] = '\0';
    }
    return ACCESS_TOKEN_OK;
}

extern "C" int SpmRemoveEntry(uint32_t tokenid)
{
    (void)tokenid;
    return ACCESS_TOKEN_OK;
}

extern "C" int SpmIncUidRefCnt(uint32_t uid, uint32_t spawnid)
{
    (void)uid;
    (void)spawnid;
    return ACCESS_TOKEN_OK;
}

extern "C" int SpmDecUidRefCnt(uint32_t uid, uint32_t spawnid)
{
    (void)uid;
    (void)spawnid;
    return ACCESS_TOKEN_OK;
}

extern "C" int SpmGetUidRefCnt(uint32_t uid, uint64_t *refcnt)
{
    (void)uid;
    if (refcnt != nullptr) {
        *refcnt = 0;
    }
    return ACCESS_TOKEN_OK;
}

extern "C" int SpmIncTokenidRefCnt(uint32_t tokenid, uint32_t spawnid)
{
    (void)tokenid;
    (void)spawnid;
    return ACCESS_TOKEN_OK;
}

extern "C" int SpmDecTokenidRefCnt(uint32_t tokenid, uint32_t spawnid)
{
    (void)tokenid;
    (void)spawnid;
    return ACCESS_TOKEN_OK;
}

extern "C" int SpmGetTokenidRefCnt(uint32_t tokenid, uint64_t *refcnt)
{
    (void)tokenid;
    if (refcnt != nullptr) {
        *refcnt = 0;
    }
    return ACCESS_TOKEN_OK;
}

extern "C" int SpmClearSpawnidRefCnt(uint32_t spawnid)
{
    (void)spawnid;
    return ACCESS_TOKEN_OK;
}

extern "C" int SpmGetVersion(uint32_t *version)
{
    if (version != nullptr) {
        *version = 1;
    }
    return ACCESS_TOKEN_OK;
}

extern "C" SpmData* SpmDataNew(uint32_t permBufSize, uint32_t extendPermBufSize, uint32_t nameBufSize)
{
    SpmData* data = static_cast<SpmData*>(calloc(1, sizeof(SpmData)));
    if (data == nullptr) {
        return nullptr;
    }

    if (permBufSize > 0) {
        data->perms.buf = static_cast<char*>(calloc(permBufSize, 1));
        if (data->perms.buf == nullptr) {
            SpmDataFree(data);
            return nullptr;
        }
        data->perms.bufSize = permBufSize;
    }

    if (extendPermBufSize > 0) {
        data->extendPerms.buf = static_cast<char*>(calloc(extendPermBufSize, 1));
        if (data->extendPerms.buf == nullptr) {
            SpmDataFree(data);
            return nullptr;
        }
        data->extendPerms.bufSize = extendPermBufSize;
    }

    if (nameBufSize > 0) {
        data->name.buf = static_cast<char*>(calloc(nameBufSize, 1));
        if (data->name.buf == nullptr) {
            SpmDataFree(data);
            return nullptr;
        }
        data->name.bufSize = nameBufSize;
    }

    return data;
}

extern "C" void SpmDataFree(SpmData *data)
{
    if (data == nullptr) {
        return;
    }
    free(data->perms.buf);
    free(data->extendPerms.buf);
    free(data->name.buf);
    free(data);
}
