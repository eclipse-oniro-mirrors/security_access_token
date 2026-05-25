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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "securec.h"

#define INVAL_TOKEN_ID 0x0
#define TOKEN_ID_LOWMASK 0xffffffff

const uint64_t SET_SPM_FD_TAG = 0xD005A01;

#define ACCESS_TOKENID_ADD_SPM_ENTRIES _IOWR(ACCESS_TOKEN_ID_IOCTL_BASE, ADD_SPM_ENTRIES, struct IoctlSpmDataUpdate)
#define ACCESS_TOKENID_SET_SPM_ENTRIES _IOWR(ACCESS_TOKEN_ID_IOCTL_BASE, SET_SPM_ENTRIES, struct IoctlSpmDataUpdate)
#define ACCESS_TOKENID_GET_SPM_ENTRY _IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_SPM_ENTRY, struct IoctlSpmDataQuery)
#define ACCESS_TOKENID_REMOVE_SPM_ENTRY _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, REMOVE_SPM_ENTRY, uint32_t)
#define ACCESS_TOKENID_SET_REFCNT_UID _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_REFCNT_UID, struct IoctlSpmUidRefQuery)
#define ACCESS_TOKENID_GET_REFCNT_UID _IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_REFCNT_UID, struct IoctlSpmUidRef)
#define ACCESS_TOKENID_SET_REFCNT_TOKENID                                                                              \
    _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, SET_REFCNT_TOKENID, struct IoctlSpmTokenidRefQuery)
#define ACCESS_TOKENID_GET_REFCNT_TOKENID                                                                              \
    _IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_REFCNT_TOKENID, struct IoctlSpmTokenidRef)
#define ACCESS_TOKENID_CLEAR_REFCNT_SPAWNID _IOW(ACCESS_TOKEN_ID_IOCTL_BASE, CLEAR_REFCNT_SPAWNID, uint32_t)
#define ACCESS_TOKENID_GET_SPM_VERSION _IOR(ACCESS_TOKEN_ID_IOCTL_BASE, GET_SPM_VERSION, uint32_t)

#define SPM_REFCNT_OP_INC 1
#define SPM_REFCNT_OP_DEC 2
#define SPM_DATA_VERSION 1

struct IoctlSpmData {
    uint32_t version;
    uint32_t uid;
    uint32_t tokenid;
    uint32_t tokenidAttr;
    uint32_t index;
    uint32_t nameSize;
    uint64_t nameOffset;
    uint16_t apl;
    uint16_t distributionType;
    uint32_t idType;
    uint64_t ownerid;
    uint32_t permSize;
    uint32_t extendPermSize;
    uint64_t permsOffset;
    uint64_t extendPermsOffset;
    uint64_t contentPtr;
    uint32_t reserved[32]; // reserved for future use, should be set to 0
};

struct IoctlSpmDataUpdate {
    uint8_t cnt;
    uint8_t idxErr;
    struct IoctlSpmData entries[];
};

struct IoctlSpmDataQuery {
    uint32_t tokenid;
    struct IoctlSpmData entry;
    uint8_t buf[];
};

struct IoctlSpmUidRefQuery {
    uint8_t op;
    uint32_t uid;
    uint32_t spawnid;
};

struct IoctlSpmUidRef {
    uint32_t uid;
    uint64_t refcnt;
};

struct IoctlSpmTokenidRefQuery {
    uint8_t op;
    uint32_t tokenid;
    uint32_t spawnid;
};

struct IoctlSpmTokenidRef {
    uint32_t tokenid;
    uint64_t refcnt;
};

static void ConstructStaticKernelData(const SpmData* src, struct IoctlSpmData* dst, char* buf)
{
    dst->version = SPM_DATA_VERSION;
    dst->uid = src->uid;
    dst->tokenid = src->tokenid;
    dst->tokenidAttr = src->tokenidAttr;
    dst->index = src->index;
    dst->nameSize = src->name.bufSize;
    dst->nameOffset = 0;
    dst->apl = src->apl;
    dst->distributionType = src->distributionType;
    dst->idType = src->idType;
    dst->ownerid = src->ownerid;
    dst->permSize = src->perms.bufSize;
    dst->extendPermSize = src->extendPerms.bufSize;
    dst->permsOffset = src->name.bufSize;
    dst->extendPermsOffset = src->name.bufSize + src->perms.bufSize;
    dst->contentPtr = (uint64_t)(uintptr_t)buf;
    (void)memset_s(dst->reserved, sizeof(dst->reserved), 0, sizeof(dst->reserved));
}

static int SpmDataToKernel(const SpmData* src, struct IoctlSpmData* dst)
{
    uint32_t nameSize = src->name.bufSize;
    uint32_t permSize = src->perms.bufSize;
    uint32_t extPermSize = src->extendPerms.bufSize;
    uint64_t totalSize = (uint64_t)nameSize + permSize + extPermSize;
    if (totalSize > UINT32_MAX) {
        return ERANGE;
    }
    if (nameSize == 0 || permSize == 0 || src->name.buf == NULL || src->perms.buf == NULL) {
        return EINVAL;
    }

    char* combinedBuf = NULL;
    if (totalSize > 0) {
        combinedBuf = (char*)calloc(totalSize, 1);
        if (combinedBuf == NULL) {
            return ENOMEM;
        }
        int ret = EOK;
        ret = memcpy_s(combinedBuf, totalSize, src->name.buf, nameSize);
        if (ret != EOK) {
            free(combinedBuf);
            return ret;
        }
        ret = memcpy_s(combinedBuf + nameSize, permSize, src->perms.buf, permSize);
        if (ret != EOK) {
            free(combinedBuf);
            return ret;
        }
        if (extPermSize > 0 && src->extendPerms.buf != NULL) {
            ret = memcpy_s(combinedBuf + nameSize + permSize, extPermSize, src->extendPerms.buf, extPermSize);
            if (ret != EOK) {
                free(combinedBuf);
                return ret;
            }
        }
    }

    ConstructStaticKernelData(src, dst, combinedBuf);
    return ACCESS_TOKEN_OK;
}

static int SpmSubmitBatch(SpmData** entries, uint8_t batchCnt, struct IoctlSpmDataUpdate* batch, int fd, int cmd)
{
    for (uint8_t i = 0; i < batchCnt; ++i) {
        int ret = SpmDataToKernel(entries[i], &batch->entries[i]);
        if (ret != ACCESS_TOKEN_OK) {
            for (uint8_t j = 0; j < i; ++j) {
                free((void*)(uintptr_t)batch->entries[j].contentPtr);
                batch->entries[j].contentPtr = 0;
            }
            batch->idxErr = 0;
            return ret;
        }
    }
    batch->cnt = batchCnt;
    batch->idxErr = 0;
    int ret = ioctl(fd, cmd, batch);
    if (ret != 0) {
        ret = errno;
    }
    for (uint8_t i = 0; i < batchCnt; i++) {
        free((void*)(uintptr_t)batch->entries[i].contentPtr);
        batch->entries[i].contentPtr = 0;
    }
    return ret;
}

static int SpmBatchEntries(SpmData** entries, uint8_t cnt, uint8_t* idxErr, int cmd)
{
    if (entries == NULL || idxErr == NULL) {
        return EINVAL;
    }
    if (cnt == 0) {
        return ACCESS_TOKEN_OK;
    }
    for (uint8_t i = 0; i < cnt; i++) {
        if (entries[i] == NULL || entries[i]->name.buf == NULL) {
            return EINVAL;
        }
    }
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, SET_SPM_FD_TAG);
    uint8_t submitted = 0;
    int ret = 0;
    while (submitted < cnt) {
        uint8_t batchCnt = (cnt - submitted > SPM_DATA_BATCH_SIZE) ? SPM_DATA_BATCH_SIZE : (cnt - submitted);
        struct IoctlSpmDataUpdate* batch = (struct IoctlSpmDataUpdate*)calloc(
            1, sizeof(struct IoctlSpmDataUpdate) + batchCnt * sizeof(struct IoctlSpmData));
        if (batch == NULL) {
            ret = ENOMEM;
            *idxErr = submitted;
            break;
        }
        ret = SpmSubmitBatch(entries + submitted, batchCnt, batch, fd, cmd);
        if (ret != 0) {
            *idxErr = submitted + batch->idxErr;
            free((void*)batch);
            break;
        }
        submitted += batchCnt;
        free((void*)batch);
    }
    (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
    return ret;
}

int SpmAddEntries(SpmData** entries, uint8_t cnt, uint8_t* idxErr)
{
    return SpmBatchEntries(entries, cnt, idxErr, ACCESS_TOKENID_ADD_SPM_ENTRIES);
}

int SpmSetEntries(SpmData** entries, uint8_t cnt, uint8_t* idxErr)
{
    return SpmBatchEntries(entries, cnt, idxErr, ACCESS_TOKENID_SET_SPM_ENTRIES);
}

static struct IoctlSpmDataQuery* SpmSetupGetQuery(const SpmData* entry, uint32_t tokenid)
{
    uint32_t nameSize = entry->name.bufSize;
    uint32_t permSize = entry->perms.bufSize;
    uint32_t extPermSize = entry->extendPerms.bufSize;
    uint64_t totalSize = (uint64_t)nameSize + permSize + extPermSize;

    struct IoctlSpmDataQuery* query =
        (struct IoctlSpmDataQuery*)calloc(1, sizeof(struct IoctlSpmDataQuery) + totalSize);
    if (query == NULL) {
        return NULL;
    }
    query->tokenid = tokenid;
    query->entry.version = SPM_DATA_VERSION;
    query->entry.nameSize = nameSize;
    query->entry.nameOffset = 0;
    query->entry.permSize = permSize;
    query->entry.permsOffset = nameSize;
    query->entry.extendPermSize = extPermSize;
    query->entry.extendPermsOffset = (uint64_t)nameSize + permSize;
    query->entry.contentPtr = (uint64_t)(uintptr_t)query->buf;
    return query;
}

static int SpmCopyGetResult(SpmData* entry, const struct IoctlSpmDataQuery* query)
{
    uint32_t size = query->entry.nameSize;
    uint64_t offset = query->entry.nameOffset;
    int ret = memcpy_s(entry->name.buf, entry->name.bufSize, query->buf + offset, size);
    if (ret != EOK) {
        return ret;
    }
    size = query->entry.permSize;
    offset = query->entry.permsOffset;
    ret = memcpy_s(entry->perms.buf, entry->perms.bufSize, query->buf + offset, size);
    if (ret != EOK) {
        return ret;
    }
    entry->perms.bufSize = size;

    size = query->entry.extendPermSize;
    offset = query->entry.extendPermsOffset;
    ret = memcpy_s(entry->extendPerms.buf, entry->extendPerms.bufSize, query->buf + offset, size);
    if (ret != EOK) {
        return ret;
    }
    entry->extendPerms.bufSize = size;

    entry->uid = query->entry.uid;
    entry->tokenid = query->entry.tokenid;
    entry->tokenidAttr = query->entry.tokenidAttr;
    entry->index = query->entry.index;
    entry->apl = query->entry.apl;
    entry->distributionType = query->entry.distributionType;
    entry->idType = query->entry.idType;
    entry->ownerid = query->entry.ownerid;
    return ACCESS_TOKEN_OK;
}

int SpmGetEntry(uint32_t tokenid, SpmData* entry)
{
    if (entry == NULL || entry->name.buf == NULL || entry->perms.buf == NULL || entry->extendPerms.buf == NULL) {
        return EINVAL;
    }
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, SET_SPM_FD_TAG);
    struct IoctlSpmDataQuery* query = SpmSetupGetQuery(entry, tokenid);
    if (query == NULL) {
        (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
        return ENOMEM;
    }
    int ret = ioctl(fd, ACCESS_TOKENID_GET_SPM_ENTRY, query);
    if (ret != 0) {
        ret = errno;
    } else {
        ret = SpmCopyGetResult(entry, query);
    }
    free(query);
    (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
    return ret;
}

int SpmRemoveEntry(uint32_t tokenid)
{
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, SET_SPM_FD_TAG);

    int ret = ioctl(fd, ACCESS_TOKENID_REMOVE_SPM_ENTRY, &tokenid);
    if (ret != 0) {
        ret = errno;
        (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
        return ret;
    }

    (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
    return ACCESS_TOKEN_OK;
}

static int SpmSetUidRefCnt(uint32_t uid, uint32_t spawnid, int32_t opt)
{
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, SET_SPM_FD_TAG);

    struct IoctlSpmUidRefQuery query;
    query.op = (uint8_t)opt;
    query.uid = uid;
    query.spawnid = spawnid;
    int ret = ioctl(fd, ACCESS_TOKENID_SET_REFCNT_UID, &query);
    if (ret != 0) {
        ret = errno;
        (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
        return ret;
    }

    (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
    return ACCESS_TOKEN_OK;
}

int SpmIncUidRefCnt(uint32_t uid, uint32_t spawnid)
{
    return SpmSetUidRefCnt(uid, spawnid, SPM_REFCNT_OP_INC);
}

int SpmDecUidRefCnt(uint32_t uid, uint32_t spawnid)
{
    return SpmSetUidRefCnt(uid, spawnid, SPM_REFCNT_OP_DEC);
}

int SpmGetUidRefCnt(uint32_t uid, uint64_t* refcnt)
{
    if (refcnt == NULL) {
        return EINVAL;
    }

    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, SET_SPM_FD_TAG);

    struct IoctlSpmUidRef query;
    query.uid = uid;
    query.refcnt = 0;

    int ret = ioctl(fd, ACCESS_TOKENID_GET_REFCNT_UID, &query);
    if (ret != 0) {
        ret = errno;
        (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
        return ret;
    }

    *refcnt = query.refcnt;
    (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
    return ACCESS_TOKEN_OK;
}

static int SpmSetTokenidRefCnt(uint32_t tokenid, uint32_t spawnid, int32_t opt)
{
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, SET_SPM_FD_TAG);

    struct IoctlSpmTokenidRefQuery query;
    query.op = (uint8_t)opt;
    query.tokenid = tokenid;
    query.spawnid = spawnid;
    int ret = ioctl(fd, ACCESS_TOKENID_SET_REFCNT_TOKENID, &query);
    if (ret != 0) {
        ret = errno;
        (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
        return ret;
    }

    (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
    return ACCESS_TOKEN_OK;
}

int SpmIncTokenidRefCnt(uint32_t tokenid, uint32_t spawnid)
{
    return SpmSetTokenidRefCnt(tokenid, spawnid, SPM_REFCNT_OP_INC);
}

int SpmDecTokenidRefCnt(uint32_t tokenid, uint32_t spawnid)
{
    return SpmSetTokenidRefCnt(tokenid, spawnid, SPM_REFCNT_OP_DEC);
}

int SpmGetTokenidRefCnt(uint32_t tokenid, uint64_t* refcnt)
{
    if (refcnt == NULL) {
        return EINVAL;
    }

    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, SET_SPM_FD_TAG);

    struct IoctlSpmTokenidRef query;
    query.tokenid = tokenid;
    query.refcnt = 0;

    int ret = ioctl(fd, ACCESS_TOKENID_GET_REFCNT_TOKENID, &query);
    if (ret != 0) {
        ret = errno;
        (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
        return ret;
    }

    *refcnt = query.refcnt;
    (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
    return ACCESS_TOKEN_OK;
}

int SpmClearSpawnidRefCnt(uint32_t spawnid)
{
    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, SET_SPM_FD_TAG);

    int ret = ioctl(fd, ACCESS_TOKENID_CLEAR_REFCNT_SPAWNID, &spawnid);
    if (ret != 0) {
        ret = errno;
        (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
        return ret;
    }

    (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
    return ACCESS_TOKEN_OK;
}

int SpmGetVersion(uint32_t* version)
{
    if (version == NULL) {
        return EINVAL;
    }

    int fd = open(TOKENID_DEVNODE, O_RDWR);
    if (fd < 0) {
        return ACCESS_TOKEN_OPEN_ERROR;
    }
    fdsan_exchange_owner_tag(fd, 0, SET_SPM_FD_TAG);

    int ret = ioctl(fd, ACCESS_TOKENID_GET_SPM_VERSION, version);
    if (ret != 0) {
        *version = 0;
        ret = errno;
        (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
        return ret;
    }

    (void)fdsan_close_with_tag(fd, SET_SPM_FD_TAG);
    return ACCESS_TOKEN_OK;
}

SpmData* SpmDataNew(uint32_t permBufSize, uint32_t extendPermBufSize, uint32_t nameBufSize)
{
    SpmData* data = (SpmData*)calloc(1, sizeof(SpmData));
    if (data == NULL) {
        return NULL;
    }

    if (permBufSize > 0) {
        data->perms.buf = (char*)calloc(permBufSize, 1);
        if (data->perms.buf == NULL) {
            SpmDataFree(data);
            return NULL;
        }
        data->perms.bufSize = permBufSize;
    }

    if (extendPermBufSize > 0) {
        data->extendPerms.buf = (char*)calloc(extendPermBufSize, 1);
        if (data->extendPerms.buf == NULL) {
            SpmDataFree(data);
            return NULL;
        }
        data->extendPerms.bufSize = extendPermBufSize;
    }

    if (nameBufSize > 0) {
        data->name.buf = (char*)calloc(nameBufSize, 1);
        if (data->name.buf == NULL) {
            SpmDataFree(data);
            return NULL;
        }
        data->name.bufSize = nameBufSize;
    }

    return data;
}

void SpmDataFree(SpmData* data)
{
    if (data == NULL) {
        return;
    }
    free(data->perms.buf);
    free(data->extendPerms.buf);
    free(data->name.buf);
    free(data);
}

int32_t TransferSpmExternPerms(SpmBlob *data, PermsWithValue *valueList, uint32_t *listSize)
{
    int32_t codeValueSize = sizeof(uint32_t) * 2;
    if ((data == NULL) || (listSize == NULL) || (*listSize == 0) || (valueList == NULL)) {
        return ACCESS_TOKEN_PARAM_INVALID;
    }
    if (data->bufSize == 0) {
        *listSize = 0;
        return ACCESS_TOKEN_OK;
    }
    if ((data->bufSize <= codeValueSize) || ((data->bufSize > 0) && (data->buf == NULL))) {
        return ACCESS_TOKEN_PARAM_INVALID;
    }

    uint32_t capacity = *listSize;
    uint32_t outputSize = 0;
    uint32_t offset = 0;
    while (offset <= data->bufSize - codeValueSize) {
        uint32_t code = 0;
        uint32_t valueSize = 0;
        if (memcpy_s(&code, sizeof(code), data->buf + offset, sizeof(code)) != EOK) {
            return ACCESS_TOKEN_PARAM_INVALID;
        }
        offset += sizeof(uint32_t);
        if (memcpy_s(&valueSize, sizeof(valueSize), data->buf + offset, sizeof(valueSize)) != EOK) {
            return ACCESS_TOKEN_PARAM_INVALID;
        }
        offset += sizeof(uint32_t);

        if (valueSize > data->bufSize - offset) {
            return ACCESS_TOKEN_PARAM_INVALID;
        }
        if (outputSize < capacity) {
            valueList[outputSize].code = code;
            valueList[outputSize].value = data->buf + offset;
        }
        outputSize++;
        if (outputSize > capacity) {
            return ERANGE;
        }
        offset += valueSize;
    }

    *listSize = outputSize;
    if (offset != data->bufSize) {
        return ACCESS_TOKEN_PARAM_INVALID;
    }
    return ACCESS_TOKEN_OK;
}
