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

#ifndef SPM_SETPROC_H
#define SPM_SETPROC_H
#include <stdint.h>
#include "setproc_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Buffer descriptor used to pass variable-length data to/from kernel SPM ioctls.
 *        Caller allocates buf and sets bufSize before the call; kernel writes up to bufSize
 *        bytes into buf and may update bufSize to indicate the actual data length.
 */
typedef struct {
    char *buf;        /**< Pointer to the data buffer. */
    uint32_t bufSize; /**< Size of buf in bytes. */
} SpmBlob;

/**
 * @brief Describes a single SPM (Signed Permission Monitor) entry that maps a process identity
 *        to its permission policy in the kernel.
 */
typedef struct {
    uint32_t uid;
    uint32_t tokenid;
    uint32_t tokenidAttr;
    uint32_t index;
    uint16_t apl;
    uint16_t distributionType;
    uint32_t idType;
    uint64_t ownerid;
    SpmBlob name;
    SpmBlob perms;
    SpmBlob extendPerms;
} SpmData;

/**
 * @brief Parsed view of one external permission item in extendPerms.
 *        TransferSpmExternPerms parses the raw blob as repeated
 *        `[uint32_t code][uint32_t valueSize][value bytes]` records and fills this structure.
 *        `value` points into the caller-provided `SpmBlob::buf`, so it is only valid while that
 *        buffer remains alive.
 */
typedef struct {
    uint32_t code; /**< Permission opcode. */
    char *value;   /**< Pointer to the value bytes of this permission item in the raw blob buffer. */
} PermsWithValue;

/**
 * @brief Batch add SPM entries to kernel.
 * @param entries Array of SpmData to add. Each element's name.buf must be valid.
 * @param cnt Number of entries. Auto-batched if > SPM_DATA_BATCH_SIZE.
 * @param idxErr Output: global index of first failed entry on error.
 * @return 0 on success; -EINVAL if entries/idxErr NULL or name.buf NULL;
 *         EEXIST if entry conflicts (caller should handle: skip/overwrite/error);
 *         ENOTSUP if kernel doesn't support this CMD (caller should handle).
 */
int SpmAddEntries(SpmData **entries, uint8_t cnt, uint8_t *idxErr);

/**
 * @brief Batch update SPM entries in kernel. uid field is passed to the kernel but uid updates
 *        are not processed by the kernel; the kernel ignores uid changes silently.
 * @param entries Array of SpmData to update. Each element's name.buf must be valid.
 * @param cnt Number of entries. Auto-batched if > SPM_DATA_BATCH_SIZE.
 * @param idxErr Output: global index of first failed entry on error.
 * @return 0 on success; -EINVAL if entries/idxErr NULL or name.buf NULL;
 *         ENOTSUP if kernel doesn't support this CMD (caller should handle).
 */
int SpmSetEntries(SpmData **entries, uint8_t cnt, uint8_t *idxErr);

/**
 * @brief Query SPM entry by tokenid.
 * @param tokenid Target tokenid.
 * @param entry Output: caller must set name.buf/name.bufSize before call. If perms.buf or
 *        extendPerms.buf is provided, the caller should also set the corresponding bufSize so
 *        kernel can write back the full entry payload.
 * @return 0 on success; -EINVAL if entry/name.buf NULL;
 *         ENOTSUP if kernel doesn't support this CMD (caller should handle).
 */
int SpmGetEntry(uint32_t tokenid, SpmData *entry);

/**
 * @brief Remove SPM entry by tokenid.
 * @param tokenid Target tokenid.
 * @return 0 on success; ENOTSUP if kernel doesn't support this CMD (caller should handle).
 */
int SpmRemoveEntry(uint32_t tokenid);

/**
 * @brief Increment uid active process refcount.
 * @param uid Target uid.
 * @param spawnid Spawn ID of the process being tracked.
 * @return 0 on success; ENOTSUP if kernel doesn't support this CMD (caller should handle).
 */
int SpmIncUidRefCnt(uint32_t uid, uint32_t spawnid);

/**
 * @brief Decrement uid active process refcount.
 * @param uid Target uid.
 * @param spawnid Spawn ID of the process being tracked.
 * @return 0 on success; ENOTSUP if kernel doesn't support this CMD (caller should handle).
 */
int SpmDecUidRefCnt(uint32_t uid, uint32_t spawnid);

/**
 * @brief Get uid active process refcount.
 * @param uid Target uid.
 * @param refcnt Output: refcount value.
 * @return 0 on success; ENOTSUP if kernel doesn't support this CMD (caller should handle).
 */
int SpmGetUidRefCnt(uint32_t uid, uint64_t *refcnt);

/**
 * @brief Increment tokenid active process refcount.
 * @param tokenid Target tokenid.
 * @param spawnid Spawn ID of the process being tracked.
 * @return 0 on success; ENOTSUP if kernel doesn't support this CMD (caller should handle).
 */
int SpmIncTokenidRefCnt(uint32_t tokenid, uint32_t spawnid);

/**
 * @brief Decrement tokenid active process refcount.
 * @param tokenid Target tokenid.
 * @param spawnid Spawn ID of the process being tracked.
 * @return 0 on success; ENOTSUP if kernel doesn't support this CMD (caller should handle).
 */
int SpmDecTokenidRefCnt(uint32_t tokenid, uint32_t spawnid);

/**
 * @brief Get tokenid active process refcount.
 * @param tokenid Target tokenid.
 * @param refcnt Output: refcount value.
 * @return 0 on success; ENOTSUP if kernel doesn't support this CMD (caller should handle).
 */
int SpmGetTokenidRefCnt(uint32_t tokenid, uint64_t *refcnt);

/**
 * @brief Clear spawnid refcount.
 * @param spawnid Target spawnid.
 * @return 0 on success; ENOTSUP if kernel doesn't support this CMD (caller should handle).
 */
int SpmClearSpawnidRefCnt(uint32_t spawnid);

/**
 * @brief Get SPM kernel feature version. Initial version is 1.
 * @param version Output: version number.
 * @return 0 on success; ENOTSUP if kernel doesn't support this CMD (caller should handle).
 */
int SpmGetVersion(uint32_t *version);

/**
 * @brief Allocate and zero-init SpmData with SpmBlob buffers.
 * @param permBufSize Size for perms.buf (0 means no allocation).
 * @param extendPermBufSize Size for extendPerms.buf (0 means no allocation).
 * @param nameBufSize Size for name.buf (0 means no allocation).
 * @return Pointer to new SpmData; NULL on failure (no memory leak).
 */
SpmData *SpmDataNew(uint32_t permBufSize, uint32_t extendPermBufSize, uint32_t nameBufSize);

/**
 * @brief Free SpmData allocated by SpmDataNew and its internal buffers.
 * @param data SpmData to free. NULL is safe (no-op).
 */
void SpmDataFree(SpmData *data);

/**
 * @brief Parse the extendPerms buffer in SpmBlob.
 *        The buffer layout is [permCode(uint32_t)][valueSize(uint32_t)][value bytes with trailing '\0')]...
 * @param data Input blob containing extended permission buffer.
 * @param valueList Caller-allocated output array.
 * @param listSize Input: valueList capacity. Output: actual parsed item count.
 * @return ACCESS_TOKEN_OK on success; ACCESS_TOKEN_PARAM_INVALID on invalid args; ERANGE if capacity is insufficient.
 */
int32_t TransferSpmExternPerms(SpmBlob *data, PermsWithValue *valueList, uint32_t *listSize);

#ifdef __cplusplus
}
#endif

#endif
