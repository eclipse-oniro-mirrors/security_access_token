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

#ifndef ACCESSTOKEN_FILE_UTIL_H
#define ACCESSTOKEN_FILE_UTIL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * Atomically write data to a file with backup and metadata preservation.
 *
 * The write follows an 11-step sequence:
 *   1. Construct .new path, unlink stale .new if present.
 *   2. open(.new) -> write -> fsync -> close. Failure aborts.
 *   3. chown .new to parent dir uid/gid (best-effort).
 *   4. Restorecon .new (best-effort, SELinux only).
 *   5. rename .new -> filePath. FATAL on failure (data not committed).
 *   6. fsync parent directory (best-effort).
 *   7. Restorecon filePath (best-effort, SELinux only).
 *   8. Copy filePath -> backup (best-effort).
 *   9. chown backup to parent dir uid/gid (best-effort).
 *  10. Restorecon backup (best-effort, SELinux only).
 *  11. Return 0 (success).
 *
 * After step 5 succeeds, data is committed; steps 6-10 are best-effort
 * and failures only produce LOGE, never change the return value.
 *
 * @param filePath Target file path (must not be NULL).
 * @param data     Data buffer to write (must not be NULL when dataLen > 0).
 * @param dataLen  Number of bytes to write.
 * @param mode     File permission mode for created files (e.g. 0600).
 * @return 0 on success, non-zero on failure before data commit.
 */
int32_t AtomicWriteFile(const char* filePath, const char* data, size_t dataLen, int32_t mode);

/**
 * Construct the backup sibling path for a given file path.
 *
 * @param filePath  Source path (must not be NULL).
 * @param bakPath   Output buffer for backup path (must not be NULL).
 * @param bakPathLen Size of bakPath buffer including NUL terminator.
 * @return 0 on success, non-zero if output would be truncated.
 */
int32_t GetBakFilePath(const char* filePath, char* bakPath, size_t bakPathLen);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif // ACCESSTOKEN_FILE_UTIL_H
