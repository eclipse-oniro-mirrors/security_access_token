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

#ifndef ACCESS_TOKEN_KERNEL_AND_DB_LOCK_H
#define ACCESS_TOKEN_KERNEL_AND_DB_LOCK_H

#include <shared_mutex>

namespace OHOS {
namespace Security {
namespace AccessToken {

/**
 * Global exclusive lock serializing all kernel -> database -> cache write sequences.
 * It must be the outermost lock (L0) in the lock hierarchy and can only be acquired
 * by KernelAndDBWriteTransaction construction points.
 *
 * Placement constraint (do NOT "tidy up"):
 * This header must stay in kernel/ (or lower). The guard assertions are embedded in
 * KernelDetail (kernel/) and reference this header, while the transaction layer
 * (transaction/) references kernel/ tasks. Moving this lock to transaction/ would
 * create a directory cycle kernel/ -> transaction/ -> kernel/.
 */
class KernelAndDBLock final {
public:
    KernelAndDBLock() = delete;
    ~KernelAndDBLock() = delete;

    static std::shared_mutex& Get();
};

/** Whether current thread holds the kernel+db write guard (i.e. runs inside a transaction). */
bool IsKernelAndDBWriteHeldByCurrentThread();

/**
 * Report a guard violation: a kernel mutation entry point was reached outside any
 * KernelAndDBWriteTransaction. Logs a critical error and aborts in test builds.
 *
 * @param apiName Name of the violated entry point.
 */
void ReportKernelAndDBGuardViolation(const char* apiName);

namespace KernelAndDBDetail {
/** Increment the per-thread write guard depth. Only called by the transaction ctor. */
void EnterWrite();

/** Decrement the per-thread write guard depth. Only called by the transaction dtor. */
void ExitWrite();
} // namespace KernelAndDBDetail
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_KERNEL_AND_DB_LOCK_H
