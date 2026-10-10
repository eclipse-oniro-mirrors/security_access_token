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

#ifndef ACCESS_TOKEN_KERNEL_AND_DB_TRANSACTION_H
#define ACCESS_TOKEN_KERNEL_AND_DB_TRANSACTION_H

#include <memory>
#include <shared_mutex>
#include <vector>

#include "access_token.h"
#include "add_spm_data_task.h"
#include "atm_data_type.h"
#include "kernel_and_db_lock.h"
#include "remove_spm_data_task.h"
#include "update_spm_data_task.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

/**
 * Serializes the kernel -> database -> cache write sequence of a single business
 * operation and provides RAII compensation for the kernel stage.
 *
 * Usage (must be the outermost lock; cacheMutex_/verifyMutex_ must NOT be held):
 *   KernelAndDBWriteTransaction txn;
 *   txn.StageKernelRemove({ id });              // Phase 1: kernel mutation
 *   txn.CommitDb(delInfoVec, addInfoVec);       // Phase 2: database commit
 *   CommitDeleteHapCache(...);                  // Phase 3: caller-side cache commit
 *   txn.Commit();                               // mark success, destructor keeps everything
 * Any early return triggers the destructor rollback (add -> update -> remove).
 *
 * Nested construction is a guard violation: a nested instance joins the outer
 * transaction as a hang-safe fallback (it owns neither the lock nor the guard
 * flag) but provides no isolation of its own, so it is reported through
 * ReportKernelAndDBGuardViolation (test builds abort). A flow that needs
 * several kernel stages must stage them on a single transaction instead of
 * nesting transactions.
 *
 * Placement constraint (do NOT "tidy up"):
 * transaction/ is the only layer allowed to depend on both kernel/ and database/.
 * KernelAndDBLock stays in kernel/ because KernelDetail guard assertions live
 * there; moving it here would create a directory cycle.
 */
class KernelAndDBWriteTransaction final {
public:
    KernelAndDBWriteTransaction();
    ~KernelAndDBWriteTransaction();

    KernelAndDBWriteTransaction(const KernelAndDBWriteTransaction&) = delete;
    KernelAndDBWriteTransaction& operator=(const KernelAndDBWriteTransaction&) = delete;
    KernelAndDBWriteTransaction(KernelAndDBWriteTransaction&&) = delete;
    KernelAndDBWriteTransaction& operator=(KernelAndDBWriteTransaction&&) = delete;

    /**
     * Phase 1: stage a kernel add. At most one add per transaction.
     * @return RET_SUCCESS on success, error code otherwise (task self-rolled-back).
     */
    int32_t StageKernelAdd(const std::vector<SpmDataParam>& params);

    /**
     * Phase 1: stage a kernel update. At most one update per transaction.
     * @return RET_SUCCESS on success, error code otherwise (task self-rolled-back).
     */
    int32_t StageKernelUpdate(const std::vector<SpmDataParam>& params);

    /**
     * Phase 1: stage a kernel remove. The spm entries are captured at the
     * beginning of the removal (ENODATA tolerant), while the old permission
     * opcodes are caller-provided through the params, mirroring
     * SpmDataParam::oldPermBriefDataList (the caller usually holds the
     * DB-truth granted list already, so the task avoids a redundant kernel
     * perm query).
     * At most one remove per transaction; an empty params list is a no-op.
     * @return RET_SUCCESS on success, error code otherwise.
     */
    int32_t StageKernelRemove(const std::vector<RemoveSpmDataParam>& params);

    /**
     * Phase 2: pure database commit without callbacks. All database operations
     * of one logical change (including conditional cleanups) must be merged
     * into a single call: one call is one DB transaction, and on failure the
     * DB is atomically untouched, so the destructor compensation restores full
     * consistency. Multiple calls are only acceptable when an early failure is
     * fatal anyway and partial DB success can be tolerated (DB commits are
     * irreversible; the caller owns that trade-off).
     * A failure poisons the transaction: later Commit() calls are rejected and
     * the destructor still compensates, so an unchecked CommitDb failure can
     * never be whitewashed into a commit.
     * @return RET_SUCCESS on success, ERR_DATABASE_OPERATE_FAILED otherwise.
     */
    int32_t CommitDb(const std::vector<DelInfo>& delInfoVec, const std::vector<AddInfo>& addInfoVec);

    /**
     * Phase 3: mark the whole sequence successful, destructor keeps everything.
     * Rejected with a guard violation report when a previous CommitDb call
     * failed and the failure was left unchecked; the destructor then still
     * compensates (fail-safe).
     */
    void Commit();

    /**
     * Explicit rollback (active path besides the destructor fallback).
     * @return RET_SUCCESS on success, ERR_PARAM_INVALID after Commit/Abort.
     */
    int32_t Abort();

private:
    void RollbackInternal();

    std::shared_ptr<AddSpmDataTask> addTask_;
    std::shared_ptr<UpdateSpmDataTask> updateTask_;
    std::shared_ptr<RemoveSpmDataTask> removeTask_;
    // Declared last: members are destroyed in reverse order, so the lock is
    // released first while the guard flag is already cleared in the destructor.
    std::unique_lock<std::shared_mutex> lock_;
    bool addSucceeded_ = false;
    bool updateSucceeded_ = false;
    bool removeSucceeded_ = false;
    bool dbFailed_ = false;
    bool committed_ = false;
    bool rolledBack_ = false;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_KERNEL_AND_DB_TRANSACTION_H
