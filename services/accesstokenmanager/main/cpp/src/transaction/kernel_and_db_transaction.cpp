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

#include "kernel_and_db_transaction.h"

#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "hisysevent_adapter.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

KernelAndDBWriteTransaction::KernelAndDBWriteTransaction()
{
    if (IsKernelAndDBWriteHeldByCurrentThread()) {
        // Nested construction is a guard violation: the nested instance joins
        // the outer transaction as a hang-safe fallback (no isolation of its
        // own), reported like any other bypass of the transaction guard.
        ReportKernelAndDBGuardViolation("nested KernelAndDBWriteTransaction");
        return;
    }
    lock_ = std::unique_lock<std::shared_mutex>(KernelAndDBLock::Get());
    KernelAndDBDetail::EnterWrite();
}

KernelAndDBWriteTransaction::~KernelAndDBWriteTransaction()
{
    if (!committed_ && !rolledBack_) {
        // RAII compensation: unified fallback for early returns and failures.
        RollbackInternal();
    }
    if (lock_.owns_lock()) {
        // Clear the guard flag before member destruction releases the lock.
        KernelAndDBDetail::ExitWrite();
    }
}

int32_t KernelAndDBWriteTransaction::StageKernelAdd(const std::vector<SpmDataParam>& params)
{
    if (committed_ || rolledBack_ || addTask_ != nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "StageKernelAdd rejected, invalid transaction state.");
        return ERR_PARAM_INVALID;
    }
    addTask_ = std::make_shared<AddSpmDataTask>(params);
    uint32_t errIndex = 0;
    int32_t ret = addTask_->Add(errIndex);
    if (ret != RET_SUCCESS) {
        // Add() self-rolled-back, nothing left to compensate.
        addTask_ = nullptr;
        return ret;
    }
    addSucceeded_ = true;
    return RET_SUCCESS;
}

int32_t KernelAndDBWriteTransaction::StageKernelUpdate(const std::vector<SpmDataParam>& params)
{
    if (committed_ || rolledBack_ || updateTask_ != nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "StageKernelUpdate rejected, invalid transaction state.");
        return ERR_PARAM_INVALID;
    }
    updateTask_ = std::make_shared<UpdateSpmDataTask>(params);
    uint32_t errIndex = 0;
    int32_t ret = updateTask_->Update(errIndex);
    if (ret != RET_SUCCESS) {
        // Update() self-rolled-back, nothing left to compensate.
        updateTask_ = nullptr;
        return ret;
    }
    updateSucceeded_ = true;
    return RET_SUCCESS;
}

int32_t KernelAndDBWriteTransaction::StageKernelRemove(const std::vector<RemoveSpmDataParam>& params)
{
    if (committed_ || rolledBack_ || removeTask_ != nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "StageKernelRemove rejected, invalid transaction state.");
        return ERR_PARAM_INVALID;
    }
    if (params.empty()) {
        // Empty list: no task, treat as success (decision table).
        return RET_SUCCESS;
    }
    removeTask_ = std::make_shared<RemoveSpmDataTask>(params);
    uint32_t errIndex = 0;
    int32_t ret = removeTask_->Remove(errIndex);
    if (ret != RET_SUCCESS) {
        // Nothing was removed (build failure), nothing left to compensate.
        removeTask_ = nullptr;
        return ret;
    }
    removeSucceeded_ = true;
    return RET_SUCCESS;
}

int32_t KernelAndDBWriteTransaction::CommitDb(const std::vector<DelInfo>& delInfoVec,
    const std::vector<AddInfo>& addInfoVec)
{
    if (committed_ || rolledBack_) {
        LOGE(ATM_DOMAIN, ATM_TAG, "CommitDb rejected, invalid transaction state.");
        return ERR_PARAM_INVALID;
    }
    int32_t ret = AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec);
    if (ret != RET_SUCCESS) {
        // Poison: Commit() is rejected from now on and the destructor still
        // compensates, so the failure cannot be whitewashed into a commit.
        dbFailed_ = true;
        LOGE(ATM_DOMAIN, ATM_TAG, "DeleteAndInsertValues failed, ret=%{public}d.", ret);
        return ERR_DATABASE_OPERATE_FAILED;
    }
    return RET_SUCCESS;
}

void KernelAndDBWriteTransaction::Commit()
{
    if (dbFailed_) {
        ReportKernelAndDBGuardViolation("Commit after unchecked CommitDb failure");
        return; // committed_ stays false: the destructor still compensates (fail-safe)
    }
    committed_ = true;
}

int32_t KernelAndDBWriteTransaction::Abort()
{
    if (committed_ || rolledBack_) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Abort rejected, invalid transaction state.");
        return ERR_PARAM_INVALID;
    }
    RollbackInternal();
    rolledBack_ = true;
    return RET_SUCCESS;
}

void KernelAndDBWriteTransaction::RollbackInternal()
{
    int32_t failCount = 0;
    // Order aligned with the install add -> update sequence; the remove
    // compensation runs last because it restores the pre-transaction world.
    if (addTask_ != nullptr && addSucceeded_ && addTask_->Rollback() != RET_SUCCESS) {
        failCount++;
    }
    if (updateTask_ != nullptr && updateSucceeded_ && updateTask_->Rollback() != RET_SUCCESS) {
        failCount++;
    }
    if (removeTask_ != nullptr && removeSucceeded_ && removeTask_->Rollback() != RET_SUCCESS) {
        failCount++;
    }
    if (failCount > 0) {
        // Compensation failures are evented, not retried (avoid rollback storms);
        // restart reconciliation is the final fallback.
        LOGE(ATM_DOMAIN, ATM_TAG, "KernelAndDB rollback failed, count=%{public}d.", failCount);
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
