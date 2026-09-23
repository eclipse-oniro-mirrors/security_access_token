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

#ifndef REMOVE_SPM_DATA_TASK_H
#define REMOVE_SPM_DATA_TASK_H

#include <vector>

#include "access_token.h"
#include "spm_data_kernel_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * Caller-owned removal request, mirroring the SpmDataParam contract of
 * Add/UpdateSpmDataTask: oldPermBriefDataList points to a caller-owned
 * granted-permission list (e.g. the PermissionDataBrief view of the token)
 * and must stay alive from task construction until Remove()/Rollback()
 * completes (nullptr or empty = nothing to restore).
 */
struct RemoveSpmDataParam final {
    AccessTokenID tokenId = INVALID_TOKENID;
    const std::vector<BriefPermData>* oldPermBriefDataList = nullptr;
};

/**
 * Kernel removal task, symmetric to Add/UpdateSpmDataTask: the constructor
 * only validates the params, Remove() captures the old spm entries and then
 * deletes both kernel objects best-effort, and Rollback() restores the
 * removed entries per kernel object in reverse order.
 *
 * Old-value sources are split like UpdateSpmDataTask: the spm entry is
 * captured inside Remove() (ENODATA tolerant, SPM-gated), while the old
 * permission list is the caller-provided RemoveSpmDataParam::oldPermBriefDataList,
 * restored through the fixed AddHapPermToKernel(BriefPermDataList) overload -
 * the same path as UpdateSpmDataTask::RollbackPermData. That overload filters
 * granted entries and delegates to the real-return-code opCodeList path.
 */
class RemoveSpmDataTask final {
public:
    /**
     * Validate the params (non-empty, at most MAX_ENTRY_NUM entries) and
     * record the SPM support flag. No kernel reads happen here: the spm
     * entries are captured at the beginning of Remove().
     */
    explicit RemoveSpmDataTask(const std::vector<RemoveSpmDataParam>& params);
    ~RemoveSpmDataTask();

    RemoveSpmDataTask(const RemoveSpmDataTask&) = delete;
    RemoveSpmDataTask& operator=(const RemoveSpmDataTask&) = delete;
    RemoveSpmDataTask(RemoveSpmDataTask&&) = delete;
    RemoveSpmDataTask& operator=(RemoveSpmDataTask&&) = delete;

    /**
     * Capture the current spm entry of every token, then remove the spm
     * entries and permission data from the kernel. Best-effort: single
     * failures do not abort the loop (legacy delete semantics), the first
     * failure is reported through errIndex. Tokens whose entry capture fails
     * stay deletable but are no longer entry-compensable.
     *
     * @param errIndex Output. Index of the first failed entry on failure;
     *                 stays at the item count when no failure occurred
     *                 (distinguishes "no failure" from "failure at index 0").
     * @return RET_SUCCESS on success (including best-effort partial failures),
     *         ERR_PARAM_INVALID when the task was not built successfully.
     */
    int32_t Remove(uint32_t& errIndex);

    /**
     * Rollback removed entries by restoring the spm entries captured at the
     * beginning of Remove() and the caller-provided old permission list
     * (through the fixed BriefPermDataList overload, same as
     * UpdateSpmDataTask), in reverse order (restore the pre-transaction
     * world). Compensation is tracked per kernel object: only the perm
     * bitmap / spm entry whose removal succeeded is restored - a failed
     * removal leaves the object in the kernel, so restoring it is neither
     * needed nor correct.
     *
     * @return RET_SUCCESS on success, the first error code otherwise.
     */
    int32_t Rollback();

private:
    struct Item final {
        AccessTokenID tokenId = INVALID_TOKENID;
        // nullptr = no entry or capture failed, skip restore
        SpmDataPtr oldSpmData;
        // caller-owned, nullptr/empty = nothing to restore
        const std::vector<BriefPermData>* oldPermBriefDataList = nullptr;
        // perm bitmap removal succeeded: participates in perm compensation
        bool permRemoved = false;
        // spm entry removal succeeded: participates in entry compensation
        bool spmEntryRemoved = false;
    };

    void LoadOldSpmEntries();

    std::vector<Item> items_;
    bool isBuildSuccess_ = false;
    bool isSpmSupport_ = false;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // REMOVE_SPM_DATA_TASK_H
