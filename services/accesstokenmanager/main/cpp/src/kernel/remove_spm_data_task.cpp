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

#include "remove_spm_data_task.h"

#include <algorithm>
#include <cstdint>
#include <utility>

#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "hisysevent_adapter.h"
#include "permission_kernel_utils.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t MAX_ENTRY_NUM = 255;
// batch count and idxErr of SPM entry ioctls are uint8_t, the limit must fit to avoid wraparound
static_assert(MAX_ENTRY_NUM <= UINT8_MAX, "MAX_ENTRY_NUM must fit in uint8_t");
} // namespace

RemoveSpmDataTask::RemoveSpmDataTask(const std::vector<RemoveSpmDataParam>& params)
{
    if (params.empty() || params.size() > MAX_ENTRY_NUM) {
        LOGE(ATM_DOMAIN, ATM_TAG, "RemoveSpmDataTask params invalid.");
        return;
    }
    isSpmSupport_ = PermissionKernelUtils::IsKernelSupportSpm();
    items_.reserve(params.size());
    for (const auto& param : params) {
        Item item;
        item.tokenId = param.tokenId;
        item.oldPermBriefDataList = param.oldPermBriefDataList;
        items_.emplace_back(std::move(item));
    }
    isBuildSuccess_ = true;
}

RemoveSpmDataTask::~RemoveSpmDataTask() = default;

void RemoveSpmDataTask::LoadOldSpmEntries()
{
    if (!isSpmSupport_) {
        return;
    }
    for (auto& item : items_) {
        int32_t ret = KernelDetail::LoadSpmDataFromKernel(item.tokenId, item.oldSpmData);
        if (ret != RET_SUCCESS) {
            item.oldSpmData.reset();
            if (ret == ERR_NO_DATA_FROM_KERNEL) {
                // ENODATA = kernel had no entry: nothing to restore on rollback;
                // other errors: the token stays deletable but is no longer compensable
                continue;
            }
            LOGC(ATM_DOMAIN, ATM_TAG,
                "Load spm data failed, token=%{public}u is not compensable, ret=%{public}d.",
                item.tokenId, ret);
            ReportSysCommonEventError(KERNEL_SPM_DATA_LOAD, ret);
        }
    }
}

int32_t RemoveSpmDataTask::Remove(uint32_t& errIndex)
{
    errIndex = 0;
    if (!isBuildSuccess_) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build remove spm data task failed.");
        return ERR_PARAM_INVALID;
    }

    LoadOldSpmEntries();

    errIndex = items_.size();
    for (size_t i = 0; i < items_.size(); ++i) {
        int32_t permRet = PermissionKernelUtils::RemovePermFromKernel(items_[i].tokenId);
        int32_t spmRet = RET_SUCCESS;
        if (isSpmSupport_) {
            spmRet = KernelDetail::RemoveSpmEntryFromKernel(items_[i].tokenId);
            if (spmRet == RET_SUCCESS) {
                items_[i].spmEntryRemoved = true;
            }
        }
        if (permRet == RET_SUCCESS) {
            items_[i].permRemoved = true;
        }
        if (permRet != RET_SUCCESS) {
            if (i < errIndex) {
                errIndex = static_cast<uint32_t>(i);
            }
            // Residue risk: the perm bitmap stays in the kernel after the DB
            // delete succeeds (compensable only while the transaction lives).
            LOGC(ATM_DOMAIN, ATM_TAG,
                "RemovePermFromKernel failed, tokenId=%{public}u, errIndex=%{public}u, ret=%{public}d.",
                items_[i].tokenId, errIndex, permRet);
            ReportSysCommonEventError(KERNEL_PERM_DATA_DELETE, permRet);
        }
        if (spmRet != RET_SUCCESS) {
            if (i < errIndex) {
                errIndex = static_cast<uint32_t>(i);
            }
            // Residue risk: the spm entry stays in the kernel after the DB
            // delete succeeds (compensable only while the transaction lives).
            LOGC(ATM_DOMAIN, ATM_TAG,
                "RemoveSpmEntryFromKernel failed, tokenId=%{public}u, errIndex=%{public}u, ret=%{public}d.",
                items_[i].tokenId, errIndex, spmRet);
            ReportSysCommonEventError(KERNEL_SPM_DATA_DELETE, spmRet);
        }
    }
    // Best-effort, aligned with the legacy delete semantics: single failures are
    // reported through errIndex but never abort the whole removal.
    return RET_SUCCESS;
}

static int32_t RestoreSpmEntries(std::vector<SpmData*>& entries)
{
    // Batch add, mirroring AddSpmDataTask::Add. EEXIST means the entry is
    // still present because the rollback already ran (a failed removal never
    // reaches here: spmEntryRemoved stays false): skip that entry and retry
    // the rest of the batch, keeping the restore idempotent.
    size_t offset = 0;
    while (offset < entries.size()) {
        std::vector<SpmData*> remaining(entries.begin() + offset, entries.end());
        uint8_t idxErr = 0;
        int32_t ret = KernelDetail::AddSpmEntriesToKernel(remaining, idxErr);
        if (ret == RET_SUCCESS) {
            return RET_SUCCESS;
        }
        if (ret == ERR_DATA_CONFLICT_WITH_KERNEL && idxErr < remaining.size()) {
            offset += static_cast<size_t>(idxErr) + 1; // skip the still-existing entry
            continue;
        }
        size_t failedIdx = std::min(static_cast<size_t>(idxErr), remaining.size() - 1);
        LOGC(ATM_DOMAIN, ATM_TAG,
            "Rollback AddSpmEntriesToKernel failed for token=%{public}u, ret=%{public}d.",
            entries[offset + failedIdx]->tokenid, ret);
        ReportSysCommonEventError(KERNEL_SPM_DATA_ROLLBACK, ret);
        return ret;
    }
    return RET_SUCCESS;
}

static int32_t RestorePermCodes(AccessTokenID tokenId, const std::vector<BriefPermData>* oldPermBriefDataList)
{
    if (oldPermBriefDataList == nullptr || oldPermBriefDataList->empty()) {
        return RET_SUCCESS;
    }
    // Same path as UpdateSpmDataTask::RollbackPermData: the fixed overload
    // filters granted entries and delegates to the real-return-code
    // opCodeList path (F3.3), so compensation failures stay visible.
    int32_t ret = PermissionKernelUtils::AddHapPermToKernel(tokenId, *oldPermBriefDataList);
    if (ret != RET_SUCCESS) {
        LOGC(ATM_DOMAIN, ATM_TAG,
            "Rollback AddHapPermToKernel failed for token=%{public}u, ret=%{public}d.", tokenId, ret);
        ReportSysCommonEventError(KERNEL_PERM_DATA_ROLLBACK, ret);
        return ret;
    }
    return RET_SUCCESS;
}

int32_t RemoveSpmDataTask::Rollback()
{
    int32_t result = RET_SUCCESS;
    // Phase 1: batch-restore the spm entries whose removal succeeded, reverse order.
    std::vector<SpmData*> entries;
    entries.reserve(items_.size());
    for (size_t i = items_.size(); i > 0; --i) {
        const Item& item = items_[i - 1];
        if (item.spmEntryRemoved && item.oldSpmData != nullptr) {
            entries.emplace_back(item.oldSpmData.get());
        }
    }
    if (!entries.empty()) {
        int32_t ret = RestoreSpmEntries(entries);
        if (ret != RET_SUCCESS) {
            result = ret;
        }
    }
    // Phase 2: restore the caller-provided old permission list whose removal
    // succeeded, reverse order.
    for (size_t i = items_.size(); i > 0; --i) {
        const Item& item = items_[i - 1];
        if (!item.permRemoved) {
            continue; // removal failed: the bitmap is still in the kernel, no restore needed
        }
        int32_t ret = RestorePermCodes(item.tokenId, item.oldPermBriefDataList);
        if (ret != RET_SUCCESS && result == RET_SUCCESS) {
            result = ret;
        }
    }
    return result;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
