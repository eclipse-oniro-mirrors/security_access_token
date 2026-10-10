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

#include "update_spm_data_task.h"

#include <algorithm>
#include <cstdint>
#include <utility>

#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "hisysevent_adapter.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
constexpr int32_t MAX_ENTRY_NUM = 255;
// batch count and idxErr of SPM entry ioctls are uint8_t, the limit must fit to avoid wraparound
static_assert(MAX_ENTRY_NUM <= UINT8_MAX, "MAX_ENTRY_NUM must fit in uint8_t");

UpdateSpmDataTask::UpdateSpmDataTask(const std::vector<SpmDataParam>& params)
{
    if (params.empty() || params.size() > MAX_ENTRY_NUM) {
        isBuildSuccess_ = false;
        LOGE(ATM_DOMAIN, ATM_TAG, "UpdateSpmDataTask params invalid.");
        return;
    }
    updateWithPerm_ = params.front().updateWithPerm;
    items_.reserve(params.size());
    for (const auto& param : params) {
        if (param.updateWithPerm != updateWithPerm_) {
            isBuildSuccess_ = false;
            break;
        }
        SpmDataTaskItem item;
        const auto& hapInfo = param.hapInfo.get();
        const auto& noCachedInfo = param.noCachedInfo.get();
        const auto& permBriefDataList = param.permBriefDataList.get();
        const auto& extendPermList = param.extendPermList.get();
        item.tokenId = hapInfo.tokenID;
        item.permBriefDataList = permBriefDataList;
        item.oldPermBriefDataList = param.oldPermBriefDataList;
        // oldPermBriefDataList == nullptr is valid: "no known old perms" (new
        // token or data gap). Rollback removes the written bitmap for such
        // tokens instead of restoring, so install can converge add and update
        // routing into a single update task.
        if (KernelDetail::BuildSpmData(hapInfo, noCachedInfo, permBriefDataList, extendPermList,
            item.newSpmData) != RET_SUCCESS) {
            isBuildSuccess_ = false;
            break;
        }
        items_.emplace_back(std::move(item));
    }
    if (!isBuildSuccess_) {
        items_.clear();
    }
}

UpdateSpmDataTask::~UpdateSpmDataTask() = default;

static int32_t LoadOldSpmDataForItems(std::vector<SpmDataTaskItem>& items, bool& isSpmSupport)
{
    isSpmSupport = PermissionKernelUtils::IsKernelSupportSpm();
    if (!isSpmSupport) {
        return RET_SUCCESS;
    }
    for (size_t i = 0; i < items.size(); ++i) {
        auto& item = items[i];
        int32_t ret = KernelDetail::LoadSpmDataFromKernel(item.tokenId, item.oldSpmData);
        if (ret == ERR_NO_DATA_FROM_KERNEL) {
            // kernel has no entry yet (new token first update): no old data to protect,
            // rollback removes the new entry instead
            item.oldSpmData.reset();
            continue;
        }
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Load spm data failed, tokenId = %{public}d.", item.tokenId);
            return ret;
        }
    }
    return RET_SUCCESS;
}

static int32_t SetNewSpmDataToKernel(const std::vector<SpmDataTaskItem>& items,
    size_t& spmDataSuccessCount, uint32_t& errIndex)
{
    spmDataSuccessCount = 0;
    size_t itemSize = items.size();
    std::vector<SpmData*> entries;
    entries.reserve(itemSize);
    for (const auto& item : items) {
        entries.emplace_back(item.newSpmData.get());
    }
    uint8_t idxErr = 0;
    int32_t ret = KernelDetail::SetSpmEntriesToKernel(entries, idxErr);
    if (ret != RET_SUCCESS) {
        errIndex = static_cast<uint32_t>(idxErr);
        spmDataSuccessCount = std::min(static_cast<size_t>(errIndex), entries.size());
        LOGE(ATM_DOMAIN, ATM_TAG,
            "Set spm entries failed, errIndex=%{public}u, ret=%{public}d.", errIndex, ret);
        return ret;
    }
    spmDataSuccessCount = itemSize;
    return RET_SUCCESS;
}

static int32_t UpdatePermData(const std::vector<SpmDataTaskItem>& items, size_t& permDataSuccessCount,
    uint32_t& errIndex)
{
    permDataSuccessCount = 0;
    size_t itemSize = items.size();
    for (size_t i = 0; i < itemSize; ++i) {
        int32_t permRet = PermissionKernelUtils::AddHapPermToKernel(items[i].tokenId, items[i].permBriefDataList);
        if (permRet != RET_SUCCESS) {
            permDataSuccessCount = i;
            errIndex = static_cast<uint32_t>(i);
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Update hap perm in kernel failed, tokenId=%{public}u, errIndex=%{public}u, ret=%{public}d.",
                items[i].tokenId, errIndex, permRet);
            return permRet;
        }
    }
    permDataSuccessCount = itemSize;
    return RET_SUCCESS;
}

int32_t UpdateSpmDataTask::Update(uint32_t& errIndex)
{
    errIndex = 0;
    if (!isBuildSuccess_) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build spm data failed.");
        return ERR_PARAM_INVALID;
    }

    bool isSpmSupport = false;
    int32_t ret = LoadOldSpmDataForItems(items_, isSpmSupport);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    if (isSpmSupport) {
        ret = SetNewSpmDataToKernel(items_, spmDataSuccessCount_, errIndex);
        if (ret != RET_SUCCESS) {
            (void)Rollback();
            return ret;
        }
    }

    if (!updateWithPerm_) {
        return RET_SUCCESS;
    }

    ret = UpdatePermData(items_, permDataSuccessCount_, errIndex);
    if (ret != RET_SUCCESS) {
        (void)Rollback();
        return ret;
    }
    return RET_SUCCESS;
}

static int32_t RollbackSpmEntries(const std::vector<SpmData*>& entries)
{
    uint8_t idxErr = 0;
    int32_t ret = KernelDetail::SetSpmEntriesToKernel(entries, idxErr);
    if (ret == RET_SUCCESS) {
        return RET_SUCCESS;
    }
    if (static_cast<size_t>(idxErr) < entries.size()) {
        LOGC(ATM_DOMAIN, ATM_TAG,
            "Rollback SetSpmEntriesToKernel failed for token=%{public}u, ret=%{public}d.",
            entries[idxErr]->tokenid, ret);
        ReportSysCommonEventError(KERNEL_SPM_DATA_ROLLBACK, ret);
    }
    return ret;
}

static int32_t RollbackPermData(const std::vector<SpmDataTaskItem>& items, size_t permDataSuccessCount)
{
    int32_t result = RET_SUCCESS;
    for (size_t i = 0; i < permDataSuccessCount; ++i) {
        int32_t ret;
        if (items[i].oldPermBriefDataList == nullptr) {
            if (items[i].oldSpmData != nullptr) {
                // entry existed but its old perms are unknown: degraded compensation
                LOGE(ATM_DOMAIN, ATM_TAG, "No oldPermBriefDataList token=%{public}u.", items[i].tokenId);
            }
            // no known old perms (new token or data gap): remove the written
            // bitmap instead of restoring, symmetric to AddSpmDataTask rollback
            ret = PermissionKernelUtils::RemovePermFromKernel(items[i].tokenId);
        } else {
            ret = PermissionKernelUtils::AddHapPermToKernel(items[i].tokenId, *(items[i].oldPermBriefDataList));
        }
        if (ret == RET_SUCCESS) {
            continue;
        }
        LOGC(ATM_DOMAIN, ATM_TAG,
            "Rollback perm data failed for token=%{public}u, ret=%{public}d.", items[i].tokenId, ret);
        ReportSysCommonEventError(KERNEL_PERM_DATA_ROLLBACK, ret);
        result = ret;
    }
    return result;
}

int32_t UpdateSpmDataTask::Rollback()
{
    // defensive clamp: success counters must never exceed the item count
    spmDataSuccessCount_ = std::min(spmDataSuccessCount_, items_.size());
    permDataSuccessCount_ = std::min(permDataSuccessCount_, items_.size());
    std::vector<SpmData*> entries;
    entries.reserve(spmDataSuccessCount_);
    int32_t result = RET_SUCCESS;
    for (size_t i = 0; i < spmDataSuccessCount_; ++i) {
        if (items_[i].oldSpmData == nullptr) {
            // ENODATA on load: kernel had no entry before update, remove the new one
            int32_t ret = KernelDetail::RemoveSpmEntryFromKernel(items_[i].tokenId);
            if (ret != RET_SUCCESS) {
                LOGC(ATM_DOMAIN, ATM_TAG,
                    "Rollback RemoveSpmEntryFromKernel failed for token=%{public}u, ret=%{public}d.",
                    items_[i].tokenId, ret);
                ReportSysCommonEventError(KERNEL_SPM_DATA_ROLLBACK, ret);
                result = ret;
            }
            continue;
        }
        entries.emplace_back(items_[i].oldSpmData.get());
    }
    if (!entries.empty()) {
        int32_t ret = RollbackSpmEntries(entries);
        if (ret != RET_SUCCESS) {
            result = ret;
        }
    }
    int32_t permResult = RollbackPermData(items_, permDataSuccessCount_);
    spmDataSuccessCount_ = 0;
    permDataSuccessCount_ = 0;
    return (result != RET_SUCCESS) ? result : permResult;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
