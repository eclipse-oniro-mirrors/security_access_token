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

#include "add_spm_data_task.h"

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

AddSpmDataTask::AddSpmDataTask(const std::vector<SpmDataParam>& params)
{
    if (params.empty() || params.size() > MAX_ENTRY_NUM) {
        isBuildSuccess_ = false;
        LOGE(ATM_DOMAIN, ATM_TAG, "AddSpmDataTask params invalid.");
        return;
    }
    items_.reserve(params.size());
    updateWithPerm_ = params.front().updateWithPerm;
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

AddSpmDataTask::~AddSpmDataTask() = default;

static int32_t AddPermDataToKernel(const std::vector<SpmDataTaskItem>& items, size_t& permDataSuccessCount,
    uint32_t& errIndex)
{
    permDataSuccessCount = 0;
    size_t itemSize = items.size();
    for (size_t i = 0; i < itemSize; ++i) {
        int32_t permRet = PermissionKernelUtils::AddHapPermToKernel(
            items[i].tokenId, items[i].permBriefDataList);
        if (permRet != RET_SUCCESS) {
            permDataSuccessCount = i;
            errIndex = static_cast<uint32_t>(i);
            LOGW(ATM_DOMAIN, ATM_TAG,
                "Add hap perm to kernel failed, tokenId=%{public}u, errIndex=%{public}u, ret=%{public}d.",
                items[i].tokenId, errIndex, permRet);
            return permRet;
        }
    }
    permDataSuccessCount = itemSize;
    return RET_SUCCESS;
}

int32_t AddSpmDataTask::Add(uint32_t& errIndex)
{
    errIndex = 0;
    if (!isBuildSuccess_) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Build spm data failed.");
        return ERR_PARAM_INVALID;
    }

    spmDataSuccessCount_ = 0;
    permDataSuccessCount_ = 0;
    if (PermissionKernelUtils::IsKernelSupportSpm()) {
        std::vector<SpmData*> entries;
        entries.reserve(items_.size());
        for (const auto& item : items_) {
            entries.emplace_back(item.newSpmData.get());
        }

        uint8_t idxErr = 0;
        int32_t ret = KernelDetail::AddSpmEntriesToKernel(entries, idxErr);
        if (ret != RET_SUCCESS) {
            errIndex = static_cast<uint32_t>(idxErr);
            spmDataSuccessCount_ = std::min(static_cast<size_t>(idxErr), items_.size());
            LOGE(ATM_DOMAIN, ATM_TAG, "Add spm entries failed, errIndex=%{public}u, ret=%{public}d.", errIndex, ret);
            (void)Rollback();
            return ret;
        } else {
            spmDataSuccessCount_ = items_.size();
        }
    }

    if (!updateWithPerm_) {
        return RET_SUCCESS;
    }

    int32_t ret = AddPermDataToKernel(items_, permDataSuccessCount_, errIndex);
    if (ret != RET_SUCCESS) {
        (void)Rollback();
        return ret;
    }
    return RET_SUCCESS;
}

int32_t AddSpmDataTask::Rollback()
{
    // defensive clamp: success counters must never exceed the item count
    spmDataSuccessCount_ = std::min(spmDataSuccessCount_, items_.size());
    permDataSuccessCount_ = std::min(permDataSuccessCount_, items_.size());
    int32_t result = RET_SUCCESS;
    if (updateWithPerm_) {
        for (size_t i = permDataSuccessCount_; i > 0; --i) {
            AccessTokenID tokenId = items_[i - 1].tokenId;
            int32_t ret = PermissionKernelUtils::RemovePermFromKernel(tokenId);
            if (ret != RET_SUCCESS) {
                LOGC(ATM_DOMAIN, ATM_TAG,
                    "Rollback RemovePermFromKernel failed for token=%{public}u, ret=%{public}d.",
                    tokenId, ret);
                ReportSysCommonEventError(KERNEL_PERM_DATA_ROLLBACK, ret);
                result = ret;
            }
        }
    }

    for (size_t i = spmDataSuccessCount_; i > 0; --i) {
        AccessTokenID tokenId = items_[i - 1].tokenId;
        int32_t ret = KernelDetail::RemoveSpmEntryFromKernel(tokenId);
        if (ret != RET_SUCCESS) {
            LOGC(ATM_DOMAIN, ATM_TAG,
                "Rollback RemoveSpmEntryFromKernel failed for token=%{public}u, ret=%{public}d.",
                tokenId, ret);
            ReportSysCommonEventError(KERNEL_SPM_DATA_ROLLBACK, ret);
            result = ret;
        }
    }
    spmDataSuccessCount_ = 0;
    permDataSuccessCount_ = 0;
    return result;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
