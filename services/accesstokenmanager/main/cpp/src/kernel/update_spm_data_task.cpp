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

#include <utility>

#include "accesstoken_common_log.h"
#include "access_token_error.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
constexpr int32_t MAX_ENTRY_NUM = 255;

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
        if (updateWithPerm_ && param.oldPermBriefDataList == nullptr) {
            isBuildSuccess_ = false;
            LOGE(ATM_DOMAIN, ATM_TAG, "UpdateSpmDataTask need oldPermBriefDataList with permission update.");
            break;
        }
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
        spmDataSuccessCount = static_cast<size_t>(errIndex);
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

int32_t UpdateSpmDataTask::Rollback()
{
    std::vector<SpmData*> entries;
    entries.reserve(spmDataSuccessCount_);
    for (size_t i = 0; i < spmDataSuccessCount_; ++i) {
        if (items_[i].oldSpmData == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "No oldSpmData token=%{public}u.", items_[i].tokenId);
            continue;
        }
        entries.emplace_back(items_[i].oldSpmData.get());
    }
    int32_t result = RET_SUCCESS;
    if (!entries.empty()) {
        uint8_t idxErr = 0;
        int32_t ret = KernelDetail::SetSpmEntriesToKernel(entries, idxErr);
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Rollback SpmSetEntries failed at index=%{public}u, ret=%{public}d.", idxErr, ret);
            result = ret;
        }
    }

    for (size_t i = 0; i < permDataSuccessCount_; ++i) {
        if (items_[i].oldPermBriefDataList == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "No oldPermBriefDataList token=%{public}u.", items_[i].tokenId);
            result = RET_FAILED;
            break;  // no possible to reach here
        }
        int32_t ret = PermissionKernelUtils::AddHapPermToKernel(items_[i].tokenId, *(items_[i].oldPermBriefDataList));
        if (ret != RET_SUCCESS) {
            LOGE(ATM_DOMAIN, ATM_TAG,
                "Rollback AddHapPermToKernel failed for token=%{public}u, ret=%{public}d.",
                items_[i].tokenId, ret);
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
