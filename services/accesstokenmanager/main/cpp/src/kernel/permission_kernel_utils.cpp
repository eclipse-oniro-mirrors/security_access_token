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

#include "permission_kernel_utils.h"

#include <atomic>
#include <mutex>
#include "accesstoken_common_log.h"
#include "permission_map.h"
#include "perm_setproc.h"
#include "spm_setproc.h"
#include "spm_data_kernel_common.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
void PermissionKernelUtils::AddNativePermToKernel(AccessTokenID tokenID,
    const std::vector<uint32_t>& opCodeList, const std::vector<bool>& statusList)
{
    std::vector<uint32_t> grantedPermList;
    for (size_t i = 0; i < opCodeList.size(); ++i) {
        if (statusList[i]) {
            grantedPermList.emplace_back(opCodeList[i]);
        }
    }
    int32_t ret = AddPermissionToKernel(tokenID, grantedPermList);
    if (ret != ACCESS_TOKEN_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AddPermissionToKernel(token=%{public}d), size=%{public}zu, err=%{public}d",
            tokenID, grantedPermList.size(), ret);
    }
}

int32_t PermissionKernelUtils::AddHapPermToKernel(AccessTokenID tokenID, const std::vector<uint32_t>& opCodeList)
{
    int32_t ret = AddPermissionToKernel(tokenID, opCodeList);
    if (ret != ACCESS_TOKEN_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AddPermissionToKernel(token=%{public}d), size=%{public}zu, err=%{public}d",
            tokenID, opCodeList.size(), ret);
    }
    return ret;
}

int32_t PermissionKernelUtils::AddHapPermToKernel(AccessTokenID tokenID,
    const std::vector<BriefPermData>& permBriefDataList)
{
    std::vector<uint32_t> opCodeList;
    for (const auto& permData : permBriefDataList) {
        if (permData.status == PERMISSION_GRANTED) {
            opCodeList.emplace_back(permData.permCode);
        }
    }
    AddHapPermToKernel(tokenID, opCodeList);
    return RET_SUCCESS;
}

int32_t PermissionKernelUtils::GetBundleInfoFromKernel(AccessTokenID tokenId, BundleNoCachedInfo& noCachedInfo,
    std::vector<PermissionWithValue>& permList)
{
    SpmDataPtr spmData = nullptr;
    int32_t ret = KernelDetail::LoadSpmDataFromKernel(tokenId, spmData);
    if (ret != RET_SUCCESS) {
        return ret;
    }

    noCachedInfo.apl = static_cast<ATokenAplEnum>(spmData->apl);
    noCachedInfo.distributionType = spmData->distributionType;
    noCachedInfo.idType = spmData->idType;
    noCachedInfo.ownerid = spmData->ownerid;
    return KernelDetail::ParseExtendedPermissionBuffer(spmData->extendPerms, permList);
}

void PermissionKernelUtils::RemovePermFromKernel(AccessTokenID tokenID)
{
    int32_t ret = RemovePermissionFromKernel(tokenID);
    if (ret == RET_SUCCESS) {
        return;
    }
    // retry
    ret = RemovePermissionFromKernel(tokenID);
    if (ret == RET_SUCCESS) {
        return;
    }
    LOGE(ATM_DOMAIN, ATM_TAG,
        "RemovePermissionFromKernel(token=%{public}d), err=%{public}d", tokenID, ret);
}

void PermissionKernelUtils::SetPermToKernel(AccessTokenID tokenID, const std::string& permissionName, bool isGranted)
{
    uint32_t code;
    if (!TransferPermissionToOpcode(permissionName, code)) {
        return;
    }
    int32_t ret = SetPermissionToKernel(tokenID, code, isGranted);
    LOGI(ATM_DOMAIN, ATM_TAG,
        "SetPermissionToKernel(token=%{public}d, permission=(%{public}s), err=%{public}d",
        tokenID, permissionName.c_str(), ret);
}

bool PermissionKernelUtils::IsKernelSupportSpm()
{
#ifndef ATM_TEST_ENABLE
    static std::atomic<bool> isSupportSpm{false};
    static std::atomic<bool> hasChecked{false};
    static std::mutex checkMutex;

    if (hasChecked.load(std::memory_order_acquire)) {
        return isSupportSpm.load(std::memory_order_acquire);
    }

    std::lock_guard<std::mutex> lock(checkMutex);
    if (hasChecked.load(std::memory_order_relaxed)) {
        return isSupportSpm.load(std::memory_order_relaxed);
    }
#endif

    uint32_t version = 0;
    int ret = SpmGetVersion(&version);
#ifndef ATM_TEST_ENABLE
    isSupportSpm.store(ret != ENOTSUP, std::memory_order_release);
    hasChecked.store(true, std::memory_order_release);
#endif
    LOGI(ATM_DOMAIN, ATM_TAG,
        "Spm is %{public}s", ret != ENOTSUP ? "supported" : "not supported");
    return ret != ENOTSUP;
}

void PermissionKernelUtils::RemoveSpmEntryFromKernel(AccessTokenID tokenId)
{
    KernelDetail::RemoveSpmEntryFromKernel(tokenId);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
