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

#include <mutex>
#include "accesstoken_common_log.h"
#include "hap_token_info_inner.h"
#include "perm_setproc.h"
#include "permission_map.h"
#include "spm_setproc.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
void PermissionKernelUtils::AddNativePermToKernel(AccessTokenID tokenID,
    const std::vector<uint32_t>& opCodeList, const std::vector<bool>& statusList)
{
    int32_t ret = AddPermissionToKernel(tokenID, opCodeList, statusList);
    if (ret != ACCESS_TOKEN_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AddPermissionToKernel(token=%{public}d), size=%{public}zu, err=%{public}d",
            tokenID, opCodeList.size(), ret);
    }
}

void PermissionKernelUtils::AddHapPermToKernel(AccessTokenID tokenID, const std::vector<uint32_t>& constrainedPermList)
{
    std::vector<uint32_t> opCodeList;
    std::vector<bool> statusList;
    HapTokenInfoInner::GetPermStatusListByTokenId(tokenID, constrainedPermList, opCodeList, statusList);
    int32_t ret = AddPermissionToKernel(tokenID, opCodeList, statusList);
    if (ret != ACCESS_TOKEN_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "AddPermissionToKernel(token=%{public}d), size=%{public}zu, err=%{public}d",
            tokenID, opCodeList.size(), ret);
    }
}

void PermissionKernelUtils::RemovePermFromKernel(AccessTokenID tokenID)
{
    int32_t ret = RemovePermissionFromKernel(tokenID);
    LOGI(ATM_DOMAIN, ATM_TAG,
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
    static bool isSupportSpm = false;
    static bool hasChecked = false;
    static std::mutex checkMutex;
    std::lock_guard<std::mutex> lock(checkMutex);
    if (hasChecked) {
        return isSupportSpm;
    }
    uint32_t version = 0;
    int ret = SpmGetVersion(&version);
    isSupportSpm = (ret == ENOTSUP) ? false : true;
    hasChecked = true;
    LOGE(ATM_DOMAIN, ATM_TAG,
        "Spm is %{public}s", isSupportSpm ? "supported" : "not supported");
    return isSupportSpm;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
