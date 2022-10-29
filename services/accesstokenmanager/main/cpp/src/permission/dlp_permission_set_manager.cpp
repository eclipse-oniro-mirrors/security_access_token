/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "dlp_permission_set_manager.h"

#include <fcntl.h>
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "access_token.h"
#include "accesstoken_log.h"
#include "data_validator.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "DlpPermissionSetManager"};
}

DlpPermissionSetManager& DlpPermissionSetManager::GetInstance()
{
    static DlpPermissionSetManager instance;
    return instance;
}

DlpPermissionSetManager::DlpPermissionSetManager()
{}

DlpPermissionSetManager::~DlpPermissionSetManager()
{}

void DlpPermissionSetManager::ProcessDlpPermInfos(const std::vector<PermissionDlpMode>& dlpPermInfos)
{
    for (auto iter = dlpPermInfos.begin(); iter != dlpPermInfos.end(); iter++) {
        auto it = dlpPermissionModeMap_.find(iter->permissionName);
        if (it != dlpPermissionModeMap_.end()) {
            ACCESSTOKEN_LOG_WARN(LABEL,
                "info for permission: %{public}s dlpMode %{public}d has been insert, please check!",
                iter->permissionName.c_str(), iter->dlpMode);
            continue;
        }
        dlpPermissionModeMap_[iter->permissionName] = iter->dlpMode;
    }
}

int32_t DlpPermissionSetManager::GetPermDlpMode(const std::string& permissionName)
{
    auto it = dlpPermissionModeMap_.find(permissionName);
    if (it == dlpPermissionModeMap_.end()) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "can not find permission: %{public}s in dlp permission cfg",
            permissionName.c_str());
        return DLP_PERM_ALL;
    }
    return dlpPermissionModeMap_[permissionName];
}

int32_t DlpPermissionSetManager::UpdatePermStateWithDlpInfo(int32_t dlpType,
    std::vector<PermissionStateFull>& permStateList)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "dlpType: %{public}d", dlpType);
    for (auto iter = permStateList.begin(); iter != permStateList.end(); iter++) {
        if (iter->grantStatus[0] == PERMISSION_DENIED) {
            continue;
        }
        int32_t dlpMode = GetPermDlpMode(iter->permissionName);
        bool res = IsPermStateNeedUpdate(dlpType, dlpMode);
        if (res) {
            iter->grantStatus[0] = PERMISSION_DENIED;
        }
    }
    return RET_SUCCESS;
}

bool DlpPermissionSetManager::IsPermStateNeedUpdate(int32_t dlpType, int32_t dlpMode)
{
    ACCESSTOKEN_LOG_DEBUG(LABEL, "dlpType: %{public}d dlpMode %{public}d", dlpType, dlpMode);
    /* permission is available to all dlp hap */
    if (dlpMode == DLP_PERM_ALL) {
        return false;
    }

    /* permission is available to full control */
    if (dlpMode == DLP_PERM_FULL_CONTROL && dlpType == DLP_FULL_CONTROL) {
        return false;
    }
    /* permission is available to none */
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
