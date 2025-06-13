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

#include <memory>
#include <mutex>

#include "access_token.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "data_validator.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
}

DlpPermissionSetManager& DlpPermissionSetManager::GetInstance()
{
    static DlpPermissionSetManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            DlpPermissionSetManager* tmp = new (std::nothrow) DlpPermissionSetManager();
            instance = std::move(tmp);
        }
    }
    return *instance;
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
            LOGW(ATM_DOMAIN, ATM_TAG,
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
        LOGD(ATM_DOMAIN, ATM_TAG, "Can not find permission: %{public}s in dlp permission cfg",
            permissionName.c_str());
        return DLP_PERM_ALL;
    }
    return dlpPermissionModeMap_[permissionName];
}

void DlpPermissionSetManager::UpdatePermStateWithDlpInfo(int32_t hapDlpType,
    std::vector<PermissionStatus>& permStateList)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "DlpType: %{public}d", hapDlpType);
    for (auto iter = permStateList.begin(); iter != permStateList.end(); ++iter) {
        if (iter->grantStatus == PERMISSION_DENIED) {
            continue;
        }
        int32_t permissionDlpMode = GetPermDlpMode(iter->permissionName);
        bool res = IsPermDlpModeAvailableToDlpHap(hapDlpType, permissionDlpMode);
        if (!res) {
            iter->grantStatus = PERMISSION_DENIED;
        }
    }
}

bool DlpPermissionSetManager::IsPermissionAvailableToDlpHap(int32_t hapDlpType,
    const std::string& permissionName)
{
    int32_t permissionDlpMode = GetPermDlpMode(permissionName);
    return IsPermDlpModeAvailableToDlpHap(hapDlpType, permissionDlpMode);
}

bool DlpPermissionSetManager::IsPermDlpModeAvailableToDlpHap(int32_t hapDlpType, int32_t permDlpMode)
{
    LOGD(ATM_DOMAIN, ATM_TAG, "DlpType: %{public}d dlpMode %{public}d", hapDlpType, permDlpMode);

    /* permission is available to all dlp hap */
    if ((hapDlpType == DLP_COMMON) || (permDlpMode == DLP_PERM_ALL)) {
        return true;
    }

    /* permission is available to full control */
    if (permDlpMode == DLP_PERM_FULL_CONTROL && hapDlpType == DLP_FULL_CONTROL) {
        return true;
    }
    /* permission is available to none */
    return false;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
