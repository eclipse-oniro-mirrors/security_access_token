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

#include "claw_permission_status_helper.h"

#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "permission_manager.h"
#ifdef SAF_AGENT_FENCE_ENABLE
#include "saf_result_code.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
bool IsUserDeniedFlag(uint32_t flag)
{
    return (flag & PERMISSION_USER_FIXED) != 0;
}

bool IsRestrictedFlag(uint32_t flag)
{
    static constexpr uint32_t RESTRICTED_FLAGS = PERMISSION_SYSTEM_FIXED |
        PERMISSION_FIXED_FOR_SECURITY_POLICY | PERMISSION_FIXED_BY_ADMIN_POLICY;
    return (flag & RESTRICTED_FLAGS) != 0;
}

bool IsAllowThisTimeFlag(uint32_t flag)
{
    return (flag & PERMISSION_ALLOW_THIS_TIME) != 0;
}

bool IsGrantedWithoutDialog(const PermissionStatus& status)
{
    return (status.grantStatus == PERMISSION_GRANTED) && !IsAllowThisTimeFlag(status.grantFlag) &&
        (status.grantFlag != PERMISSION_DEFAULT_FLAG);
}

int32_t BuildPermissionStatusMap(AccessTokenID tokenId, PermissionStatusMap& permissionStatusMap)
{
    std::vector<PermissionStatus> userGrantPermissions;
    int32_t ret = PermissionManager::GetInstance().GetReqPermissions(tokenId, userGrantPermissions, false);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get user grant permissions failed, tokenId=%{public}u, ret=%{public}d.",
            tokenId, ret);
        return ret;
    }

    std::vector<PermissionStatus> systemGrantPermissions;
    ret = PermissionManager::GetInstance().GetReqPermissions(tokenId, systemGrantPermissions, true);
    if (ret != RET_SUCCESS) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Get system grant permissions failed, tokenId=%{public}u, ret=%{public}d.",
            tokenId, ret);
        return ret;
    }

    permissionStatusMap.clear();
    permissionStatusMap.reserve(userGrantPermissions.size() + systemGrantPermissions.size());
    for (const auto& permission : userGrantPermissions) {
        permissionStatusMap[permission.permissionName] = permission;
    }
    for (const auto& permission : systemGrantPermissions) {
        permissionStatusMap[permission.permissionName] = permission;
    }
    return RET_SUCCESS;
}

bool ResolveCliGrantedPermission(const PermissionStatusMap& permissionStatusMap,
    const std::string& permissionName, bool cliAuthorizationResult)
{
    auto iter = permissionStatusMap.find(permissionName);
    if (iter == permissionStatusMap.end()) {
        return cliAuthorizationResult;
    }

    const PermissionStatus& status = iter->second;
    if (IsGrantedWithoutDialog(status)) {
        return true;
    }
    if (IsRestrictedFlag(status.grantFlag) || IsUserDeniedFlag(status.grantFlag)) {
        return false;
    }
    return cliAuthorizationResult;
}

int32_t TransferErrorCode(int32_t ret)
{
    switch (ret) {
        case ERR_TICKET_NOT_LOGGED_IN:
            return ERR_NOT_LOGGED_IN;
        case ERR_TICKET_NETWORK_DISCONNECTED:
            return ERR_NETWORK_DISCONNECTED;
#ifdef SAF_AGENT_FENCE_ENABLE
        case SAF_ERR_IPC_WRITE_DATA_FAIL:
            return ERR_WRITE_PARCEL_FAILED;
        case SAF_ERR_IPC_READ_DATA_FAIL:
            return ERR_READ_PARCEL_FAILED;
        case SAF_ERR_IPC_SEND_REQUEST_FAIL:
        case SAF_ERR_IPC_PROXY_FAIL:
        case SAF_ERR_IPC_ERROR:
        case SAF_ERR_IPC_INVALID_IPC_CODE:
            return ERROR_IPC_REQUEST_FAIL;
        case SAF_ERR_SERVICE_UNAVAILABLE:
        case SAF_ERR_SERVICE_IS_STOPPING:
            return ERR_SERVICE_ABNORMAL;
#endif
        default:
            break;
    }
    return ret;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
