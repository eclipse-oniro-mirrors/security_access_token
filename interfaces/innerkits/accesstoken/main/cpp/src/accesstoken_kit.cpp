/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"

#include <string>
#include <vector>

#include "accesstoken_log.h"
#include "accesstoken_manager_client.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenKit"};
} // namespace

AccessTokenIDEx AccessTokenKit::AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policy)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);

    return AccessTokenManagerClient::GetInstance().AllocHapToken(info, policy);
}

AccessTokenID AccessTokenKit::AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    return AccessTokenManagerClient::GetInstance().AllocLocalTokenID(remoteDeviceID, remoteTokenID);
}

int AccessTokenKit::UpdateHapToken(AccessTokenID tokenID, const std::string& appIDDesc, const HapPolicyParams& policy)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    return AccessTokenManagerClient::GetInstance().UpdateHapToken(tokenID, appIDDesc, policy);
}

int AccessTokenKit::DeleteToken(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID=%{public}d", tokenID);

    return AccessTokenManagerClient::GetInstance().DeleteToken(tokenID);
}

int AccessTokenKit::GetTokenType(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID=%{public}d", tokenID);
    return AccessTokenManagerClient::GetInstance().GetTokenType(tokenID);
}

int AccessTokenKit::CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID=%{public}d, dcap=%{public}s", tokenID, dcap.c_str());
    return AccessTokenManagerClient::GetInstance().CheckNativeDCap(tokenID, dcap);
}

AccessTokenID AccessTokenKit::GetHapTokenID(int userID, const std::string& bundleName, int instIndex)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "int userID=%{public}d, bundleName=%{public}s, instIndex=%{public}d",
        userID, bundleName.c_str(), instIndex);

    return AccessTokenManagerClient::GetInstance().GetHapTokenID(userID, bundleName, instIndex);
}

int AccessTokenKit::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID=%{public}d", tokenID);

    return AccessTokenManagerClient::GetInstance().GetHapTokenInfo(tokenID, hapTokenInfoRes);
}

int AccessTokenKit::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID=%{public}d", tokenID);

    return AccessTokenManagerClient::GetInstance().GetNativeTokenInfo(tokenID, nativeTokenInfoRes);
}

int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID=%{public}d, permissionName=%{public}s", tokenID, permissionName.c_str());
    return AccessTokenManagerClient::GetInstance().VerifyAccessToken(tokenID, permissionName);
}

int AccessTokenKit::VerifyAccessToken(
    AccessTokenID callerTokenID, AccessTokenID firstTokenID, const std::string& permissionName)
{
    return 0;
}

int AccessTokenKit::GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "permissionName=%{public}s", permissionName.c_str());

    int ret = AccessTokenManagerClient::GetInstance().GetDefPermission(permissionName, permissionDefResult);
    ACCESSTOKEN_LOG_INFO(LABEL, "GetDefPermission bundleName = %{public}s", permissionDefResult.bundleName.c_str());

    return ret;
}

int AccessTokenKit::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permDefList)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID=%{public}d", tokenID);

    ACCESSTOKEN_LOG_INFO(LABEL, "GetDefPermissions permDefList size = %{public}d", permDefList.size());
    return AccessTokenManagerClient::GetInstance().GetDefPermissions(tokenID, permDefList);
}

int AccessTokenKit::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID=%{public}d, isSystemGrant=%{public}d", tokenID, isSystemGrant);

    ACCESSTOKEN_LOG_INFO(LABEL, "GetReqPermissions, reqPermList size=%{public}d", reqPermList.size());
    return AccessTokenManagerClient::GetInstance().GetReqPermissions(tokenID, reqPermList, isSystemGrant);
}

int AccessTokenKit::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID=%{public}d, permissionName=%{public}s", tokenID, permissionName.c_str());
    return AccessTokenManagerClient::GetInstance().GetPermissionFlag(tokenID, permissionName);
}

int AccessTokenKit::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID=%{public}d, permissionName=%{public}s, flag=%{public}d",
        tokenID, permissionName.c_str(), flag);
    return AccessTokenManagerClient::GetInstance().GrantPermission(tokenID, permissionName, flag);
}

int AccessTokenKit::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID=%{public}d, permissionName=%{public}s, flag=%{public}d",
        tokenID, permissionName.c_str(), flag);
    return AccessTokenManagerClient::GetInstance().RevokePermission(tokenID, permissionName, flag);
}

int AccessTokenKit::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    ACCESSTOKEN_LOG_INFO(LABEL, "tokenID=%{public}d", tokenID);
    return AccessTokenManagerClient::GetInstance().ClearUserGrantedPermissionState(tokenID);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
