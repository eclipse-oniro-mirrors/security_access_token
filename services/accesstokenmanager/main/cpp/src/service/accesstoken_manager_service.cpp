/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "accesstoken_manager_service.h"

#include "access_token.h"
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "native_token_info_inner.h"
#include "native_token_receptor.h"
#include "permission_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenManagerService"
};
}

const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(DelayedSingleton<AccessTokenManagerService>::GetInstance().get());

AccessTokenManagerService::AccessTokenManagerService()
    : SystemAbility(SA_ID_ACCESSTOKEN_MANAGER_SERVICE, true), state_(ServiceRunningState::STATE_NOT_START)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "AccessTokenManagerService()");
}

AccessTokenManagerService::~AccessTokenManagerService()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "~AccessTokenManagerService()");
}

void AccessTokenManagerService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        ACCESSTOKEN_LOG_INFO(LABEL, "AccessTokenManagerService has already started!");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "AccessTokenManagerService is starting");
    if (!Initialize()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to initialize");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    bool ret = Publish(DelayedSingleton<AccessTokenManagerService>::GetInstance().get());
    if (!ret) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to publish service!");
        return;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Congratulations, AccessTokenManagerService start successfully!");
}

void AccessTokenManagerService::OnStop()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "stop service");
    state_ = ServiceRunningState::STATE_NOT_START;
}

int AccessTokenManagerService::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: 0x%{public}x, permissionName: %{public}s", __func__,
        tokenID, permissionName.c_str());
    return PermissionManager::GetInstance().VerifyAccessToken(tokenID, permissionName);
}

int AccessTokenManagerService::VerifyNativeToken(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: 0x%{public}x, permissionName: %{public}s", __func__,
        tokenID, permissionName.c_str());
    return PermissionManager::GetInstance().VerifyNativeToken(tokenID, permissionName);
}

int AccessTokenManagerService::GetDefPermission(
    const std::string& permissionName, PermissionDefParcel& permissionDefResult)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, permissionName: %{public}s", __func__, permissionName.c_str());
    return PermissionManager::GetInstance().GetDefPermission(permissionName, permissionDefResult.permissionDef);
}

int AccessTokenManagerService::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDefParcel>& permList)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: 0x%{public}x", __func__, tokenID);
    std::vector<PermissionDef> permVec;
    int ret = PermissionManager::GetInstance().GetDefPermissions(tokenID, permVec);
    for (auto perm : permVec) {
        PermissionDefParcel permPrcel;
        permPrcel.permissionDef = perm;
        permList.emplace_back(permPrcel);
    }
    return ret;
}

int AccessTokenManagerService::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStateFullParcel>& reqPermList, bool isSystemGrant)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: 0x%{public}x, isSystemGrant: %{public}d", __func__, tokenID, isSystemGrant);

    std::vector<PermissionStateFull> permList;
    int ret = PermissionManager::GetInstance().GetReqPermissions(tokenID, permList, isSystemGrant);

    for (auto& perm : permList) {
        PermissionStateFullParcel permPrcel;
        permPrcel.permStatFull = perm;
        reqPermList.emplace_back(permPrcel);
    }
    return ret;
}

int AccessTokenManagerService::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: 0x%{public}x, permissionName: %{public}s", __func__,
        tokenID, permissionName.c_str());
    return PermissionManager::GetInstance().GetPermissionFlag(tokenID, permissionName);
}

int AccessTokenManagerService::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: 0x%{public}x, permissionName: %{public}s, flag: %{public}d", __func__,
        tokenID, permissionName.c_str(), flag);
    PermissionManager::GetInstance().GrantPermission(tokenID, permissionName, flag);
    AccessTokenInfoManager::GetInstance().RefreshTokenInfoIfNeeded();
    return RET_SUCCESS;
}

int AccessTokenManagerService::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: 0x%{public}x, permissionName: %{public}s, flag: %{public}d", __func__,
        tokenID, permissionName.c_str(), flag);
    PermissionManager::GetInstance().RevokePermission(tokenID, permissionName, flag);
    AccessTokenInfoManager::GetInstance().RefreshTokenInfoIfNeeded();
    return RET_SUCCESS;
}

int AccessTokenManagerService::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: 0x%{public}x", __func__, tokenID);
    PermissionManager::GetInstance().ClearUserGrantedPermissionState(tokenID);
    AccessTokenInfoManager::GetInstance().RefreshTokenInfoIfNeeded();
    return RET_SUCCESS;
}

AccessTokenIDEx AccessTokenManagerService::AllocHapToken(const HapInfoParcel& info, const HapPolicyParcel& policy)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);
    AccessTokenIDEx tokenIdEx;
    tokenIdEx.tokenIDEx = 0LL;

    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        info.hapInfoParameter, policy.hapPolicyParameter, tokenIdEx);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_INFO(LABEL, "hap token info create failed");
    }
    return tokenIdEx;
}

int AccessTokenManagerService::DeleteToken(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL,
        "%{public}s called, tokenID: 0x%{public}x", __func__, tokenID);
    // only support hap token deletion
    return AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
}

int AccessTokenManagerService::GetTokenType(AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: 0x%{public}x", __func__, tokenID);
    return AccessTokenIDManager::GetInstance().GetTokenIdType(tokenID);
}

int AccessTokenManagerService::CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: 0x%{public}x, dcap: %{public}s",
        __func__, tokenID, dcap.c_str());
    return AccessTokenInfoManager::GetInstance().CheckNativeDCap(tokenID, dcap);
}

AccessTokenID AccessTokenManagerService::GetHapTokenID(int userID, const std::string& bundleName, int instIndex)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, userID: %{public}d, bundleName: %{public}s, instIndex: %{public}d",
        __func__, userID, bundleName.c_str(), instIndex);
    return AccessTokenInfoManager::GetInstance().GetHapTokenID(userID, bundleName, instIndex);
}

AccessTokenID AccessTokenManagerService::AllocLocalTokenID(
    const std::string& remoteDeviceID, AccessTokenID remoteTokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, remoteDeviceID: %{public}s, remoteTokenID: %{public}d",
        __func__, remoteDeviceID.c_str(), remoteTokenID);
    return AccessTokenInfoManager::GetInstance().AllocLocalTokenID(remoteDeviceID, remoteTokenID);
}

int AccessTokenManagerService::UpdateHapToken(AccessTokenID tokenID, const std::string& appIDDesc,
    const HapPolicyParcel& policyParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: 0x%{public}x", __func__, tokenID);

    return AccessTokenInfoManager::GetInstance().UpdateHapToken(tokenID, appIDDesc,
        policyParcel.hapPolicyParameter);
}

int AccessTokenManagerService::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& InfoParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: 0x%{public}x", __func__, tokenID);

    return AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenID, InfoParcel.hapTokenInfoParams);
}

int AccessTokenManagerService::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& InfoParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: 0x%{public}x", __func__, tokenID);

    return AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(tokenID, InfoParcel.nativeTokenInfoParams);
}

int AccessTokenManagerService::GetHapTokenInfoFromRemote(AccessTokenID tokenID,
    HapTokenInfoForSyncParcel& hapSyncParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, tokenID: 0x%{public}x", __func__, tokenID);

    return AccessTokenInfoManager::GetInstance().GetHapTokenInfoFromRemote(tokenID,
        hapSyncParcel.hapTokenInfoForSyncParams);
}

int AccessTokenManagerService::GetAllNativeTokenInfo(std::vector<NativeTokenInfoParcel>& nativeTokenInfosRes)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);

    std::vector<NativeTokenInfo> nativeVec;
    AccessTokenInfoManager::GetInstance().GetAllNativeTokenInfo(nativeVec);
    for (auto& native : nativeVec) {
        NativeTokenInfoParcel nativeParcel;
        nativeParcel.nativeTokenInfoParams = native;
        nativeTokenInfosRes.emplace_back(nativeParcel);
    }

    return RET_SUCCESS;
}

int AccessTokenManagerService::SetRemoteHapTokenInfo(const std::string& deviceID,
    HapTokenInfoForSyncParcel& hapSyncParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, deviceID: %{public}s", __func__, deviceID.c_str());

    return AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(deviceID,
        hapSyncParcel.hapTokenInfoForSyncParams);
}

int AccessTokenManagerService::SetRemoteNativeTokenInfo(const std::string& deviceID,
    std::vector<NativeTokenInfoParcel>& nativeTokenInfoParcel)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, deviceID: %{public}s", __func__, deviceID.c_str());

    std::vector<NativeTokenInfo> nativeList;

    for (auto& nativeParcel : nativeTokenInfoParcel) {
        nativeList.emplace_back(nativeParcel.nativeTokenInfoParams);
    }

    return AccessTokenInfoManager::GetInstance().SetRemoteNativeTokenInfo(deviceID, nativeList);
}

int AccessTokenManagerService::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, deviceID: %{public}s, token id %{public}d",
        __func__, deviceID.c_str(), tokenID);

    return AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceID, tokenID);
}

AccessTokenID AccessTokenManagerService::GetRemoteNativeTokenID(const std::string& deviceID,
    AccessTokenID tokenID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, deviceID: %{public}s, token id %{public}d",
        __func__, deviceID.c_str(), tokenID);

    return AccessTokenInfoManager::GetInstance().GetRemoteNativeTokenID(deviceID, tokenID);
}

int AccessTokenManagerService::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called, deviceID: %{public}s", __func__, deviceID.c_str());

    return AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(deviceID);
}

void AccessTokenManagerService::DumpTokenInfo(std::string& dumpInfo)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called", __func__);

    AccessTokenInfoManager::GetInstance().DumpTokenInfo(dumpInfo);
}

bool AccessTokenManagerService::Initialize() const
{
    AccessTokenInfoManager::GetInstance().Init();
    NativeTokenReceptor::GetInstance().Init();
    return true;
}
} // namespace AccessToken
} // namespace Security
}
