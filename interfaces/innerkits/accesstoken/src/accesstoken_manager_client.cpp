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

#include "accesstoken_manager_client.h"

#include "accesstoken_log.h"
#include "access_token_error.h"
#include "accesstoken_manager_proxy.h"
#include "hap_token_info.h"
#include "hap_token_info_for_sync_parcel.h"
#include "iservice_registry.h"
#include "native_token_info_for_sync_parcel.h"
#include "native_token_info.h"
#include "permission_state_change_callback.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenManagerClient"
};
} // namespace
static const uint32_t MAX_CALLBACK_MAP_SIZE = 200;

AccessTokenManagerClient& AccessTokenManagerClient::GetInstance()
{
    static AccessTokenManagerClient instance;
    return instance;
}

AccessTokenManagerClient::AccessTokenManagerClient()
{}

AccessTokenManagerClient::~AccessTokenManagerClient()
{}

int AccessTokenManagerClient::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return PERMISSION_DENIED;
    }
    return proxy->VerifyAccessToken(tokenID, permissionName);
}

int AccessTokenManagerClient::GetDefPermission(
    const std::string& permissionName, PermissionDef& permissionDefResult)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }
    PermissionDefParcel permissionDefParcel;
    int result = proxy->GetDefPermission(permissionName, permissionDefParcel);
    permissionDefResult = permissionDefParcel.permissionDef;
    return result;
}

int AccessTokenManagerClient::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }
    std::vector<PermissionDefParcel> parcelList;
    int result = proxy->GetDefPermissions(tokenID, parcelList);
    for (const auto& permParcel : parcelList) {
        PermissionDef perm = permParcel.permissionDef;
        permList.emplace_back(perm);
    }
    return result;
}

int AccessTokenManagerClient::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }
    std::vector<PermissionStateFullParcel> parcelList;
    int result = proxy->GetReqPermissions(tokenID, parcelList, isSystemGrant);
    for (const auto& permParcel : parcelList) {
        PermissionStateFull perm = permParcel.permStatFull;
        reqPermList.emplace_back(perm);
    }
    return result;
}

int AccessTokenManagerClient::GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, int& flag)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }
    return proxy->GetPermissionFlag(tokenID, permissionName, flag);
}

PermissionOper AccessTokenManagerClient::GetSelfPermissionsState(std::vector<PermissionListState>& permList)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null.");
        return INVALID_OPER;
    }

    size_t len = permList.size();
    if (len == 0) {
        ACCESSTOKEN_LOG_DEBUG(LABEL, "len is zero.");
        return PASS_OPER;
    }

    std::vector<PermissionListStateParcel> parcelList;

    for (const auto& perm : permList) {
        PermissionListStateParcel permParcel;
        permParcel.permsState = perm;
        parcelList.emplace_back(permParcel);
    }
    PermissionOper result = proxy->GetSelfPermissionsState(parcelList);

    for (uint32_t i = 0; i < len; i++) {
        PermissionListState perm = parcelList[i].permsState;
        permList[i].state = perm.state;
    }
    return result;
}

int AccessTokenManagerClient::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }
    return proxy->GrantPermission(tokenID, permissionName, flag);
}

int AccessTokenManagerClient::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }
    return proxy->RevokePermission(tokenID, permissionName, flag);
}

int AccessTokenManagerClient::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }
    return proxy->ClearUserGrantedPermissionState(tokenID);
}

int32_t AccessTokenManagerClient::CreatePermStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& customizedCb,
    sptr<PermissionStateChangeCallback>& callback)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (callbackMap_.size() == MAX_CALLBACK_MAP_SIZE) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "the maximum number of callback has been reached");
        return AccessTokenError::ERR_EXCEEDED_MAXNUM_REGISTRATION_LIMIT;
    }

    auto goalCallback = callbackMap_.find(customizedCb);
    if (goalCallback != callbackMap_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "already has the same callback");
        return AccessTokenError::ERR_PARAM_INVALID;
    } else {
        callback = new (std::nothrow) PermissionStateChangeCallback(customizedCb);
        if (!callback) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "memory allocation for callback failed!");
            return AccessTokenError::ERR_SA_WORK_ABNORMAL;
        }
    }
    return RET_SUCCESS;
}

int32_t AccessTokenManagerClient::RegisterPermStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& customizedCb)
{
    if (customizedCb == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "customizedCb is nullptr");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    sptr<PermissionStateChangeCallback> callback = nullptr;
    int32_t result = CreatePermStateChangeCallback(customizedCb, callback);
    if (result != RET_SUCCESS) {
        return result;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }

    PermStateChangeScopeParcel scopeParcel;
    customizedCb->GetScope(scopeParcel.scope);

    if (scopeParcel.scope.permList.size() > PERMS_LIST_SIZE_MAX ||
        scopeParcel.scope.tokenIDs.size() > TOKENIDS_LIST_SIZE_MAX) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    result = proxy->RegisterPermStateChangeCallback(scopeParcel, callback->AsObject());
    if (result == RET_SUCCESS) {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        callbackMap_[customizedCb] = callback;
    }
    return result;
}

int32_t AccessTokenManagerClient::UnRegisterPermStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& customizedCb)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }

    std::lock_guard<std::mutex> lock(callbackMutex_);
    auto goalCallback = callbackMap_.find(customizedCb);
    if (goalCallback == callbackMap_.end()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "goalCallback already is not exist");
        return AccessTokenError::ERR_INTERFACE_NOT_USED_TOGETHER;
    }

    int32_t result = proxy->UnRegisterPermStateChangeCallback(goalCallback->second->AsObject());
    if (result == RET_SUCCESS) {
        callbackMap_.erase(goalCallback);
    }
    return result;
}

AccessTokenIDEx AccessTokenManagerClient::AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policy)
{
    AccessTokenIDEx res = { 0 };
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return res;
    }
    HapInfoParcel hapInfoParcel;
    HapPolicyParcel hapPolicyParcel;
    hapInfoParcel.hapInfoParameter = info;
    hapPolicyParcel.hapPolicyParameter = policy;

    return proxy->AllocHapToken(hapInfoParcel, hapPolicyParcel);
}

int AccessTokenManagerClient::DeleteToken(AccessTokenID tokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }
    return proxy->DeleteToken(tokenID);
}

ATokenTypeEnum AccessTokenManagerClient::GetTokenType(AccessTokenID tokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return TOKEN_INVALID;
    }
    return static_cast<ATokenTypeEnum>(proxy->GetTokenType(tokenID));
}

int AccessTokenManagerClient::CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }
    return proxy->CheckNativeDCap(tokenID, dcap);
}

AccessTokenID AccessTokenManagerClient::GetHapTokenID(int userID, const std::string& bundleName, int instIndex)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return INVALID_TOKENID;
    }
    return proxy->GetHapTokenID(userID, bundleName, instIndex);
}

AccessTokenID AccessTokenManagerClient::AllocLocalTokenID(
    const std::string& remoteDeviceID, AccessTokenID remoteTokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return INVALID_TOKENID;
    }
    return proxy->AllocLocalTokenID(remoteDeviceID, remoteTokenID);
}

int AccessTokenManagerClient::UpdateHapToken(
    AccessTokenID tokenID, const std::string& appIDDesc, int32_t apiVersion, const HapPolicyParams& policy)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }
    HapPolicyParcel hapPolicyParcel;
    hapPolicyParcel.hapPolicyParameter = policy;
    return proxy->UpdateHapToken(tokenID, appIDDesc, apiVersion, hapPolicyParcel);
}

int AccessTokenManagerClient::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }
    HapTokenInfoParcel hapTokenInfoParcel;
    int res = proxy->GetHapTokenInfo(tokenID, hapTokenInfoParcel);

    hapTokenInfoRes = hapTokenInfoParcel.hapTokenInfoParams;
    return res;
}

int AccessTokenManagerClient::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }
    NativeTokenInfoParcel nativeTokenInfoParcel;
    int res = proxy->GetNativeTokenInfo(tokenID, nativeTokenInfoParcel);
    nativeTokenInfoRes = nativeTokenInfoParcel.nativeTokenInfoParams;
    return res;
}

int32_t AccessTokenManagerClient::ReloadNativeTokenInfo()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }
    return proxy->ReloadNativeTokenInfo();
}

AccessTokenID AccessTokenManagerClient::GetNativeTokenId(const std::string& processName)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return INVALID_TOKENID;
    }
    return proxy->GetNativeTokenId(processName);
}

#ifdef TOKEN_SYNC_ENABLE
int AccessTokenManagerClient::GetHapTokenInfoFromRemote(AccessTokenID tokenID, HapTokenInfoForSync& hapSync)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }

    HapTokenInfoForSyncParcel hapSyncParcel;
    int res = proxy->GetHapTokenInfoFromRemote(tokenID, hapSyncParcel);
    hapSync = hapSyncParcel.hapTokenInfoForSyncParams;
    return res;
}

int AccessTokenManagerClient::GetAllNativeTokenInfo(std::vector<NativeTokenInfoForSync>& nativeTokenInfosRes)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }

    std::vector<NativeTokenInfoForSyncParcel> parcelList;
    int result = proxy->GetAllNativeTokenInfo(parcelList);
    for (const auto& nativeTokenParcel : parcelList) {
        NativeTokenInfoForSync native = nativeTokenParcel.nativeTokenInfoForSyncParams;
        nativeTokenInfosRes.emplace_back(native);
    }

    return result;
}

int AccessTokenManagerClient::SetRemoteHapTokenInfo(const std::string& deviceID, const HapTokenInfoForSync& hapSync)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }

    HapTokenInfoForSyncParcel hapSyncParcel;
    hapSyncParcel.hapTokenInfoForSyncParams = hapSync;

    int res = proxy->SetRemoteHapTokenInfo(deviceID, hapSyncParcel);
    return res;
}

int AccessTokenManagerClient::SetRemoteNativeTokenInfo(const std::string& deviceID,
    const std::vector<NativeTokenInfoForSync>& nativeTokenInfoList)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }
    std::vector<NativeTokenInfoForSyncParcel> nativeTokenInfoParcels;
    for (const auto& native : nativeTokenInfoList) {
        NativeTokenInfoForSyncParcel nativeTokenInfoForSyncParcel;
        nativeTokenInfoForSyncParcel.nativeTokenInfoForSyncParams = native;
        nativeTokenInfoParcels.emplace_back(nativeTokenInfoForSyncParcel);
    }
    PermissionStateFullParcel permStateParcel;
    int res = proxy->SetRemoteNativeTokenInfo(deviceID, nativeTokenInfoParcels);
    return res;
}

int AccessTokenManagerClient::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }

    int res = proxy->DeleteRemoteToken(deviceID, tokenID);
    return res;
}

AccessTokenID AccessTokenManagerClient::GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return INVALID_TOKENID;
    }

    AccessTokenID res = proxy->GetRemoteNativeTokenID(deviceID, tokenID);
    return res;
}

int AccessTokenManagerClient::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return AccessTokenError::ERR_SA_WORK_ABNORMAL;
    }

    int res = proxy->DeleteRemoteDeviceTokens(deviceID);
    return res;
}
#endif

void AccessTokenManagerClient::DumpTokenInfo(AccessTokenID tokenID, std::string& dumpInfo)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "proxy is null");
        return;
    }
    proxy->DumpTokenInfo(tokenID, dumpInfo);
}

void AccessTokenManagerClient::InitProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr) {
        auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (sam == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbilityManager is null");
            return;
        }
        auto accesstokenSa = sam->GetSystemAbility(IAccessTokenManager::SA_ID_ACCESSTOKEN_MANAGER_SERVICE);
        if (accesstokenSa == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "GetSystemAbility %{public}d is null",
                IAccessTokenManager::SA_ID_ACCESSTOKEN_MANAGER_SERVICE);
            return;
        }

        serviceDeathObserver_ = new (std::nothrow) AccessTokenDeathRecipient();
        if (serviceDeathObserver_ != nullptr) {
            accesstokenSa->AddDeathRecipient(serviceDeathObserver_);
        }
        proxy_ = iface_cast<IAccessTokenManager>(accesstokenSa);
        if (proxy_ == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "iface_cast get null");
        }
    }
}

void AccessTokenManagerClient::OnRemoteDiedHandle()
{
    {
        std::lock_guard<std::mutex> lock(proxyMutex_);
        proxy_ = nullptr;
    }
    InitProxy();
}

sptr<IAccessTokenManager> AccessTokenManagerClient::GetProxy()
{
    if (proxy_ == nullptr) {
        InitProxy();
    }
    return proxy_;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
