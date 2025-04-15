/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "accesstoken_manager_proxy.h"
#include "atm_tools_param_info_parcel.h"
#include "hap_token_info.h"
#include "hap_token_info_for_sync_parcel.h"
#include "iservice_registry.h"
#include "parameter.h"
#include "permission_grant_info_parcel.h"
#include "accesstoken_callbacks.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t VALUE_MAX_LEN = 32;
static const char* ACCESS_TOKEN_SERVICE_INIT_KEY = "accesstoken.permission.init";
std::recursive_mutex g_instanceMutex;
} // namespace
static const uint32_t MAX_CALLBACK_MAP_SIZE = 200;

AccessTokenManagerClient& AccessTokenManagerClient::GetInstance()
{
    static AccessTokenManagerClient* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            AccessTokenManagerClient* tmp = new AccessTokenManagerClient();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

AccessTokenManagerClient::AccessTokenManagerClient()
{}

AccessTokenManagerClient::~AccessTokenManagerClient()
{
    LOGE(ATM_DOMAIN, ATM_TAG, "~AccessTokenManagerClient");
    std::lock_guard<std::mutex> lock(proxyMutex_);
    ReleaseProxy();
}

PermUsedTypeEnum AccessTokenManagerClient::GetPermissionUsedType(
    AccessTokenID tokenID, const std::string &permissionName)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return PermUsedTypeEnum::INVALID_USED_TYPE;
    }
    return proxy->GetPermissionUsedType(tokenID, permissionName);
}

int AccessTokenManagerClient::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    auto proxy = GetProxy();
    if (proxy != nullptr) {
        return proxy->VerifyAccessToken(tokenID, permissionName);
    }
    char value[VALUE_MAX_LEN] = {0};
    int32_t ret = GetParameter(ACCESS_TOKEN_SERVICE_INIT_KEY, "", value, VALUE_MAX_LEN - 1);
    if ((ret < 0) || (static_cast<uint64_t>(std::atoll(value)) != 0)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "At service has been started, ret=%{public}d.", ret);
        return PERMISSION_DENIED;
    }
    AccessTokenIDInner *idInner = reinterpret_cast<AccessTokenIDInner *>(&tokenID);
    if (static_cast<ATokenTypeEnum>(idInner->type) == TOKEN_NATIVE) {
        LOGI(ATM_DOMAIN, ATM_TAG, "At service has not been started.");
        return PERMISSION_GRANTED;
    }
    LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
    return PERMISSION_DENIED;
}

int AccessTokenManagerClient::VerifyAccessToken(AccessTokenID tokenID,
    const std::vector<std::string>& permissionList, std::vector<int32_t>& permStateList)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->VerifyAccessToken(tokenID, permissionList, permStateList);
}

int AccessTokenManagerClient::GetDefPermission(
    const std::string& permissionName, PermissionDef& permissionDefResult)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    PermissionDefParcel permissionDefParcel;
    int result = proxy->GetDefPermission(permissionName, permissionDefParcel);
    permissionDefResult = permissionDefParcel.permissionDef;
    return result;
}

int AccessTokenManagerClient::GetReqPermissions(
    AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    std::vector<PermissionStatusParcel> parcelList;
    int result = proxy->GetReqPermissions(tokenID, parcelList, isSystemGrant);
    for (const auto& permParcel : parcelList) {
        PermissionStateFull perm;
        perm.permissionName = permParcel.permState.permissionName;
        perm.isGeneral = true;
        perm.resDeviceID.emplace_back("PHONE-001");
        perm.grantStatus.emplace_back(permParcel.permState.grantStatus);
        perm.grantFlags.emplace_back(permParcel.permState.grantFlag);
        reqPermList.emplace_back(perm);
    }
    return result;
}

int AccessTokenManagerClient::GetPermissionFlag(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->GetPermissionFlag(tokenID, permissionName, flag);
}

int32_t AccessTokenManagerClient::GetSelfPermissionStatus(const std::string& permissionName, PermissionOper& status)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        status = INVALID_OPER;
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    int32_t retStatus = INVALID_OPER;
    int32_t result = proxy->GetSelfPermissionStatus(permissionName, retStatus);
    if (result != RET_SUCCESS) {
        return result;
    }
    status = static_cast<PermissionOper>(retStatus);
    LOGI(ATM_DOMAIN, ATM_TAG, "Result from server (error=%{public}d, status=%{public}d).", result, retStatus);
    return result;
}

PermissionOper AccessTokenManagerClient::GetSelfPermissionsState(std::vector<PermissionListState>& permList,
    PermissionGrantInfo& info)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return INVALID_OPER;
    }

    size_t len = permList.size();
    if (len == 0) {
        LOGD(ATM_DOMAIN, ATM_TAG, "Len is zero.");
        return PASS_OPER;
    }

    std::vector<PermissionListStateParcel> parcelList;

    for (const auto& perm : permList) {
        PermissionListStateParcel permParcel;
        permParcel.permsState = perm;
        parcelList.emplace_back(permParcel);
    }
    PermissionGrantInfoParcel infoParcel;
    PermissionOper result = proxy->GetSelfPermissionsState(parcelList, infoParcel);

    for (uint32_t i = 0; i < len; i++) {
        PermissionListState perm = parcelList[i].permsState;
        permList[i].state = perm.state;
        permList[i].errorReason = perm.errorReason;
    }

    info = infoParcel.info;
    return result;
}

int32_t AccessTokenManagerClient::GetPermissionsStatus(
    AccessTokenID tokenID, std::vector<PermissionListState>& permList)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    size_t len = permList.size();
    if (len == 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Len is zero.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    std::vector<PermissionListStateParcel> parcelList;

    for (const auto& perm : permList) {
        PermissionListStateParcel permParcel;
        permParcel.permsState = perm;
        parcelList.emplace_back(permParcel);
    }
    int32_t result = proxy->GetPermissionsStatus(tokenID, parcelList);
    if (result != RET_SUCCESS) {
        return result;
    }
    for (uint32_t i = 0; i < len; i++) {
        PermissionListState perm = parcelList[i].permsState;
        permList[i].state = perm.state;
    }

    return result;
}

int AccessTokenManagerClient::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->GrantPermission(tokenID, permissionName, flag);
}

int AccessTokenManagerClient::RevokePermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->RevokePermission(tokenID, permissionName, flag);
}

int AccessTokenManagerClient::GrantPermissionForSpecifiedTime(
    AccessTokenID tokenID, const std::string& permissionName, uint32_t onceTime)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->GrantPermissionForSpecifiedTime(tokenID, permissionName, onceTime);
}

int AccessTokenManagerClient::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->ClearUserGrantedPermissionState(tokenID);
}

int32_t AccessTokenManagerClient::SetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t status,
    int32_t userID = 0)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->SetPermissionRequestToggleStatus(permissionName, status, userID);
}

int32_t AccessTokenManagerClient::GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status,
    int32_t userID = 0)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->GetPermissionRequestToggleStatus(permissionName, status, userID);
}

int32_t AccessTokenManagerClient::RequestAppPermOnSetting(AccessTokenID tokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->RequestAppPermOnSetting(tokenID);
}

int32_t AccessTokenManagerClient::CreatePermStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& customizedCb,
    sptr<PermissionStateChangeCallback>& callback)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (callbackMap_.size() == MAX_CALLBACK_MAP_SIZE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "The maximum number of callback has been reached");
        return AccessTokenError::ERR_CALLBACKS_EXCEED_LIMITATION;
    }

    auto goalCallback = callbackMap_.find(customizedCb);
    if (goalCallback != callbackMap_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Already has the same callback");
        return AccessTokenError::ERR_CALLBACK_ALREADY_EXIST;
    } else {
        callback = new (std::nothrow) PermissionStateChangeCallback(customizedCb);
        if (!callback) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Memory allocation for callback failed!");
            return AccessTokenError::ERR_SERVICE_ABNORMAL;
        }
    }
    return RET_SUCCESS;
}

int32_t AccessTokenManagerClient::RegisterPermStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& customizedCb, RegisterPermChangeType type)
{
    if (customizedCb == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "CustomizedCb is nullptr");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    sptr<PermissionStateChangeCallback> callback = nullptr;
    int32_t result = CreatePermStateChangeCallback(customizedCb, callback);
    if (result != RET_SUCCESS) {
        return result;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    PermStateChangeScopeParcel scopeParcel;
    customizedCb->GetScope(scopeParcel.scope);

    if (scopeParcel.scope.permList.size() > PERMS_LIST_SIZE_MAX) {
        LOGE(ATM_DOMAIN, ATM_TAG, "PermList scope oversize");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    if (type == SYSTEM_REGISTER_TYPE) {
        if (scopeParcel.scope.tokenIDs.size() > TOKENIDS_LIST_SIZE_MAX) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TokenIDs scope oversize");
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        result = proxy->RegisterPermStateChangeCallback(scopeParcel, callback->AsObject());
    } else {
        if (scopeParcel.scope.tokenIDs.size() != 1) {
            LOGE(ATM_DOMAIN, ATM_TAG, "TokenIDs scope invalid");
            return AccessTokenError::ERR_PARAM_INVALID;
        }
        result = proxy->RegisterSelfPermStateChangeCallback(scopeParcel, callback->AsObject());
    }
    if (result == RET_SUCCESS) {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        callbackMap_[customizedCb] = callback;
    }
    return result;
}

int32_t AccessTokenManagerClient::UnRegisterPermStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& customizedCb, RegisterPermChangeType type)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    std::lock_guard<std::mutex> lock(callbackMutex_);
    auto goalCallback = callbackMap_.find(customizedCb);
    if (goalCallback == callbackMap_.end()) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GoalCallback already is not exist");
        return AccessTokenError::ERR_INTERFACE_NOT_USED_TOGETHER;
    }
    int32_t result;
    if (type == SYSTEM_REGISTER_TYPE) {
        result = proxy->UnRegisterPermStateChangeCallback(goalCallback->second->AsObject());
    } else {
        result = proxy->UnRegisterSelfPermStateChangeCallback(goalCallback->second->AsObject());
    }
    if (result == RET_SUCCESS) {
        callbackMap_.erase(goalCallback);
    }
    return result;
}

AccessTokenIDEx AccessTokenManagerClient::AllocHapToken(const HapInfoParams& info, const HapPolicy& policy)
{
    AccessTokenIDEx tokenIdEx = { 0 };
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return tokenIdEx;
    }
    HapInfoParcel hapInfoParcel;
    HapPolicyParcel hapPolicyParcel;
    hapInfoParcel.hapInfoParameter = info;
    hapPolicyParcel.hapPolicy = policy;

    return proxy->AllocHapToken(hapInfoParcel, hapPolicyParcel);
}

int32_t AccessTokenManagerClient::InitHapToken(const HapInfoParams& info, HapPolicy& policy,
    AccessTokenIDEx& fullTokenId, HapInfoCheckResult& result)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    HapInfoParcel hapInfoParcel;
    HapPolicyParcel hapPolicyParcel;
    hapInfoParcel.hapInfoParameter = info;
    hapPolicyParcel.hapPolicy = policy;

    return proxy->InitHapToken(hapInfoParcel, hapPolicyParcel, fullTokenId, result);
}

int AccessTokenManagerClient::DeleteToken(AccessTokenID tokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->DeleteToken(tokenID);
}

ATokenTypeEnum AccessTokenManagerClient::GetTokenType(AccessTokenID tokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return TOKEN_INVALID;
    }
    return static_cast<ATokenTypeEnum>(proxy->GetTokenType(tokenID));
}

AccessTokenIDEx AccessTokenManagerClient::GetHapTokenID(
    int32_t userID, const std::string& bundleName, int32_t instIndex)
{
    AccessTokenIDEx result = {0};
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return result;
    }
    return proxy->GetHapTokenID(userID, bundleName, instIndex);
}

AccessTokenID AccessTokenManagerClient::AllocLocalTokenID(
    const std::string& remoteDeviceID, AccessTokenID remoteTokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return INVALID_TOKENID;
    }
    return proxy->AllocLocalTokenID(remoteDeviceID, remoteTokenID);
}

int32_t AccessTokenManagerClient::UpdateHapToken(AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info,
    const HapPolicy& policy, HapInfoCheckResult& result)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    HapPolicyParcel hapPolicyParcel;
    hapPolicyParcel.hapPolicy = policy;
    return proxy->UpdateHapToken(tokenIdEx, info, hapPolicyParcel, result);
}

int32_t AccessTokenManagerClient::GetTokenIDByUserID(int32_t userID, std::unordered_set<AccessTokenID>& tokenIdList)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->GetTokenIDByUserID(userID, tokenIdList);
}

int AccessTokenManagerClient::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
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
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    NativeTokenInfoParcel nativeTokenInfoParcel;
    int res = proxy->GetNativeTokenInfo(tokenID, nativeTokenInfoParcel);
    nativeTokenInfoRes = nativeTokenInfoParcel.nativeTokenInfoParams;
    return res;
}

#ifndef ATM_BUILD_VARIANT_USER_ENABLE
int32_t AccessTokenManagerClient::ReloadNativeTokenInfo()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->ReloadNativeTokenInfo();
}
#endif

int AccessTokenManagerClient::GetHapTokenInfoExtension(AccessTokenID tokenID, HapTokenInfoExt& info)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    HapTokenInfoParcel hapTokenInfoParcel;
    int res = proxy->GetHapTokenInfoExtension(tokenID, hapTokenInfoParcel, info.appID);
    info.baseInfo = hapTokenInfoParcel.hapTokenInfoParams;
    return res;
}

AccessTokenID AccessTokenManagerClient::GetNativeTokenId(const std::string& processName)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return INVALID_TOKENID;
    }
    return proxy->GetNativeTokenId(processName);
}

#ifdef TOKEN_SYNC_ENABLE
int AccessTokenManagerClient::GetHapTokenInfoFromRemote(AccessTokenID tokenID, HapTokenInfoForSync& hapSync)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    HapTokenInfoForSyncParcel hapSyncParcel;
    int res = proxy->GetHapTokenInfoFromRemote(tokenID, hapSyncParcel);
    hapSync = hapSyncParcel.hapTokenInfoForSyncParams;
    return res;
}

int AccessTokenManagerClient::SetRemoteHapTokenInfo(const std::string& deviceID, const HapTokenInfoForSync& hapSync)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    HapTokenInfoForSyncParcel hapSyncParcel;
    hapSyncParcel.hapTokenInfoForSyncParams = hapSync;

    int res = proxy->SetRemoteHapTokenInfo(deviceID, hapSyncParcel);
    return res;
}

int AccessTokenManagerClient::DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    int res = proxy->DeleteRemoteToken(deviceID, tokenID);
    return res;
}

AccessTokenID AccessTokenManagerClient::GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return INVALID_TOKENID;
    }

    AccessTokenID res = proxy->GetRemoteNativeTokenID(deviceID, tokenID);
    return res;
}

int AccessTokenManagerClient::DeleteRemoteDeviceTokens(const std::string& deviceID)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    int res = proxy->DeleteRemoteDeviceTokens(deviceID);
    return res;
}

int32_t AccessTokenManagerClient::RegisterTokenSyncCallback(
    const std::shared_ptr<TokenSyncKitInterface>& syncCallback)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    if (syncCallback == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Input callback is null.");
        return AccessTokenError::ERR_PARAM_INVALID;
    }
    
    sptr<TokenSyncCallback> callback = sptr<TokenSyncCallback>(new TokenSyncCallback(syncCallback));

    std::lock_guard<std::mutex> lock(tokenSyncCallbackMutex_);
    int32_t res = proxy->RegisterTokenSyncCallback(callback->AsObject());
    if (res == RET_SUCCESS) {
        tokenSyncCallback_ = callback;
        syncCallbackImpl_ = syncCallback;
    }
    return res;
}

int32_t AccessTokenManagerClient::UnRegisterTokenSyncCallback()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    std::lock_guard<std::mutex> lock(tokenSyncCallbackMutex_);
    int32_t res = proxy->UnRegisterTokenSyncCallback();
    if (res == RET_SUCCESS) {
        tokenSyncCallback_ = nullptr;
        syncCallbackImpl_ = nullptr;
    }
    return res;
}
#endif

void AccessTokenManagerClient::DumpTokenInfo(const AtmToolsParamInfo& info, std::string& dumpInfo)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return;
    }

    AtmToolsParamInfoParcel infoParcel;
    infoParcel.info = info;
    proxy->DumpTokenInfo(infoParcel, dumpInfo);
}

int32_t AccessTokenManagerClient::GetVersion(uint32_t& version)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null.");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }

    return proxy->GetVersion(version);
}

void AccessTokenManagerClient::InitProxy()
{
    if (proxy_ == nullptr || proxy_->AsObject() == nullptr || proxy_->AsObject()->IsObjectDead()) {
        auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (sam == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "GetSystemAbilityManager is null");
            return;
        }
        sptr<IRemoteObject> accesstokenSa =
            sam->GetSystemAbility(IAccessTokenManager::SA_ID_ACCESSTOKEN_MANAGER_SERVICE);
        if (accesstokenSa == nullptr) {
            LOGE(ATM_DOMAIN, ATM_TAG, "GetSystemAbility %{public}d is null",
                IAccessTokenManager::SA_ID_ACCESSTOKEN_MANAGER_SERVICE);
            return;
        }

        serviceDeathObserver_ = sptr<AccessTokenDeathRecipient>::MakeSptr();
        if (serviceDeathObserver_ != nullptr) {
            accesstokenSa->AddDeathRecipient(serviceDeathObserver_);
        }
        proxy_ = new AccessTokenManagerProxy(accesstokenSa);
        if (proxy_ == nullptr || proxy_->AsObject() == nullptr || proxy_->AsObject()->IsObjectDead()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Iface_cast get null");
        }
    }
}

void AccessTokenManagerClient::OnRemoteDiedHandle()
{
    {
        std::lock_guard<std::mutex> lock(proxyMutex_);
        ReleaseProxy();
        InitProxy();
    }

#ifdef TOKEN_SYNC_ENABLE
    if (syncCallbackImpl_ != nullptr) {
        RegisterTokenSyncCallback(syncCallbackImpl_); // re-register callback when AT crashes
    }
#endif // TOKEN_SYNC_ENABLE
}

sptr<IAccessTokenManager> AccessTokenManagerClient::GetProxy()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    if (proxy_ == nullptr || proxy_->AsObject() == nullptr || proxy_->AsObject()->IsObjectDead()) {
        InitProxy();
    }
    return proxy_;
}

int32_t AccessTokenManagerClient::SetPermDialogCap(const HapBaseInfo& hapBaseInfo, bool enable)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    HapBaseInfoParcel hapBaseInfoParcel;
    hapBaseInfoParcel.hapBaseInfo = hapBaseInfo;
    return proxy->SetPermDialogCap(hapBaseInfoParcel, enable);
}

void AccessTokenManagerClient::GetPermissionManagerInfo(PermissionGrantInfo& info)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return;
    }
    PermissionGrantInfoParcel infoParcel;
    proxy->GetPermissionManagerInfo(infoParcel);
    info = infoParcel.info;
}

int32_t AccessTokenManagerClient::InitUserPolicy(
    const std::vector<UserState>& userList, const std::vector<std::string>& permList)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->InitUserPolicy(userList, permList);
}

int32_t AccessTokenManagerClient::ClearUserPolicy()
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->ClearUserPolicy();
}

int32_t AccessTokenManagerClient::UpdateUserPolicy(const std::vector<UserState>& userList)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->UpdateUserPolicy(userList);
}

void AccessTokenManagerClient::ReleaseProxy()
{
    if (proxy_ != nullptr && serviceDeathObserver_ != nullptr) {
        proxy_->AsObject()->RemoveDeathRecipient(serviceDeathObserver_);
    }
    proxy_ = nullptr;
    serviceDeathObserver_ = nullptr;
}

int32_t AccessTokenManagerClient::GetKernelPermissions(
    AccessTokenID tokenId, std::vector<PermissionWithValue>& kernelPermList)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->GetKernelPermissions(tokenId, kernelPermList);
}

int32_t AccessTokenManagerClient::GetReqPermissionByName(
    AccessTokenID tokenId, const std::string& permissionName, std::string& value)
{
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Proxy is null");
        return AccessTokenError::ERR_SERVICE_ABNORMAL;
    }
    return proxy->GetReqPermissionByName(tokenId, permissionName, value);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
