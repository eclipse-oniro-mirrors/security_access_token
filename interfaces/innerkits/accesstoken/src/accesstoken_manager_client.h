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

#ifndef ACCESSTOKEN_MANAGER_CLIENT_H
#define ACCESSTOKEN_MANAGER_CLIENT_H

#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "access_token.h"
#include "accesstoken_death_recipient.h"
#include "hap_info_parcel.h"
#include "hap_policy_parcel.h"
#include "hap_token_info.h"
#include "i_accesstoken_manager.h"
#include "native_token_info.h"
#include "nocopyable.h"
#include "permission_def.h"
#include "permission_state_change_callback.h"
#include "permission_state_full.h"
#include "perm_state_change_callback_customize.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenManagerClient final {
public:
    static AccessTokenManagerClient& GetInstance();

    virtual ~AccessTokenManagerClient();

    int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    int GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult);
    int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList);
    int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant);
    int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, int& flag);
    PermissionOper GetSelfPermissionsState(std::vector<PermissionListState>& permList);
    int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag);
    int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag);
    int ClearUserGrantedPermissionState(AccessTokenID tokenID);
    AccessTokenIDEx AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policy);
    int DeleteToken(AccessTokenID tokenID);
    ATokenTypeEnum GetTokenType(AccessTokenID tokenID);
    int CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap);
    AccessTokenID GetHapTokenID(int userID, const std::string& bundleName, int instIndex);
    AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID);
    int UpdateHapToken(
        AccessTokenID tokenID, const std::string& appIDDesc, int32_t apiVersion, const HapPolicyParams& policy);
    int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes);
    int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes);
    int32_t ReloadNativeTokenInfo();
    AccessTokenID GetNativeTokenId(const std::string& processName);
    int32_t RegisterPermStateChangeCallback(
        const std::shared_ptr<PermStateChangeCallbackCustomize>& customizedCb);
    int32_t UnRegisterPermStateChangeCallback(
        const std::shared_ptr<PermStateChangeCallbackCustomize>& customizedCb);

#ifdef TOKEN_SYNC_ENABLE
    int GetHapTokenInfoFromRemote(AccessTokenID tokenID, HapTokenInfoForSync& hapSync);
    int GetAllNativeTokenInfo(std::vector<NativeTokenInfoForSync>& nativeTokenInfosRes);
    int SetRemoteHapTokenInfo(const std::string& deviceID, const HapTokenInfoForSync& hapSync);
    int SetRemoteNativeTokenInfo(const std::string& deviceID,
        const std::vector<NativeTokenInfoForSync>& nativeTokenInfoList);
    int DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID);
    AccessTokenID GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID);
    int DeleteRemoteDeviceTokens(const std::string& deviceID);
#endif

    void DumpTokenInfo(AccessTokenID tokenID, std::string& dumpInfo);
    void OnRemoteDiedHandle();

private:
    AccessTokenManagerClient();
    int32_t CreatePermStateChangeCallback(
        const std::shared_ptr<PermStateChangeCallbackCustomize>& customizedCb,
        sptr<PermissionStateChangeCallback>& callback);

    DISALLOW_COPY_AND_MOVE(AccessTokenManagerClient);
    std::mutex proxyMutex_;
    sptr<IAccessTokenManager> proxy_ = nullptr;
    sptr<AccessTokenDeathRecipient> serviceDeathObserver_ = nullptr;
    void InitProxy();
    sptr<IAccessTokenManager> GetProxy();
    std::mutex callbackMutex_;
    std::map<std::shared_ptr<PermStateChangeCallbackCustomize>, sptr<PermissionStateChangeCallback>> callbackMap_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_MANAGER_CLIENT_H
