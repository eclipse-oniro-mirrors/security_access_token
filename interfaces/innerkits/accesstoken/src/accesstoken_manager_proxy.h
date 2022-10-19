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

#ifndef ACCESSTOKEN_MANAGER_PROXY_H
#define ACCESSTOKEN_MANAGER_PROXY_H

#include <string>
#include <vector>

#include "access_token.h"
#include "hap_info_parcel.h"
#include "hap_policy_parcel.h"
#include "hap_token_info_parcel.h"
#include "hap_token_info_for_sync_parcel.h"
#include "i_accesstoken_manager.h"
#include "iremote_proxy.h"
#include "native_token_info_for_sync_parcel.h"
#include "native_token_info_parcel.h"
#include "permission_def_parcel.h"
#include "permission_list_state_parcel.h"
#include "permission_state_full_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenManagerProxy : public IRemoteProxy<IAccessTokenManager> {
public:
    explicit AccessTokenManagerProxy(const sptr<IRemoteObject>& impl);
    ~AccessTokenManagerProxy() override;

    int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName) override;
    int GetDefPermission(const std::string& permissionName, PermissionDefParcel& permissionDefResult) override;
    int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDefParcel>& permList) override;
    int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFullParcel>& reqPermList, bool isSystemGrant) override;
    int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, int& flag) override;
    int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag) override;
    int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag) override;
    PermissionOper GetSelfPermissionsState(std::vector<PermissionListStateParcel>& permListParcel) override;
    int ClearUserGrantedPermissionState(AccessTokenID tokenID) override;
    int GetTokenType(AccessTokenID tokenID) override;
    int CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap) override;
    AccessTokenID GetHapTokenID(int userID, const std::string& bundleName, int instIndex) override;
    AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID) override;
    AccessTokenIDEx AllocHapToken(const HapInfoParcel& hapInfo, const HapPolicyParcel& policyParcel) override;
    int DeleteToken(AccessTokenID tokenID) override;
    int UpdateHapToken(AccessTokenID tokenID, const std::string& appIDDesc, int32_t apiVersion,
        const HapPolicyParcel& policyParcel) override;
    int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& hapTokenInfoRes) override;
    int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& nativeTokenInfoRes) override;
    int32_t ReloadNativeTokenInfo() override;
    int32_t RegisterPermStateChangeCallback(
        const PermStateChangeScopeParcel& scope, const sptr<IRemoteObject>& callback) override;
    int32_t UnRegisterPermStateChangeCallback(const sptr<IRemoteObject>& callback) override;
    AccessTokenID GetNativeTokenId(const std::string& processName) override;
    
#ifdef TOKEN_SYNC_ENABLE
    int GetHapTokenInfoFromRemote(AccessTokenID tokenID, HapTokenInfoForSyncParcel& hapSyncParcel) override;
    int GetAllNativeTokenInfo(std::vector<NativeTokenInfoForSyncParcel>& nativeTokenInfoRes) override;
    int SetRemoteHapTokenInfo(const std::string& deviceID, HapTokenInfoForSyncParcel& hapSyncParcel) override;
    int SetRemoteNativeTokenInfo(const std::string& deviceID,
        std::vector<NativeTokenInfoForSyncParcel>& nativeTokenInfoForSyncParcel) override;
    int DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID) override;
    AccessTokenID GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID) override;
    int DeleteRemoteDeviceTokens(const std::string& deviceID) override;
#endif

    void DumpTokenInfo(AccessTokenID tokenID, std::string& dumpInfo) override;

private:
    bool SendRequest(IAccessTokenManager::InterfaceCode code, MessageParcel& data, MessageParcel& reply);
    static inline BrokerDelegator<AccessTokenManagerProxy> delegator_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_MANAGER_PROXY_H
