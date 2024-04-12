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

#ifndef ACCESSTOKEN_MANAGER_PROXY_H
#define ACCESSTOKEN_MANAGER_PROXY_H

#include <string>
#include <vector>

#include "access_token.h"
#include "atm_tools_param_info_parcel.h"
#include "hap_info_parcel.h"
#include "hap_base_info_parcel.h"
#include "hap_policy_parcel.h"
#include "hap_token_info_parcel.h"
#include "hap_token_info_for_sync_parcel.h"
#include "i_accesstoken_manager.h"
#include "iremote_proxy.h"
#include "native_token_info_for_sync_parcel.h"
#include "native_token_info_parcel.h"
#include "permission_def_parcel.h"
#include "permission_grant_info_parcel.h"
#include "permission_list_state_parcel.h"
#include "permission_state_full_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenManagerProxy : public IRemoteProxy<IAccessTokenManager> {
public:
    explicit AccessTokenManagerProxy(const sptr<IRemoteObject>& impl);
    ~AccessTokenManagerProxy() override;

    PermUsedTypeEnum GetUserGrantedPermissionUsedType(
        AccessTokenID tokenID, const std::string& permissionName) override;
    int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName) override;
    int GetDefPermission(const std::string& permissionName, PermissionDefParcel& permissionDefResult) override;
    int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDefParcel>& permList) override;
    int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFullParcel>& reqPermList, bool isSystemGrant) override;
    int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag) override;
    int32_t SetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t status,
        int32_t userID) override;
    int32_t GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status,
        int32_t userID) override;
    int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag) override;
    int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag) override;
    PermissionOper GetSelfPermissionsState(std::vector<PermissionListStateParcel>& permListParcel,
        PermissionGrantInfoParcel& infoParcel) override;
    int32_t GetPermissionsStatus(
        AccessTokenID tokenID, std::vector<PermissionListStateParcel>& permListParcel) override;
    int ClearUserGrantedPermissionState(AccessTokenID tokenID) override;
    int GetTokenType(AccessTokenID tokenID) override;
    int CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap) override;
    AccessTokenIDEx GetHapTokenID(int32_t userID, const std::string& bundleName, int32_t instIndex) override;
    AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID) override;
    AccessTokenIDEx AllocHapToken(const HapInfoParcel& hapInfo, const HapPolicyParcel& policyParcel) override;
    int32_t InitHapToken(const HapInfoParcel& hapInfoParcel, HapPolicyParcel& policyParcel,
        AccessTokenIDEx& fullTokenId) override;
    int DeleteToken(AccessTokenID tokenID) override;
    int32_t UpdateHapToken(
        AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info, const HapPolicyParcel& policyParcel) override;
    int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& hapTokenInfoRes) override;
    int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& nativeTokenInfoRes) override;
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    int32_t ReloadNativeTokenInfo() override;
#endif
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
    int32_t RegisterTokenSyncCallback(const sptr<IRemoteObject>& callback) override;
    int32_t UnRegisterTokenSyncCallback() override;
#endif

    int32_t SetPermDialogCap(const HapBaseInfoParcel& hapBaseInfo, bool enable) override;
    void DumpTokenInfo(const AtmToolsParamInfoParcel& infoParcel, std::string& dumpInfo) override;
    int32_t DumpPermDefInfo(std::string& dumpInfo) override;
    int32_t GetVersion(uint32_t& version) override;

private:
    bool SendRequest(AccessTokenInterfaceCode code, MessageParcel& data, MessageParcel& reply);
    static inline BrokerDelegator<AccessTokenManagerProxy> delegator_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_MANAGER_PROXY_H
