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

#ifndef I_ACCESSTOKEN_MANAGER_H
#define I_ACCESSTOKEN_MANAGER_H

#include <string>

#include "access_token.h"
#include "accesstoken_service_ipc_interface_code.h"
#include "atm_tools_param_info_parcel.h"
#include "errors.h"
#include "hap_base_info_parcel.h"
#include "hap_info_parcel.h"
#include "hap_policy_parcel.h"
#include "hap_token_info_for_sync_parcel.h"
#include "hap_token_info_parcel.h"
#include "iremote_broker.h"
#include "i_permission_state_callback.h"
#include "native_token_info_for_sync_parcel.h"
#include "native_token_info_parcel.h"
#include "permission_def_parcel.h"
#include "permission_grant_info_parcel.h"
#include "permission_list_state_parcel.h"
#include "permission_state_full_parcel.h"
#include "permission_state_change_scope_parcel.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class IAccessTokenManager : public IRemoteBroker {
public:
    static const int SA_ID_ACCESSTOKEN_MANAGER_SERVICE = ACCESS_TOKEN_MANAGER_SERVICE_ID;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.accesstoken.IAccessTokenManager");

    virtual PermUsedTypeEnum GetUserGrantedPermissionUsedType(
        AccessTokenID tokenID, const std::string& permissionName) = 0;
    virtual int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName) = 0;
    virtual int GetDefPermission(const std::string& permissionName, PermissionDefParcel& permissionDefResult) = 0;
    virtual int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDefParcel>& permList) = 0;
    virtual int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFullParcel>& reqPermList, bool isSystemGrant) = 0;
    virtual int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag) = 0;
    virtual int32_t SetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t status,
        int32_t userID = 0) = 0;
    virtual int32_t GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status,
        int32_t userID = 0) = 0;
    virtual PermissionOper GetSelfPermissionsState(std::vector<PermissionListStateParcel>& permListParcel,
        PermissionGrantInfoParcel& infoParcel) = 0;
    virtual int32_t GetPermissionsStatus(
        AccessTokenID tokenID, std::vector<PermissionListStateParcel>& permListParcel) = 0;
    virtual int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag) = 0;
    virtual int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag) = 0;
    virtual int ClearUserGrantedPermissionState(AccessTokenID tokenID) = 0;
    virtual AccessTokenIDEx AllocHapToken(const HapInfoParcel& hapInfo, const HapPolicyParcel& policyParcel) = 0;
    virtual int32_t InitHapToken(const HapInfoParcel& info, HapPolicyParcel& policy,
        AccessTokenIDEx& fullTokenId) = 0;
    virtual int DeleteToken(AccessTokenID tokenID) = 0;
    virtual int GetTokenType(AccessTokenID tokenID) = 0;
    virtual int CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap) = 0;
    virtual AccessTokenIDEx GetHapTokenID(int32_t userID, const std::string& bundleName, int32_t instIndex) = 0;
    virtual AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID) = 0;
    virtual int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& nativeTokenInfoRes) = 0;
    virtual int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& hapTokenInfoRes) = 0;
    virtual int32_t UpdateHapToken(
        AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info, const HapPolicyParcel& policyParcel) = 0;
    virtual int32_t RegisterPermStateChangeCallback(
        const PermStateChangeScopeParcel& scope, const sptr<IRemoteObject>& callback) = 0;
    virtual int32_t UnRegisterPermStateChangeCallback(const sptr<IRemoteObject>& callback) = 0;
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    virtual int32_t ReloadNativeTokenInfo() = 0;
#endif
    virtual AccessTokenID GetNativeTokenId(const std::string& processName) = 0;

#ifdef TOKEN_SYNC_ENABLE
    virtual int GetHapTokenInfoFromRemote(AccessTokenID tokenID,
        HapTokenInfoForSyncParcel& hapSyncParcel) = 0;
    virtual int GetAllNativeTokenInfo(std::vector<NativeTokenInfoForSyncParcel>& nativeTokenInfoRes)  = 0;
    virtual int SetRemoteHapTokenInfo(const std::string& deviceID,
        HapTokenInfoForSyncParcel& hapSyncParcel) = 0;
    virtual int SetRemoteNativeTokenInfo(const std::string& deviceID,
        std::vector<NativeTokenInfoForSyncParcel>& nativeTokenInfoForSyncParcel)  = 0;
    virtual int DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID) = 0;
    virtual AccessTokenID GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID) = 0;
    virtual int DeleteRemoteDeviceTokens(const std::string& deviceID)  = 0;
    virtual int32_t RegisterTokenSyncCallback(const sptr<IRemoteObject>& callback) = 0;
    virtual int32_t UnRegisterTokenSyncCallback() = 0;
#endif

    virtual int SetPermDialogCap(const HapBaseInfoParcel& hapBaseInfoParcel, bool enable) = 0;
    virtual void DumpTokenInfo(const AtmToolsParamInfoParcel& infoParcel, std::string& tokenInfo) = 0;
    virtual int32_t DumpPermDefInfo(std::string& tokenInfo) = 0;
    virtual int32_t GetVersion(uint32_t& version) = 0;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // I_ACCESSTOKEN_MANAGER_H
