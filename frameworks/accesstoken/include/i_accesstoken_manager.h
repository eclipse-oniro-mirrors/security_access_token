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

#ifndef I_ACCESSTOKEN_MANAGER_H
#define I_ACCESSTOKEN_MANAGER_H

#include <string>

#include "access_token.h"
#include "errors.h"
#include "hap_info_parcel.h"
#include "hap_policy_parcel.h"
#include "hap_token_info_for_sync_parcel.h"
#include "hap_token_info_parcel.h"
#include "iremote_broker.h"
#include "i_permission_state_callback.h"
#include "native_token_info_for_sync_parcel.h"
#include "native_token_info_parcel.h"
#include "permission_def_parcel.h"
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

    virtual int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName) = 0;
    virtual int GetDefPermission(const std::string& permissionName, PermissionDefParcel& permissionDefResult) = 0;
    virtual int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDefParcel>& permList) = 0;
    virtual int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFullParcel>& reqPermList, bool isSystemGrant) = 0;
    virtual int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, int& flag) = 0;
    virtual PermissionOper GetSelfPermissionsState(
        std::vector<PermissionListStateParcel>& permListParcel) = 0;
    virtual int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag) = 0;
    virtual int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag) = 0;
    virtual int ClearUserGrantedPermissionState(AccessTokenID tokenID) = 0;
    virtual AccessTokenIDEx AllocHapToken(const HapInfoParcel& hapInfo, const HapPolicyParcel& policyParcel) = 0;
    virtual int DeleteToken(AccessTokenID tokenID) = 0;
    virtual int GetTokenType(AccessTokenID tokenID) = 0;
    virtual int CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap) = 0;
    virtual AccessTokenID GetHapTokenID(int userID, const std::string& bundleName, int instIndex) = 0;
    virtual AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID) = 0;
    virtual int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& nativeTokenInfoRes) = 0;
    virtual int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& hapTokenInfoRes) = 0;
    virtual int UpdateHapToken(AccessTokenID tokenID, const std::string& appIDDesc, int32_t apiVersion,
        const HapPolicyParcel& policyParcel) = 0;
    virtual int32_t RegisterPermStateChangeCallback(
        const PermStateChangeScopeParcel& scope, const sptr<IRemoteObject>& callback) = 0;
    virtual int32_t UnRegisterPermStateChangeCallback(const sptr<IRemoteObject>& callback) = 0;
    virtual int32_t ReloadNativeTokenInfo() = 0;
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
#endif

    virtual void DumpTokenInfo(AccessTokenID tokenID, std::string& tokenInfo) = 0;

    enum class InterfaceCode {
        VERIFY_ACCESSTOKEN = 0xff10,
        GET_DEF_PERMISSION,
        GET_DEF_PERMISSIONS,
        GET_REQ_PERMISSIONS,
        GET_PERMISSION_FLAG,
        GRANT_PERMISSION,
        REVOKE_PERMISSION,
        CLEAR_USER_GRANT_PERMISSION,
        ALLOC_TOKEN_HAP,
        TOKEN_DELETE,

        GET_TOKEN_TYPE = 0xff20,
        CHECK_NATIVE_DCAP,
        GET_HAP_TOKEN_ID,
        ALLOC_LOCAL_TOKEN_ID,
        GET_NATIVE_TOKENINFO,
        GET_HAP_TOKENINFO,
        UPDATE_HAP_TOKEN,

        GET_HAP_TOKEN_FROM_REMOTE = 0xff30,
        GET_ALL_NATIVE_TOKEN_FROM_REMOTE,
        SET_REMOTE_HAP_TOKEN_INFO,
        SET_REMOTE_NATIVE_TOKEN_INFO,
        DELETE_REMOTE_TOKEN_INFO,
        DELETE_REMOTE_DEVICE_TOKEN,
        GET_NATIVE_REMOTE_TOKEN,

        DUMP_TOKENINFO = 0xff50,
        GET_PERMISSION_OPER_STATE,
        REGISTER_PERM_STATE_CHANGE_CALLBACK,
        UNREGISTER_PERM_STATE_CHANGE_CALLBACK,
        RELOAD_NATIVE_TOKEN_INFO,
        GET_NATIVE_TOKEN_ID,
    };
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // I_ACCESSTOKEN_MANAGER_H
