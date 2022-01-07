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

#ifndef I_ACCESSTOKEN_MANAGER_H
#define I_ACCESSTOKEN_MANAGER_H

#include <string>

#include "iremote_broker.h"
#include "errors.h"

#include "access_token.h"
#include "permission_def_parcel.h"
#include "permission_state_full_parcel.h"
#include "hap_policy_parcel.h"
#include "hap_token_info_parcel.h"
#include "hap_info_parcel.h"
#include "native_token_info_parcel.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class IAccessTokenManager : public IRemoteBroker {
public:
    static const int SA_ID_ACCESSTOKEN_MANAGER_SERVICE = 3503;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.accesstoken.IAccessTokenManager");

    virtual int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName) = 0;
    virtual int GetDefPermission(const std::string& permissionName, PermissionDefParcel& permissionDefResult) = 0;
    virtual int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDefParcel>& permList) = 0;
    virtual int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFullParcel>& reqPermList, bool isSystemGrant) = 0;
    virtual int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName) = 0;
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
    virtual int UpdateHapToken(
        AccessTokenID tokenID, const std::string& appIDDesc, const HapPolicyParcel& policyParcel) = 0;

    enum class InterfaceCode {
        VERIFY_ACCESSTOKEN = 0xff10,
        GET_DEF_PERMISSION = 0xff11,
        GET_DEF_PERMISSIONS = 0xff12,
        GET_REQ_PERMISSIONS = 0xff13,
        GET_PERMISSION_FLAG = 0xff14,
        GRANT_PERMISSION = 0xff15,
        REVOKE_PERMISSION = 0xff16,
        CLEAR_USER_GRANT_PERMISSION = 0xff17,
        ALLOC_TOKEN_HAP = 0xff18,
        TOKEN_DELETE = 0xff19,
        GET_TOKEN_TYPE = 0xff20,
        CHECK_NATIVE_DCAP = 0xff21,
        GET_HAP_TOKEN_ID = 0xff22,
        ALLOC_LOCAL_TOKEN_ID = 0xff23,
        GET_NATIVE_TOKENINFO = 0xff24,
        GET_HAP_TOKENINFO = 0xff25,
        UPDATE_HAP_TOKEN = 0xff26,
    };
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // I_ACCESSTOKEN_MANAGER_H
