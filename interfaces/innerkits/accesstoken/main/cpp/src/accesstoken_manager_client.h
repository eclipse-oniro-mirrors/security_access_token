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

#ifndef ACCESSTOKEN_MANAGER_CLIENT_H
#define ACCESSTOKEN_MANAGER_CLIENT_H

#include <string>
#include <vector>

#include "access_token.h"
#include "hap_info_parcel.h"
#include "hap_policy_parcel.h"
#include "hap_token_info.h"
#include "i_accesstoken_manager.h"
#include "native_token_info.h"
#include "nocopyable.h"
#include "permission_def.h"
#include "permission_state_full.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenManagerClient final {
public:
    static AccessTokenManagerClient& GetInstance();

    virtual ~AccessTokenManagerClient();

    int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName) const;
    int GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult) const;
    int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList) const;
    int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant) const;
    int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName) const;
    int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag) const;
    int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag) const;
    int ClearUserGrantedPermissionState(AccessTokenID tokenID) const;
    AccessTokenIDEx AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policy) const;
    int DeleteToken(AccessTokenID tokenID) const;
    int GetTokenType(AccessTokenID tokenID) const;
    int CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap) const;
    AccessTokenID GetHapTokenID(int userID, const std::string& bundleName, int instIndex) const;
    AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID) const;
    int UpdateHapToken(AccessTokenID tokenID, const std::string& appIDDesc, const HapPolicyParams& policy) const;
    int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes) const;
    int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes) const;

private:
    AccessTokenManagerClient();

    DISALLOW_COPY_AND_MOVE(AccessTokenManagerClient);

    sptr<IAccessTokenManager> GetProxy() const;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_MANAGER_CLIENT_H
