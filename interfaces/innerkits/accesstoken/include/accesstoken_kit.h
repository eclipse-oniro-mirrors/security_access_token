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

#ifndef INTERFACES_INNER_KITS_ACCESSTOKEN_KIT_H
#define INTERFACES_INNER_KITS_ACCESSTOKEN_KIT_H

#include <string>
#include <vector>

#include "access_token.h"
#include "hap_token_info.h"
#include "native_token_info.h"
#include "permission_def.h"
#include "permission_state_full.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenKit {
public:
    static AccessTokenIDEx AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policy);
    static AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID);
    static int UpdateHapToken(AccessTokenID tokenID, const std::string& appIDDesc, const HapPolicyParams& policy);
    static int DeleteToken(AccessTokenID tokenID);
    static ATokenTypeEnum GetTokenType(AccessTokenID tokenID);
    static int CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap);
    static AccessTokenID GetHapTokenID(int userID, const std::string& bundleName, int instIndex);
    static int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes);
    static int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes);
    static int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    static int VerifyAccessToken(
        AccessTokenID callerTokenID, AccessTokenID firstTokenID, const std::string& permissionName);
    static int GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult);
    static int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList);
    static int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant);
    static int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName);
    static int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag);
    static int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag);
    static int ClearUserGrantedPermissionState(AccessTokenID tokenID);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif
