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

#ifndef INTERFACES_INNER_KITS_ACCESSTOKEN_KIT_H
#define INTERFACES_INNER_KITS_ACCESSTOKEN_KIT_H

#include <string>
#include <vector>

#include "access_token.h"
#include "hap_token_info.h"
#include "native_token_info.h"
#include "permission_def.h"
#include "permission_list_state.h"
#include "permission_state_change_info.h"
#include "permission_state_full.h"
#include "perm_state_change_callback_customize.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenKit {
public:
    static AccessTokenIDEx AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policy);
    static AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID);
    static int UpdateHapToken(
        AccessTokenID tokenID, const std::string& appIDDesc, int32_t apiVersion, const HapPolicyParams& policy);
    static int DeleteToken(AccessTokenID tokenID);
    /* Get token type by ATM service */
    static ATokenTypeEnum GetTokenType(AccessTokenID tokenID);
    /* Get token type from flag in tokenId, which doesn't depend on ATM service */
    static ATokenTypeEnum GetTokenTypeFlag(AccessTokenID tokenID);
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
    static int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, int& flag);
    static PermissionOper GetSelfPermissionsState(std::vector<PermissionListState>& permList);
    static int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag);
    static int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag);
    static int ClearUserGrantedPermissionState(AccessTokenID tokenID);
    static int32_t RegisterPermStateChangeCallback(
        const std::shared_ptr<PermStateChangeCallbackCustomize>& callback);
    static int32_t UnRegisterPermStateChangeCallback(const std::shared_ptr<PermStateChangeCallbackCustomize>& callback);
    static int32_t GetVersion(void);
    static int32_t GetHapDlpFlag(AccessTokenID tokenID);
    static int32_t ReloadNativeTokenInfo();
    static AccessTokenID GetNativeTokenId(const std::string& processName);

#ifdef TOKEN_SYNC_ENABLE
    static int GetHapTokenInfoFromRemote(AccessTokenID tokenID, HapTokenInfoForSync& hapSync);
    static int GetAllNativeTokenInfo(std::vector<NativeTokenInfoForSync>& nativeTokenInfosRes);
    static int SetRemoteHapTokenInfo(const std::string& deviceID, const HapTokenInfoForSync& hapSync);
    static int SetRemoteNativeTokenInfo(const std::string& deviceID,
        const std::vector<NativeTokenInfoForSync>& nativeTokenInfoList);
    static int DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID);
    static AccessTokenID GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID);
    static int DeleteRemoteDeviceTokens(const std::string& deviceID);
#endif
    static void DumpTokenInfo(AccessTokenID tokenID, std::string& dumpInfo);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif
