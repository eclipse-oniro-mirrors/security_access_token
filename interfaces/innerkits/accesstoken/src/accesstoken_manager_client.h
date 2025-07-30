/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include <unordered_set>
#include <vector>

#include "access_token.h"
#include "atm_tools_param_info.h"
#include "accesstoken_death_recipient.h"
#include "hap_token_info.h"
#include "iaccess_token_manager.h"
#include "nocopyable.h"
#include "permission_def.h"
#include "permission_grant_info.h"
#include "accesstoken_callbacks.h"
#include "permission_state_full.h"
#include "perm_state_change_callback_customize.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_sync_kit_interface.h"
#endif // TOKEN_SYNC_ENABLE

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenManagerClient final {
public:
    static AccessTokenManagerClient& GetInstance();

    virtual ~AccessTokenManagerClient();

    PermUsedTypeEnum GetPermissionUsedType(AccessTokenID tokenID, const std::string& permissionName);
    int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    int VerifyAccessToken(AccessTokenID tokenID,
        const std::vector<std::string>& permissionList, std::vector<int32_t>& permStateList);
    int GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult);
    int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant);
    int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag);
    int32_t SetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t status, int32_t userID);
    int32_t GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status, int32_t userID);
    int32_t RequestAppPermOnSetting(AccessTokenID tokenID);
    int32_t GetSelfPermissionStatus(const std::string& permissionName, PermissionOper& status);
    PermissionOper GetSelfPermissionsState(std::vector<PermissionListState>& permList,
        PermissionGrantInfo& info);
    int32_t GetPermissionsStatus(AccessTokenID tokenID, std::vector<PermissionListState>& permList);
    int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag);
    int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag);
    int GrantPermissionForSpecifiedTime(
        AccessTokenID tokenID, const std::string& permissionName, uint32_t onceTime);
    int ClearUserGrantedPermissionState(AccessTokenID tokenID);
    int32_t SetPermissionStatusWithPolicy(
        AccessTokenID tokenID, const std::vector<std::string>& permissionList, int32_t status, uint32_t flag);
    AccessTokenIDEx AllocHapToken(const HapInfoParams& info, const HapPolicy& policy);
    int32_t InitHapToken(const HapInfoParams& info, HapPolicy& policy,
        AccessTokenIDEx& fullTokenId, HapInfoCheckResult& result);
    int DeleteToken(AccessTokenID tokenID);
    ATokenTypeEnum GetTokenType(AccessTokenID tokenID);
    AccessTokenIDEx GetHapTokenID(int32_t userID, const std::string& bundleName, int32_t instIndex);
    AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID);
    int32_t UpdateHapToken(AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info,
        const HapPolicy& policy, HapInfoCheckResult& result);
    int32_t GetTokenIDByUserID(int32_t userID, std::unordered_set<AccessTokenID>& tokenList);
    int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes);
    int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfoRes);
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    int32_t ReloadNativeTokenInfo();
#endif
    int GetHapTokenInfoExtension(AccessTokenID tokenID, HapTokenInfoExt& info);
    AccessTokenID GetNativeTokenId(const std::string& processName);
    int32_t RegisterPermStateChangeCallback(
        const std::shared_ptr<PermStateChangeCallbackCustomize>& customizedCb, RegisterPermChangeType type);
    int32_t UnRegisterPermStateChangeCallback(
        const std::shared_ptr<PermStateChangeCallbackCustomize>& customizedCb, RegisterPermChangeType type);

#ifdef TOKEN_SYNC_ENABLE
    int GetHapTokenInfoFromRemote(AccessTokenID tokenID, HapTokenInfoForSync& hapSync);
    int SetRemoteHapTokenInfo(const std::string& deviceID, const HapTokenInfoForSync& hapSync);
    int DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID);
    AccessTokenID GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID);
    int DeleteRemoteDeviceTokens(const std::string& deviceID);
    int32_t RegisterTokenSyncCallback(const std::shared_ptr<TokenSyncKitInterface>& syncCallback);
    int32_t UnRegisterTokenSyncCallback();
#endif

    int32_t GetKernelPermissions(
        AccessTokenID tokenId, std::vector<PermissionWithValue>& kernelPermList);
    int32_t GetReqPermissionByName(
        AccessTokenID tokenId, const std::string& permissionName, std::string& value);
    void DumpTokenInfo(const AtmToolsParamInfo& info, std::string& dumpInfo);
    int32_t GetVersion(uint32_t& version);
    void OnRemoteDiedHandle();
    int32_t SetPermDialogCap(const HapBaseInfo& hapBaseInfo, bool enable);
    void GetPermissionManagerInfo(PermissionGrantInfo& info);
    int32_t InitUserPolicy(const std::vector<UserState>& userList, const std::vector<std::string>& permList);
    int32_t UpdateUserPolicy(const std::vector<UserState>& userList);
    int32_t ClearUserPolicy();
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
    int32_t RegisterSecCompEnhance(const SecCompEnhanceData& enhance);
    int32_t UpdateSecCompEnhance(int32_t pid, uint32_t seqNum);
    int32_t GetSecCompEnhance(int32_t pid, SecCompEnhanceData& enhance);
#endif // SECURITY_COMPONENT_ENHANCE_ENABLE
    bool IsToastShownNeeded(int32_t pid);

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
    void ReleaseProxy();
    std::mutex callbackMutex_;
    std::map<std::shared_ptr<PermStateChangeCallbackCustomize>, sptr<PermissionStateChangeCallback>> callbackMap_;

#ifdef TOKEN_SYNC_ENABLE
    std::mutex tokenSyncCallbackMutex_;
    std::shared_ptr<TokenSyncKitInterface> syncCallbackImpl_ = nullptr;
    sptr<TokenSyncCallback> tokenSyncCallback_ = nullptr;
#endif // TOKEN_SYNC_ENABLE
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_MANAGER_CLIENT_H
