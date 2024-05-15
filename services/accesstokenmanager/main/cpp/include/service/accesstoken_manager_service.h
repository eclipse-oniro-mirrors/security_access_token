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

#ifndef ACCESSTOKEN_MANAGER_SERVICE_H
#define ACCESSTOKEN_MANAGER_SERVICE_H

#include <string>
#include <vector>

#include "accesstoken_manager_stub.h"
#ifdef EVENTHANDLER_ENABLE
#include "access_event_handler.h"
#endif
#include "access_token.h"
#include "hap_token_info.h"
#include "iremote_object.h"
#include "nocopyable.h"
#include "singleton.h"
#include "system_ability.h"
#include "thread_pool.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class AccessTokenManagerService final : public SystemAbility, public AccessTokenManagerStub {
    DECLARE_DELAYED_SINGLETON(AccessTokenManagerService);
    DECLEAR_SYSTEM_ABILITY(AccessTokenManagerService);

public:
    void OnStart() override;
    void OnStop() override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

    AccessTokenIDEx AllocHapToken(const HapInfoParcel& info, const HapPolicyParcel& policy) override;
    PermUsedTypeEnum GetUserGrantedPermissionUsedType(
        AccessTokenID tokenID, const std::string& permissionName) override;
    int32_t InitHapToken(const HapInfoParcel& info, HapPolicyParcel& policy,
        AccessTokenIDEx& fullTokenId) override;
    int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName) override;
    int GetDefPermission(const std::string& permissionName, PermissionDefParcel& permissionDefResult) override;
    int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDefParcel>& permList) override;
    int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFullParcel>& reqPermList, bool isSystemGrant) override;
    PermissionOper GetSelfPermissionsState(std::vector<PermissionListStateParcel>& reqPermList,
        PermissionGrantInfoParcel& infoParcel) override;
    int32_t GetPermissionsStatus(AccessTokenID tokenID, std::vector<PermissionListStateParcel>& reqPermList) override;
    int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag) override;
    int32_t SetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t status,
        int32_t userID) override;
    int32_t GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status,
        int32_t userID) override;
    int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag) override;
    int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag) override;
    int ClearUserGrantedPermissionState(AccessTokenID tokenID) override;
    int DeleteToken(AccessTokenID tokenID) override;
    int GetTokenType(AccessTokenID tokenID) override;
    int CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap) override;
    AccessTokenIDEx GetHapTokenID(int32_t userID, const std::string& bundleName, int32_t instIndex) override;
    AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID) override;
    int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& infoParcel) override;
    int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& infoParcel) override;
    int32_t UpdateHapToken(AccessTokenIDEx& tokenIdEx,
        const UpdateHapInfoParams& info, const HapPolicyParcel& policyParcel) override;
    int32_t RegisterPermStateChangeCallback(
        const PermStateChangeScopeParcel& scope, const sptr<IRemoteObject>& callback) override;
    int32_t UnRegisterPermStateChangeCallback(const sptr<IRemoteObject>& callback) override;
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    int32_t ReloadNativeTokenInfo() override;
#endif
    AccessTokenID GetNativeTokenId(const std::string& processName) override;

#ifdef TOKEN_SYNC_ENABLE
    int GetHapTokenInfoFromRemote(AccessTokenID tokenID, HapTokenInfoForSyncParcel& hapSyncParcel) override;
    int GetAllNativeTokenInfo(std::vector<NativeTokenInfoForSyncParcel>& nativeTokenInfosRes) override;
    int SetRemoteHapTokenInfo(const std::string& deviceID, HapTokenInfoForSyncParcel& hapSyncParcel) override;
    int SetRemoteNativeTokenInfo(const std::string& deviceID,
        std::vector<NativeTokenInfoForSyncParcel>& nativeTokenInfoForSyncParcel) override;
    int DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID) override;
    AccessTokenID GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID) override;
    int DeleteRemoteDeviceTokens(const std::string& deviceID) override;
    int32_t RegisterTokenSyncCallback(const sptr<IRemoteObject>& callback) override;
    int32_t UnRegisterTokenSyncCallback() override;
#endif

    int SetPermDialogCap(const HapBaseInfoParcel& hapBaseInfoParcel, bool enable) override;
    void DumpTokenInfo(const AtmToolsParamInfoParcel& infoParcel, std::string& dumpInfo) override;
    int32_t DumpPermDefInfo(std::string& dumpInfo) override;
    int32_t GetVersion(uint32_t& version) override;
    int Dump(int fd, const std::vector<std::u16string>& args) override;

private:
    void GetValidConfigFilePathList(std::vector<std::string>& pathList);
    bool GetConfigGrantValueFromFile(std::string& fileContent);
    void SetDefaultConfigValue();
    void GetConfigValue();
    bool Initialize();
    void DumpTokenIfNeeded();
    void AccessTokenServiceParamSet() const;
    PermissionOper GetPermissionsState(AccessTokenID tokenID, std::vector<PermissionListStateParcel>& reqPermList);
#ifdef EVENTHANDLER_ENABLE
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner_;
    std::shared_ptr<AppExecFwk::EventRunner> dumpEventRunner_;
    std::shared_ptr<AccessEventHandler> eventHandler_;
    std::shared_ptr<AccessEventHandler> dumpEventHandler_;
#endif
    ServiceRunningState state_;
    std::string grantBundleName_;
    std::string grantAbilityName_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_MANAGER_SERVICE_H
