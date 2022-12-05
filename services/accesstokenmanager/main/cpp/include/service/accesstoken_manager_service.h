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

#ifndef ACCESSTOKEN_MANAGER_SERVICE_H
#define ACCESSTOKEN_MANAGER_SERVICE_H

#include <string>
#include <vector>
#include <mutex>

#include "accesstoken_manager_stub.h"
#include "iremote_object.h"
#include "nocopyable.h"
#include "singleton.h"
#include "system_ability.h"
#include "hap_token_info.h"
#include "access_token.h"

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

    AccessTokenIDEx AllocHapToken(const HapInfoParcel& info, const HapPolicyParcel& policy) override;
    int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName) override;
    int GetDefPermission(const std::string& permissionName, PermissionDefParcel& permissionDefResult) override;
    int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDefParcel>& permList) override;
    int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFullParcel>& reqPermList, bool isSystemGrant) override;
    PermissionOper GetSelfPermissionsState(
        std::vector<PermissionListStateParcel>& reqPermList) override;
    int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, int& flag) override;
    int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag) override;
    int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag) override;
    int ClearUserGrantedPermissionState(AccessTokenID tokenID) override;
    int DeleteToken(AccessTokenID tokenID) override;
    int GetTokenType(AccessTokenID tokenID) override;
    int CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap) override;
    AccessTokenID GetHapTokenID(int userID, const std::string& bundleName, int instIndex) override;
    AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID) override;
    int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& infoParcel) override;
    int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& infoParcel) override;
    int UpdateHapToken(AccessTokenID tokenID,
        const std::string& appIDDesc, int32_t apiVersion, const HapPolicyParcel& policyParcel) override;
    int32_t RegisterPermStateChangeCallback(
        const PermStateChangeScopeParcel& scope, const sptr<IRemoteObject>& callback) override;
    int32_t UnRegisterPermStateChangeCallback(const sptr<IRemoteObject>& callback) override;
    int32_t ReloadNativeTokenInfo() override;
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
    void CreateDeviceListener();
    void DestroyDeviceListener();
#endif

    void DumpTokenInfo(AccessTokenID tokenID, std::string& dumpInfo) override;
    int Dump(int fd, const std::vector<std::u16string>& args) override;

private:
    bool Initialize();

    ServiceRunningState state_;
    std::mutex mutex_;
    bool isListened_ = false;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_MANAGER_SERVICE_H
