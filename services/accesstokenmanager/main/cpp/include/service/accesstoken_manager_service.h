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

#include <set>
#include <string>
#include <vector>
#include <unordered_set>

#include "access_token_manager_stub.h"
#ifdef EVENTHANDLER_ENABLE
#include "access_event_handler.h"
#endif
#include "access_token.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "iremote_object.h"
#include "json_parse_loader.h"
#include "nocopyable.h"
#include "permission_map.h"
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
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

    int32_t AllocHapToken(const HapInfoParcel& info, const HapPolicyParcel& policy, uint64_t& fullTokenId) override;
    int32_t GetPermissionUsedType(
        AccessTokenID tokenID, const std::string& permissionName, int32_t& permUsedType) override;
    int32_t InitHapToken(const HapInfoParcel& info, const HapPolicyParcel& policy,
        uint64_t& fullTokenId, HapInfoCheckResultIdl& resultInfoIdl) override;
    int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName) override;
    int VerifyAccessToken(AccessTokenID tokenID,
        const std::vector<std::string>& permissionList, std::vector<int32_t>& permStateList) override;
    int GetDefPermission(const std::string& permissionName, PermissionDefParcel& permissionDefResult) override;
    int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStatusParcel>& reqPermList, bool isSystemGrant) override;
    int32_t GetSelfPermissionStatus(const std::string& permissionName, int32_t& status) override;
    int32_t GetSelfPermissionsState(std::vector<PermissionListStateParcel>& reqPermList,
        PermissionGrantInfoParcel& infoParcel, int32_t& permOper) override;
    int32_t GetPermissionsStatus(AccessTokenID tokenID, std::vector<PermissionListStateParcel>& reqPermList) override;
    int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag) override;
    int32_t SetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t status,
        int32_t userID) override;
    int32_t GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status,
        int32_t userID) override;
    int32_t RequestAppPermOnSetting(AccessTokenID tokenID) override;
    int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag) override;
    int RevokePermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag) override;
    int GrantPermissionForSpecifiedTime(
        AccessTokenID tokenID, const std::string& permissionName, uint32_t onceTime) override;
    int ClearUserGrantedPermissionState(AccessTokenID tokenID) override;
    int32_t SetPermissionStatusWithPolicy(
        AccessTokenID tokenID, const std::vector<std::string>& permissionList, int32_t status, uint32_t flag) override;
    int DeleteToken(AccessTokenID tokenID) override;
    int GetTokenType(AccessTokenID tokenID);
    int GetTokenType(AccessTokenID tokenID, int32_t& tokenType) override;
    int32_t GetHapTokenID(
        int32_t userID, const std::string& bundleName, int32_t instIndex, uint64_t& fullTokenId) override;
    int32_t AllocLocalTokenID(
        const std::string& remoteDeviceID, AccessTokenID remoteTokenID, AccessTokenID& tokenId) override;
    int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoParcel& infoParcel) override;
    int32_t GetTokenIDByUserID(int32_t userID, std::vector<AccessTokenID>& tokenIds) override;
    int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfoParcel& infoParcel) override;
    int32_t UpdateHapToken(uint64_t& fullTokenId, const UpdateHapInfoParamsIdl& infoIdl,
        const HapPolicyParcel& policyParcel, HapInfoCheckResultIdl& resultInfoIdl) override;
    int32_t RegisterPermStateChangeCallback(
        const PermStateChangeScopeParcel& scope, const sptr<IRemoteObject>& callback) override;
    int32_t UnRegisterPermStateChangeCallback(const sptr<IRemoteObject>& callback) override;
    int32_t RegisterSelfPermStateChangeCallback(const PermStateChangeScopeParcel& scope,
        const sptr<IRemoteObject>& callback) override;
    int32_t UnRegisterSelfPermStateChangeCallback(const sptr<IRemoteObject>& callback) override;
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    int32_t ReloadNativeTokenInfo() override;
#endif
    int GetHapTokenInfoExtension(AccessTokenID tokenID,
        HapTokenInfoParcel& hapTokenInfoRes, std::string& appID) override;
    int32_t GetNativeTokenId(const std::string& processName, AccessTokenID& tokenID) override;
#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
    int32_t RegisterSecCompEnhance(const SecCompEnhanceDataParcel& enhanceParcel) override;
    int32_t UpdateSecCompEnhance(int32_t pid, uint32_t seqNum) override;
    int32_t GetSecCompEnhance(int32_t pid, SecCompEnhanceDataParcel& enhanceParcel) override;
#endif
    int32_t IsToastShownNeeded(int32_t pid, bool& needToShow) override;

#ifdef TOKEN_SYNC_ENABLE
    int GetHapTokenInfoFromRemote(AccessTokenID tokenID, HapTokenInfoForSyncParcel& hapSyncParcel) override;
    int SetRemoteHapTokenInfo(const std::string& deviceID, const HapTokenInfoForSyncParcel& hapSyncParcel) override;
    int DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID) override;
    int32_t GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID, AccessTokenID& tokenId) override;
    int DeleteRemoteDeviceTokens(const std::string& deviceID) override;
    int32_t RegisterTokenSyncCallback(const sptr<IRemoteObject>& callback) override;
    int32_t UnRegisterTokenSyncCallback() override;
#endif
    int32_t GetKernelPermissions(
        AccessTokenID tokenId, std::vector<PermissionWithValueIdl>& kernelPermIdlList) override;
    int32_t GetReqPermissionByName(
        AccessTokenID tokenId, const std::string& permissionName, std::string& value) override;
    int SetPermDialogCap(const HapBaseInfoParcel& hapBaseInfoParcel, bool enable) override;
    int32_t GetPermissionManagerInfo(PermissionGrantInfoParcel& infoParcel) override;
    int32_t InitUserPolicy(
        const std::vector<UserStateIdl>& userIdlList, const std::vector<std::string>& permList) override;
    int32_t UpdateUserPolicy(const std::vector<UserStateIdl>& userIdlList) override;
    int32_t ClearUserPolicy() override;
    int32_t DumpTokenInfo(const AtmToolsParamInfoParcel& infoParcel, std::string& dumpInfo) override;
    int32_t GetVersion(uint32_t& version) override;
    int Dump(int fd, const std::vector<std::u16string>& args) override;

    int32_t CallbackEnter(uint32_t code) override;
    int32_t CallbackExit(uint32_t code, int32_t result) override;

private:
    void GetValidConfigFilePathList(std::vector<std::string>& pathList);
    bool GetConfigGrantValueFromFile(std::string& fileContent);
    void SetFlagIfNeed(const AccessTokenServiceConfig& atConfig, int32_t& cancelTime, uint32_t& parseConfigFlag);
    void GetConfigValue(uint32_t& parseConfigFlag);
    bool Initialize();
    void AccessTokenServiceParamSet() const;
    PermissionOper GetPermissionsState(AccessTokenID tokenID, std::vector<PermissionListStateParcel>& reqPermList);
    int32_t UpdateHapTokenCore(AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info,
        const HapPolicyParcel& policyParcel, HapInfoCheckResultIdl& resultInfoIdl);
    void ReportAddHap(const HapInfoParcel& info, const HapPolicyParcel& policy);
    void ReportAddHapFinish(AccessTokenIDEx fullTokenId, const HapInfoParcel& info, int64_t beginTime,
        int32_t errorCode);
    int32_t UpdatePermDefVersion(const std::string& permDefVersion);
    bool IsPermissionValid(int32_t hapApl, const PermissionBriefDef& data, const std::string& value, bool isAcl);
    int32_t UpdateUndefinedToDb(const std::vector<GenericValues>& stateValues,
        const std::vector<GenericValues>& extendValues, const std::vector<GenericValues>& validValueList);
    int32_t UpdateUndefinedInfo(const std::vector<GenericValues>& validValueList);
    void HandleHapUndefinedInfo(std::map<int32_t, int32_t>& tokenIdAplMap);
    void HandlePermDefUpdate(std::map<int32_t, int32_t>& tokenIdAplMap);

    ServiceRunningState state_;
    std::string grantBundleName_;
    std::string grantAbilityName_;
    std::string grantServiceAbilityName_;
    std::string permStateAbilityName_;
    std::string globalSwitchAbilityName_;
    std::string applicationSettingAbilityName_;

    bool IsPrivilegedCalling() const;
    bool IsAccessTokenCalling();
    bool IsNativeProcessCalling();
    bool IsSystemAppCalling() const;
    bool IsShellProcessCalling();
    bool IsSecCompServiceCalling();
#ifndef ATM_BUILD_VARIANT_USER_ENABLE
    static const int32_t ROOT_UID = 0;
#endif
    static const int32_t ACCESSTOKEN_UID = 3020;

    AccessTokenID tokenSyncId_ = 0;
    AccessTokenID secCompTokenId_ = 0;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_MANAGER_SERVICE_H
