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

#ifndef PERMISSION_MANAGER_H
#define PERMISSION_MANAGER_H

#include <mutex>
#include <vector>
#include <shared_mutex>
#include <string>

#include "ability_manager_access_loader.h"
#include "access_token.h"
#include "generic_values.h"
#include "hap_token_info_inner.h"
#include "iremote_broker.h"
#include "libraryloader.h"
#include "nocopyable.h"
#include "permission_def.h"
#include "permission_grant_event.h"
#include "permission_list_state.h"
#include "permission_list_state_parcel.h"
#include "permission_map.h"
#include "permission_state_change_info.h"
#include "permission_status.h"
#include "temp_permission_observer.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
constexpr const char* VAGUE_LOCATION_PERMISSION_NAME = "ohos.permission.APPROXIMATELY_LOCATION";
constexpr const char* ACCURATE_LOCATION_PERMISSION_NAME = "ohos.permission.LOCATION";
constexpr const char* BACKGROUND_LOCATION_PERMISSION_NAME = "ohos.permission.LOCATION_IN_BACKGROUND";
const int32_t ACCURATE_LOCATION_API_VERSION = 9;
const int32_t BACKGROUND_LOCATION_API_VERSION = 11;
const uint32_t PERMISSION_NOT_REQUSET = -1;
struct LocationIndex {
    uint32_t vagueIndex = PERMISSION_NOT_REQUSET;
    uint32_t accurateIndex = PERMISSION_NOT_REQUSET;
    uint32_t backIndex = PERMISSION_NOT_REQUSET;
};
class PermissionManager {
public:
    static PermissionManager& GetInstance();
    PermissionManager();
    virtual ~PermissionManager();

    void RegisterApplicationCallback();
    void RegisterAppManagerDeathCallback();
    int VerifyHapAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    PermUsedTypeEnum GetPermissionUsedType(AccessTokenID tokenID, const std::string& permissionName);
    int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStatus>& reqPermList, bool isSystemGrant);
    int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag);
    int32_t RequestAppPermOnSetting(const HapTokenInfo& hapInfo,
        const std::string& bundleName, const std::string& abilityName);
    int32_t CheckAndUpdatePermission(AccessTokenID tokenID, const std::string& permissionName,
        bool isGranted, uint32_t flag);
    int32_t CheckAndUpdatePermissionInner(AccessTokenID tokenID, const std::string& permissionName,
        bool isGranted, uint32_t flag);
    int32_t CheckMultiPermissionStatus(
        AccessTokenID tokenID, const std::vector<std::string>& permissionList, int32_t status, uint32_t flag);
    int32_t UpdateMultiPermissionStatus(
        AccessTokenID tokenID, const std::vector<std::string> &permissionList, int32_t status, uint32_t flag);
    int32_t CheckAndUpdateMultiPermissionStatus(
        AccessTokenID tokenID, const std::vector<std::string>& permissionList, int32_t status, uint32_t flag);
    int32_t UpdatePermission(AccessTokenID tokenID, const std::string& permissionName,
        bool isGranted, uint32_t flag, bool needKill);
    int32_t GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag);
    int32_t RevokePermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag);
    int32_t GrantPermissionForSpecifiedTime(
        AccessTokenID tokenID, const std::string& permissionName, uint32_t onceTime);
    int32_t SetPermissionStatusWithPolicy(
        AccessTokenID tokenID, const std::vector<std::string>& permissionList, int32_t status, uint32_t flag);
    void GetSelfPermissionState(const std::vector<PermissionStatus>& permsList,
        PermissionListState& permState, int32_t apiVersion);
    int32_t AddPermStateChangeCallback(
        const PermStateChangeScope& scope, const sptr<IRemoteObject>& callback);
    int32_t RemovePermStateChangeCallback(const sptr<IRemoteObject>& callback);
    bool GetApiVersionByTokenId(AccessTokenID tokenID, int32_t& apiVersion);
    bool LocationPermissionSpecialHandle(AccessTokenID tokenID, std::vector<PermissionListStateParcel>& reqPermList,
        std::vector<PermissionStatus>& permsList, int32_t apiVersion);
    void NotifyPermGrantStoreResult(bool result, uint64_t timestamp);
    void ParamUpdate(const std::string& permissionName, uint32_t flag, bool filtered);
    void ParamFlagUpdate();
    void NotifyWhenPermissionStateUpdated(AccessTokenID tokenID, const std::string& permissionName,
        bool isGranted, uint32_t flag, const std::shared_ptr<HapTokenInfoInner>& infoPtr);
    void AddNativePermToKernel(
        AccessTokenID tokenID, const std::vector<uint32_t>& opCodeList, const std::vector<bool>& statusList);
    void AddHapPermToKernel(AccessTokenID tokenID, const std::vector<std::string>& permList);
    void RemovePermFromKernel(AccessTokenID tokenID);
    void SetPermToKernel(AccessTokenID tokenID, const std::string& permissionName, bool isGranted);
    bool InitPermissionList(const HapInitInfo& initInfo, std::vector<PermissionStatus>& initializedList,
        HapInfoCheckResult& result, std::vector<GenericValues>& undefValues);
    bool InitDlpPermissionList(const std::string& bundleName, int32_t userId,
        std::vector<PermissionStatus>& initializedList, std::vector<GenericValues>& undefValues);
    void NotifyUpdatedPermList(const std::vector<std::string>& grantedPermListBefore,
        const std::vector<std::string>& grantedPermListAfter, AccessTokenID tokenID);
    bool IsPermAvailableRangeSatisfied(const PermissionBriefDef& briefDef, const std::string& appDistributionType,
        bool isSystemApp, PermissionRulesEnum& rule, const HapInitInfo& initInfo);

protected:
    static void RegisterImpl(PermissionManager* implInstance);
private:
    void ScopeToString(
        const std::vector<AccessTokenID>& tokenIDs, const std::vector<std::string>& permList);
    int32_t ScopeFilter(const PermStateChangeScope& scopeSrc, PermStateChangeScope& scopeRes);
    int32_t UpdateTokenPermissionState(const std::shared_ptr<HapTokenInfoInner>& infoPtr, AccessTokenID tokenID,
        const std::string& permission, bool isGranted, uint32_t flag, bool needKill);
    int32_t UpdateMultiTokenPermissionState(const std::shared_ptr<HapTokenInfoInner> &infoPtr, AccessTokenID tokenID,
        const std::vector<std::string> &permissionList, bool isGranted, uint32_t flag, bool needKill);
    int32_t UpdateMultiTokenPermissionStateCheck(const std::shared_ptr<HapTokenInfoInner> &infoPtr,
        AccessTokenID tokenID, const std::vector<std::string> &permissionList);
    int32_t UpdateTokenPermissionState(
        AccessTokenID id, const std::string& permission, bool isGranted, uint32_t flag, bool needKill);
    int32_t UpdateTokenPermissionStateCheck(const std::shared_ptr<HapTokenInfoInner>& infoPtr,
        AccessTokenID id, const std::string& permission, bool isGranted, uint32_t flag);
    bool IsPermissionVaild(const std::string& permissionName);
    bool GetLocationPermissionIndex(std::vector<PermissionListStateParcel>& reqPermList, LocationIndex& locationIndex);
    bool GetLocationPermissionState(AccessTokenID tokenID, std::vector<PermissionListStateParcel>& reqPermList,
        std::vector<PermissionStatus>& permsList, int32_t apiVersion, const LocationIndex& locationIndex);
    void FillUndefinedPermVector(const std::string& permissionName, const std::string& appDistributionType,
        const HapPolicy& policy, std::vector<GenericValues>& undefValues);
    bool AclAndEdmCheck(const PermissionBriefDef& briefDef, const HapInitInfo& initInfo,
        const std::string& permissionName, const std::string& appDistributionType, HapInfoCheckResult& result);
    void GetMasterAppUndValues(AccessTokenID tokenId, std::vector<GenericValues>& undefValues);
    std::shared_ptr<LibraryLoader> GetAbilityManager();
    bool HandlePermissionDeniedCase(uint32_t goalGrantFlag, PermissionListState& permState);

    PermissionGrantEvent grantEvent_;
    static std::recursive_mutex mutex_;
    static PermissionManager* implInstance_;

    std::shared_mutex permParamSetLock_;
    uint64_t paramValue_ = 0;

    std::shared_mutex permFlagParamSetLock_;
    uint64_t paramFlagValue_ = 0;

    DISALLOW_COPY_AND_MOVE(PermissionManager);

    std::mutex abilityManagerMutex_;
    std::shared_ptr<LibraryLoader> abilityManagerLoader_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_MANAGER_H
