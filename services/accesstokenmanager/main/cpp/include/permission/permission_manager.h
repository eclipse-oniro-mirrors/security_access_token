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
#include <string>

#include "access_token.h"
#include "hap_token_info_inner.h"
#include "iremote_broker.h"
#include "permission_def.h"
#include "permission_grant_event.h"
#include "permission_list_state.h"
#include "permission_list_state_parcel.h"
#include "permission_state_change_info.h"
#include "permission_state_full.h"
#include "temp_permission_observer.h"

#include "rwlock.h"
#include "nocopyable.h"

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
    void AddDefPermissions(const std::vector<PermissionDef>& permList, AccessTokenID tokenId,
        bool updateFlag);
    void RemoveDefPermissions(AccessTokenID tokenID);
    int VerifyNativeAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    int VerifyHapAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    PermUsedTypeEnum GetUserGrantedPermissionUsedType(AccessTokenID tokenID, const std::string& permissionName);
    virtual int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    int GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult);
    int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList);
    int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant);
    int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag);
    int32_t SetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t status, int32_t userID);
    int32_t GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status, int32_t userID);
    int32_t CheckAndUpdatePermission(AccessTokenID tokenID, const std::string& permissionName,
        bool isGranted, uint32_t flag);
    int32_t GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag);
    int32_t RevokePermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag);
    void ClearUserGrantedPermissionState(AccessTokenID tokenID);
    void GetSelfPermissionState(const std::vector<PermissionStateFull>& permsList,
        PermissionListState& permState, int32_t apiVersion);
    int32_t AddPermStateChangeCallback(
        const PermStateChangeScope& scope, const sptr<IRemoteObject>& callback);
    int32_t RemovePermStateChangeCallback(const sptr<IRemoteObject>& callback);
    bool GetApiVersionByTokenId(AccessTokenID tokenID, int32_t& apiVersion);
    bool LocationPermissionSpecialHandle(std::vector<PermissionListStateParcel>& reqPermList,
        std::vector<PermissionStateFull>& permsList, int32_t apiVersion);
    void NotifyPermGrantStoreResult(bool result, uint64_t timestamp);
    void ClearAllSecCompGrantedPerm(const std::vector<AccessTokenID>& tokenIdList);
    void ParamUpdate(const std::string& permissionName, uint32_t flag, bool filtered);
    void NotifyWhenPermissionStateUpdated(AccessTokenID tokenID, const std::string& permissionName,
        bool isGranted, uint32_t flag, const std::shared_ptr<HapTokenInfoInner>& infoPtr);
    int32_t ClearUserGrantedPermission(AccessTokenID tokenID);
    int32_t DumpPermDefInfo(std::string& dumpInfo);
    bool IsAllowGrantTempPermission(AccessTokenID tokenID, const std::string& permissionName);
    void AddPermToKernel(AccessTokenID tokenID, const std::shared_ptr<PermissionPolicySet>& policy);
    void RemovePermFromKernel(AccessTokenID tokenID);
    void SetPermToKernel(AccessTokenID tokenID, const std::string& permissionName, bool isGranted);
    bool InitPermissionList(const std::string& appDistributionType,
        const HapPolicyParams& policy, std::vector<PermissionStateFull>& initializedList);
    bool InitDlpPermissionList(const std::string& bundleName, int32_t userId,
        std::vector<PermissionStateFull>& initializedList);
protected:
    static void RegisterImpl(PermissionManager* implInstance);
private:
    void ScopeToString(
        const std::vector<AccessTokenID>& tokenIDs, const std::vector<std::string>& permList);
    int32_t ScopeFilter(const PermStateChangeScope& scopeSrc, PermStateChangeScope& scopeRes);
    int32_t UpdateTokenPermissionState(
        AccessTokenID tokenID, const std::string& permissionName, bool isGranted, uint32_t flag);
    std::string TransferPermissionDefToString(const PermissionDef& inPermissionDef);
    bool IsPermissionVaild(const std::string& permissionName);
    bool GetLocationPermissionIndex(std::vector<PermissionListStateParcel>& reqPermList, LocationIndex& locationIndex);
    bool GetLocationPermissionState(std::vector<PermissionListStateParcel>& reqPermList,
        std::vector<PermissionStateFull>& permsList, int32_t apiVersion);
    bool GetStateWithVaguePermission(std::vector<PermissionListStateParcel>& reqPermList,
        std::vector<PermissionStateFull>& permsList, int32_t apiVersion, const LocationIndex& locationIndex);
    bool GetLocationPermissionStateBackGroundVersion(std::vector<PermissionListStateParcel>& reqPermList,
        std::vector<PermissionStateFull>& permsList, int32_t apiVersion);
    bool GetStateWithVaguePermissionBackGroundVersion(std::vector<PermissionListStateParcel>& reqPermList,
        std::vector<PermissionStateFull>& permsList, int32_t apiVersion, const LocationIndex& locationIndex);
    void NotifyUpdatedPermList(const std::vector<std::string>& grantedPermListBefore,
        const std::vector<std::string>& grantedPermListAfter, AccessTokenID tokenID);
    bool FindPermRequestToggleStatusFromDb(int32_t userID, const std::string& permissionName);
    void AddPermRequestToggleStatusToDb(int32_t userID, const std::string& permissionName);
    void DeletePermRequestToggleStatusFromDb(int32_t userID, const std::string& permissionName);
    void PermDefToString(const PermissionDef& def, std::string& info) const;

    PermissionGrantEvent grantEvent_;
    static std::recursive_mutex mutex_;
    static PermissionManager* implInstance_;

    OHOS::Utils::RWLock permParamSetLock_;
    uint64_t paramValue_ = 0;

    DISALLOW_COPY_AND_MOVE(PermissionManager);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_MANAGER_H
