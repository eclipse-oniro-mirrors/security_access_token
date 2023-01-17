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

#include "rwlock.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
constexpr const char* VAGUE_LOCATION_PERMISSION_NAME = "ohos.permission.APPROXIMATELY_LOCATION";
constexpr const char* ACCURATE_LOCATION_PERMISSION_NAME = "ohos.permission.LOCATION";
const uint32_t ELEMENT_NOT_FOUND = -1;
const int32_t ACCURATE_LOCATION_API_VERSION = 9;

class PermissionManager {
public:
    static PermissionManager& GetInstance();
    virtual ~PermissionManager();

    void AddDefPermissions(const std::vector<PermissionDef>& permList, AccessTokenID tokenId,
        bool updateFlag);
    void RemoveDefPermissions(AccessTokenID tokenID);
    int VerifyNativeAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    int VerifyHapAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    virtual int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    int GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult);
    int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList);
    int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant);
    int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, int& flag);
    int32_t GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag);
    int32_t RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag);
    void ClearUserGrantedPermissionState(AccessTokenID tokenID);
    void GetSelfPermissionState(
        std::vector<PermissionStateFull> permsList, PermissionListState &permState, int32_t apiVersion);
    int32_t AddPermStateChangeCallback(
        const PermStateChangeScope& scope, const sptr<IRemoteObject>& callback);
    int32_t RemovePermStateChangeCallback(const sptr<IRemoteObject>& callback);
    bool GetApiVersionByTokenId(AccessTokenID tokenID, int32_t& apiVersion);
    bool GetLocationPermissionIndex(std::vector<PermissionListStateParcel>& reqPermList, uint32_t& vagueIndex,
        uint32_t& accurateIndex);
    bool LocationPermissionSpecialHandle(std::vector<PermissionListStateParcel>& reqPermList, int32_t apiVersion,
        std::vector<PermissionStateFull> permsList, uint32_t vagueIndex, uint32_t accurateIndex);
    void NotifyPermGrantStoreResult(bool result, uint64_t timestamp);
    PermissionManager();
protected:
    static void RegisterImpl(PermissionManager* implInstance);
private:
    void ScopeToString(
        const std::vector<AccessTokenID>& tokenIDs, const std::vector<std::string>& permList);
    int32_t ScopeFilter(const PermStateChangeScope& scopeSrc, PermStateChangeScope& scopeRes);
    int32_t UpdateTokenPermissionState(
        AccessTokenID tokenID, const std::string& permissionName, bool isGranted, int flag);
    std::string TransferPermissionDefToString(const PermissionDef& inPermissionDef);
    bool IsPermissionVaild(const std::string& permissionName);
    bool GetPermissionStatusAndFlag(const std::string& permissionName,
        const std::vector<PermissionStateFull>& permsList, int32_t& status, uint32_t& flag);
    void AllLocationPermissionHandle(std::vector<PermissionListStateParcel>& reqPermList,
        std::vector<PermissionStateFull> permsList, uint32_t vagueIndex, uint32_t accurateIndex);
    void ParamUpdate(const std::string& permissionName, uint32_t flag);

    PermissionGrantEvent grantEvent_;
    static PermissionManager* implInstance_;
    static std::recursive_mutex mutex_;

    OHOS::Utils::RWLock permParamSetLock_;
    uint64_t paramValue_ = 0;

    DISALLOW_COPY_AND_MOVE(PermissionManager);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_MANAGER_H
