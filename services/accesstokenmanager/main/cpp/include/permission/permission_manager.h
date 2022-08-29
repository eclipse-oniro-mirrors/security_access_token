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
const int32_t ELEMENT_NOT_FOUND = -1;
const int32_t ACCURATE_LOCATION_API_VERSION = 9;

class PermissionManager final {
public:
    static PermissionManager& GetInstance();
    virtual ~PermissionManager();

    void AddDefPermissions(const std::vector<PermissionDef>& permList, AccessTokenID tokenId,
        bool updateFlag);
    void RemoveDefPermissions(AccessTokenID tokenID);
    int VerifyNativeAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    int VerifyHapAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    int GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult);
    int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList);
    int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant);
    int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName);
    void GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag);
    void RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag);
    void ClearUserGrantedPermissionState(AccessTokenID tokenID);
    void GetSelfPermissionState(
        std::vector<PermissionStateFull> permsList, PermissionListState &permState, int32_t apiVersion);
    int32_t AddPermStateChangeCallback(
        const PermStateChangeScope& scope, const sptr<IRemoteObject>& callback);
    int32_t RemovePermStateChangeCallback(const sptr<IRemoteObject>& callback);
    bool GetApiVersionByTokenId(AccessTokenID tokenID, int32_t& apiVersion);
    bool GetLocationPermissionIndex(std::vector<PermissionListStateParcel>& reqPermList, int& vagueIndex,
        int& accurateIndex);
    bool LocationPermissionSpecialHandle(std::vector<PermissionListStateParcel>& reqPermList, int32_t apiVersion,
        std::vector<PermissionStateFull> permsList, int vagueIndex, int accurateIndex);
    void NotifyPermGrantStoreResult(bool result, uint64_t timestamp);

private:
    PermissionManager();
    void UpdateTokenPermissionState(
        AccessTokenID tokenID, const std::string& permissionName, bool isGranted, int flag);
    std::string TransferPermissionDefToString(const PermissionDef& inPermissionDef);
    bool IsPermissionVaild(const std::string& permissionName);
    bool GetPermissionStatusAndFlag(const std::string& permissionName,
        const std::vector<PermissionStateFull>& permsList, int32_t& status, uint32_t& flag);
    void AllLocationPermissionHandle(std::vector<PermissionListStateParcel>& reqPermList,
        std::vector<PermissionStateFull> permsList, int vagueIndex, int accurateIndex);

    PermissionGrantEvent grantEvent_;

    DISALLOW_COPY_AND_MOVE(PermissionManager);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_MANAGER_H
