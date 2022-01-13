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

#ifndef PERMISSION_MANAGER_H
#define PERMISSION_MANAGER_H

#include <vector>
#include <string>

#include "access_token.h"
#include "hap_token_info_inner.h"
#include "permission_def.h"
#include "permission_state_full.h"

#include "rwlock.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionManager final {
public:
    static PermissionManager& GetInstance();
    virtual ~PermissionManager();

    void AddDefPermissions(std::shared_ptr<HapTokenInfoInner> tokenInfo, bool updateFlag);
    void RemoveDefPermissions(AccessTokenID tokenID);
    int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    int GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult);
    int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList);
    int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant);
    int GetPermissionFlag(AccessTokenID tokenID, const std::string& permissionName);
    void GrantPermission(AccessTokenID tokenID, const std::string& permissionName, int flag);
    void RevokePermission(AccessTokenID tokenID, const std::string& permissionName, int flag);
    void ClearUserGrantedPermissionState(AccessTokenID tokenID);
private:
    PermissionManager();
    void UpdateTokenPermissionState(
        AccessTokenID tokenID, const std::string& permissionName, bool isGranted, int flag);
    std::string TransferPermissionDefToString(const PermissionDef& inPermissionDef);

    DISALLOW_COPY_AND_MOVE(PermissionManager);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_MANAGER_H
