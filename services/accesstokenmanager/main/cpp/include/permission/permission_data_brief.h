/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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


#ifndef PERMISSION_DATA_BRIEF_H
#define PERMISSION_DATA_BRIEF_H

#include <list>
#include <memory>
#include <mutex>
#include <map>
#include <string>
#include <vector>

#include "access_token.h"

#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

typedef struct {
    uint8_t status;
    uint8_t reserved;
    uint16_t permCode;
    uint32_t flag;
} BriefPermData;

typedef struct {
    uint16_t permCode;
    uint16_t reserved;
    uint32_t tokenId;
} BriefSecCompData;

class PermissionDataBrief final {
public:
    static PermissionDataBrief& GetInstance();
    virtual ~PermissionDataBrief() = default;

    int32_t AddBriefPermDataByTokenId(AccessTokenID tokenID, const std::vector<BriefPermData>& listInput);
    int32_t DeleteBriefPermDataByTokenId(AccessTokenID tokenID);
    int32_t SetBriefPermData(AccessTokenID tokenID, int32_t opCode, bool status, uint32_t flag);
    int32_t GetBriefPermDataByTokenId(AccessTokenID tokenID, std::vector<BriefPermData>& data);
    void ToString(std::string& info);
    PermUsedTypeEnum GetPermissionUsedType(AccessTokenID tokenID, int32_t opCode);
    bool IsPermissionGrantedWithSecComp(AccessTokenID tokenID, const std::string& permissionName);
    int32_t VerifyPermissionStatus(AccessTokenID tokenID, const std::string& permission);
    int32_t QueryPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag);
    void SecCompGrantedPermListUpdated(AccessTokenID tokenID,
        const std::string& permissionName, bool isAdded);
    void ClearAllSecCompGrantedPerm();
    void ClearAllSecCompGrantedPermById(AccessTokenID tokenID);
    void GetGrantedPermByTokenId(AccessTokenID tokenID,
        const std::vector<std::string>& constrainedList, std::vector<std::string>& permissionList);
    void GetPermStatusListByTokenId(AccessTokenID tokenID,
        const std::vector<uint32_t> constrainedList, std::vector<uint32_t>& opCodeList, std::vector<bool>& statusList);
    int32_t RefreshPermStateToKernel(const std::vector<std::string>& constrainedList,
        bool hapUserIsActive, AccessTokenID tokenId, std::map<std::string, bool>& refreshedPermList);
private:
    PermissionDataBrief() = default;
    DISALLOW_COPY_AND_MOVE(PermissionDataBrief);
    OHOS::Utils::RWLock permissionStateDataLock_;
    std::map<uint32_t, std::vector<BriefPermData>> requestedPermData_;
    std::list<BriefSecCompData> secCompList_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_DATA_BRIEF_H
