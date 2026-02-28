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
#include <shared_mutex>
#include <string>
#include <vector>

#include "access_token.h"
#include "permission_status.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

typedef struct {
    int8_t status;
    uint8_t type; // KERNEL_EFFECT_FLAG = 0x1 << 0 HAS_VALUE_FLAG = 0x1 << 1
    uint16_t permCode;
    uint32_t flag;
} BriefPermData;

typedef struct {
    uint16_t permCode;
    uint16_t reserved;
    uint32_t tokenId;
} BriefSecCompData;

typedef enum AppProvisionType {
    DEBUG = 0,
    RELEASE = 1,
} AppProvisionType;

class PermissionDataBrief final {
public:
    static PermissionDataBrief& GetInstance();
    virtual ~PermissionDataBrief() = default;

    int32_t DeleteBriefPermDataByTokenId(AccessTokenID tokenID);
    int32_t AddBriefPermData(AccessTokenID tokenID, const std::string& permissionName, PermissionState grantStatus,
        PermissionFlag grantFlag, const std::string& value);
    int32_t GetBriefPermDataByTokenId(AccessTokenID tokenID, std::vector<BriefPermData>& data);
    void ToString(std::string& info);
    PermUsedTypeEnum GetPermissionUsedType(AccessTokenID tokenID, int32_t opCode);
    bool IsPermissionGrantedWithSecComp(AccessTokenID tokenID, const std::string& permissionName);
    int32_t VerifyPermissionStatus(AccessTokenID tokenID, const std::string& permission);
    int32_t QueryPermissionFlag(AccessTokenID tokenID, const std::string& permissionName, uint32_t& flag);
    void ClearAllSecCompGrantedPerm();
    void GetGrantedPermByTokenId(AccessTokenID tokenID,
        const std::vector<uint32_t>& constrainedList, std::vector<std::string>& permissionList);
    void GetPermStatusListByTokenId(AccessTokenID tokenID,
        const std::vector<uint32_t> constrainedList, std::vector<uint32_t>& opCodeList, std::vector<bool>& statusList);
    int32_t RefreshPermStateToKernel(AccessTokenID tokenId, uint32_t permCode, bool hapUserIsActive,
        std::map<std::string, bool>& refreshedPermList);
    void AddPermToBriefPermission(
            AccessTokenID tokenId, const std::vector<PermissionStatus>& permStateList, bool defCheck);
    void AddPermToBriefPermission(
            AccessTokenID tokenId, const std::vector<PermissionStatus>& permStateList,
            const std::map<std::string, std::string>& aclExtendedMap, bool defCheck);
    void Update(
        AccessTokenID tokenId, const std::vector<PermissionStatus>& permStateList,	 
        const std::map<std::string, std::string>& aclExtendedMap, bool needUpdatePermByProvision);
    void RestorePermissionBriefData(AccessTokenID tokenId,
        const std::vector<GenericValues>& permStateRes, const std::vector<GenericValues> extendedPermRes);
    int32_t StorePermissionBriefData(AccessTokenID tokenId, std::vector<GenericValues>& permStateValueList);
    int32_t UpdatePermissionStatus(AccessTokenID tokenId,
        const std::string& permissionName, bool isGranted, uint32_t flag, bool& statusChanged);
    int32_t ResetUserGrantPermissionStatus(AccessTokenID tokenID);
    int32_t GetKernelPermissions(AccessTokenID tokenId, std::vector<PermissionWithValue>& kernelPermList);
    int32_t GetReqPermissionByName(
        AccessTokenID tokenId, const std::string& permissionName, std::string& value, bool tokenIdCheck);
    void GetExtendedValueList(AccessTokenID tokenId, std::vector<PermissionWithValue>& extendedPermList);
private:
    bool GetPermissionBriefData(AccessTokenID tokenID, const PermissionStatus &permState,
        const std::map<std::string, std::string>& aclExtendedMap, BriefPermData& briefPermData);
    void GetPermissionStatus(const BriefPermData& briefPermData, PermissionStatus &permState);
    void GetPermissionBriefDataList(AccessTokenID tokenID,
        const std::vector<PermissionStatus>& permStateList,
        const std::map<std::string, std::string>& aclExtendedMap,
        std::vector<BriefPermData>& list);
    void AddBriefPermDataByTokenId(AccessTokenID tokenID, const std::vector<BriefPermData>& listInput);
    void UpdatePermStatus(const BriefPermData& permOld, BriefPermData& permNew);
    uint32_t GetFlagWroteToDb(uint32_t grantFlag);
    void MergePermBriefData(std::vector<BriefPermData>& permBriefDataList, BriefPermData& data);
    bool isRestrictedPermission(uint32_t oldFlag, uint32_t newFlag);
    int32_t UpdatePermStateList(AccessTokenID tokenId, uint32_t opCode, bool isGranted, uint32_t flag);
    int32_t UpdateSecCompGrantedPermList(AccessTokenID tokenId, const std::string& permissionName, bool isToGrant);
    int32_t VerifyPermissionStatus(AccessTokenID tokenID, uint32_t permCode);
    void ClearAllSecCompGrantedPermById(AccessTokenID tokenID);
    void SecCompGrantedPermListUpdated(AccessTokenID tokenID, const std::string& permissionName, bool isAdded);
    int32_t GetBriefPermDataByTokenIdInner(AccessTokenID tokenID, std::vector<BriefPermData>& list);
    int32_t TranslationIntoAclExtendedMap(AccessTokenID tokenId, const std::vector<GenericValues>& extendedPermRes,
        std::map<std::string, std::string>& aclExtendedMap);
    void GetExtendedValueListInner(AccessTokenID tokenId, std::vector<PermissionWithValue>& extendedPermList);
    void DeleteExtendedValue(AccessTokenID tokenID);
    PermissionDataBrief() = default;
    DISALLOW_COPY_AND_MOVE(PermissionDataBrief);
    std::shared_mutex permissionStateDataLock_;
    std::map<uint32_t, std::vector<BriefPermData>> requestedPermData_;
    std::map<uint64_t, std::string> extendedValue_;
    std::list<BriefSecCompData> secCompList_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_DATA_BRIEF_H
