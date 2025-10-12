/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_TOKEN_INFO_MANAGER_H
#define ACCESSTOKEN_TOKEN_INFO_MANAGER_H

#include <algorithm>
#include <atomic>
#include <map>
#include <memory>
#include <shared_mutex>
#include <unordered_set>
#include <vector>

#include "access_token_db.h"
#include "access_token.h"
#include "atm_tools_param_info.h"
#ifdef TOKEN_SYNC_ENABLE
#include "device_manager.h"
#endif
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "native_token_info_base.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
#ifdef TOKEN_SYNC_ENABLE
class AccessTokenDmInitCallback final : public DistributedHardware::DmInitCallback {
    void OnRemoteDied() override
    {}
};
#endif

class AccessTokenInfoManager final {
public:
    static AccessTokenInfoManager& GetInstance();
    ~AccessTokenInfoManager();
    void Init(uint32_t& hapSize, uint32_t& nativeSize, uint32_t& pefDefSize, uint32_t& dlpSize,
        std::map<int32_t, TokenIdInfo>& tokenIdAplMap);
    void InitNativeTokenInfos(const std::vector<NativeTokenInfoBase>& tokenInfos);
    int32_t GetTokenIDByUserID(int32_t userID, std::unordered_set<AccessTokenID>& tokenIdList);
    std::shared_ptr<HapTokenInfoInner> GetHapTokenInfoInner(AccessTokenID id);
    int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& infoParcel);
    int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfoBase& info);
    int AllocAccessTokenIDEx(const HapInfoParams& info, AccessTokenID tokenId, AccessTokenIDEx& tokenIdEx);
    int RemoveHapTokenInfo(AccessTokenID id);
    int RemoveNativeTokenInfo(AccessTokenID id);
    int32_t GetHapAppIdByTokenId(AccessTokenID tokenID, std::string& appId);
    int CreateHapTokenInfo(const HapInfoParams& info, const HapPolicy& policy, AccessTokenIDEx& tokenIdEx,
        std::vector<GenericValues>& undefValues);
    AccessTokenIDEx GetHapTokenID(int32_t userID, const std::string& bundleName, int32_t instIndex);
    AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID);
    int32_t UpdateHapToken(AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info,
        const std::vector<PermissionStatus>& permStateList, const HapPolicy& hapPolicy,
        std::vector<GenericValues>& undefValues);
    void DumpTokenInfo(const AtmToolsParamInfo& info, std::string& dumpInfo);
    bool IsTokenIdExist(AccessTokenID id);
    AccessTokenID GetNativeTokenId(const std::string& processName);
    void GetRelatedSandBoxHapList(AccessTokenID tokenId, std::vector<AccessTokenID>& tokenIdList);
    int32_t GetHapTokenDlpType(AccessTokenID id);
    int32_t SetPermDialogCap(AccessTokenID tokenID, bool enable);
    int32_t SetUserPolicy(
        const std::vector<int32_t>& userList, const std::vector<PermissionPolicy>& permPolicyList);
    int32_t ClearUserPolicy(const std::vector<int32_t>& userList);
    bool GetPermDialogCap(AccessTokenID tokenID);
    void ClearUserGrantedPermissionState(AccessTokenID tokenID);
    int32_t ClearUserGrantedPermission(AccessTokenID tokenID);
    bool IsPermissionRestrictedByUserPolicy(AccessTokenID id, const std::string& permissionName);
    int32_t VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    int32_t VerifyNativeAccessToken(AccessTokenID tokenID, const std::string& permissionName);

#ifdef TOKEN_SYNC_ENABLE
    /* tokensync needed */
    void InitDmCallback(void);
    int GetHapTokenSync(AccessTokenID tokenID, HapTokenInfoForSync& hapSync);
    int GetHapTokenInfoFromRemote(AccessTokenID tokenID,
        HapTokenInfoForSync& hapSync);
    int SetRemoteHapTokenInfo(const std::string& deviceID, HapTokenInfoForSync& hapSync);
    bool IsRemoteHapTokenValid(const std::string& deviceID, const HapTokenInfoForSync& hapSync);
    int DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID);
    AccessTokenID GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID);
    int DeleteRemoteDeviceTokens(const std::string& deviceID);
#endif

    bool UpdateCapStateToDatabase(AccessTokenID tokenID, bool enable);
    int32_t SetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t status, int32_t userID);
    int32_t GetPermissionRequestToggleStatus(const std::string& permissionName, uint32_t& status, int32_t userID);
    int32_t GetKernelPermissions(AccessTokenID tokenId, std::vector<PermissionWithValue>& kernelPermList);
    int32_t GetReqPermissionByName(AccessTokenID tokenId, const std::string& permissionName, std::string& value);

private:
    AccessTokenInfoManager();
    DISALLOW_COPY_AND_MOVE(AccessTokenInfoManager);

    int32_t AddHapInfoToCache(const GenericValues& tokenValue, const std::vector<GenericValues>& permStateRes,
        const std::vector<GenericValues>& extendedPermRes);
    void InitHapTokenInfos(uint32_t& hapSize, std::map<int32_t, TokenIdInfo>& tokenIdAplMap);
    void ReportAddHapIdChange(const std::shared_ptr<HapTokenInfoInner>& hapInfo, AccessTokenID oriTokenId);
    int AddHapTokenInfo(const std::shared_ptr<HapTokenInfoInner>& info, AccessTokenID& oriTokenId);
    std::string GetHapUniqueStr(const std::shared_ptr<HapTokenInfoInner>& info) const;
    std::string GetHapUniqueStr(const int& userID, const std::string& bundleName, const int& instIndex) const;
    int32_t RegisterTokenId(const HapInfoParams& info, AccessTokenID& tokenId);
    void GenerateAddInfoToVec(AtmDataType type, const std::vector<GenericValues>& addValues,
        std::vector<AddInfo>& addInfoVec);
    void GenerateDelInfoToVec(AtmDataType type, const GenericValues& delValue,
        std::vector<DelInfo>& delInfoVec);
    void AddTokenIdToUndefValues(AccessTokenID tokenId, std::vector<GenericValues>& undefValues);
    int AddHapTokenInfoToDb(const std::shared_ptr<HapTokenInfoInner>& hapInfo, const std::string& appId,
        const HapPolicy& policy, bool isUpdate, const std::vector<GenericValues>& undefValues);
    int RemoveHapTokenInfoFromDb(const std::shared_ptr<HapTokenInfoInner>& info);
    int CreateRemoteHapTokenInfo(AccessTokenID mapID, HapTokenInfoForSync& hapSync);
    int UpdateRemoteHapTokenInfo(AccessTokenID mapID, HapTokenInfoForSync& hapSync);
    void DumpHapTokenInfoByTokenId(const AccessTokenID tokenId, std::string& dumpInfo);
    void DumpHapTokenInfoByBundleName(const std::string& bundleName, std::string& dumpInfo);
    void DumpAllHapTokenname(std::string& dumpInfo);
    void DumpNativeTokenInfoByProcessName(const std::string& processName, std::string& dumpInfo);
    void DumpAllNativeTokenName(std::string& dumpInfo);
    void UpdatePermissionStateToKernel(int32_t userId, const std::map<uint32_t, bool>& changedPermList);
    int32_t AddPermRequestToggleStatusToDb(int32_t userID, const std::string& permissionName, int32_t status);
    int32_t FindPermRequestToggleStatusFromDb(int32_t userID, const std::string& permissionName);
    void GetNativePermissionList(const NativeTokenInfoBase& native,
        std::vector<uint32_t>& opCodeList, std::vector<bool>& statusList);
    std::string NativeTokenToString(AccessTokenID tokenID);
    int32_t CheckHapInfoParam(const HapInfoParams& info, const HapPolicy& policy);
    std::shared_ptr<HapTokenInfoInner> GetHapTokenInfoInnerFromDb(AccessTokenID id);
    std::vector<uint32_t> GetConstraintPermList(int32_t userId);
    bool AddPermPolicyToCache(
        int32_t userId, const PermissionPolicy& policy, std::map<uint32_t, bool>& changedPermList);

    bool hasInited_;

    std::shared_mutex hapTokenInfoLock_;
    std::shared_mutex nativeTokenInfoLock_;
    std::shared_mutex managerLock_;
    std::shared_mutex modifyLock_;

    std::map<int, std::shared_ptr<HapTokenInfoInner>> hapTokenInfoMap_;
    std::map<std::string, AccessTokenID> hapTokenIdMap_;
    std::map<uint32_t, NativeTokenInfoCache> nativeTokenInfoMap_;

    std::shared_mutex userPolicyLock_;
    std::map<int32_t, std::vector<uint32_t>> userPolicyList_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_TOKEN_INFO_MANAGER_H
