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

#ifndef ACCESSTOKEN_TOKEN_INFO_MANAGER_H
#define ACCESSTOKEN_TOKEN_INFO_MANAGER_H

#include <map>
#include <memory>
#include <vector>

#include "access_token.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "native_token_info.h"
#include "native_token_info_inner.h"
#include "nocopyable.h"
#include "rwlock.h"
#include "thread_pool.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static const int UDID_MAX_LENGTH = 128; // udid/uuid max length

class AccessTokenInfoManager final {
public:
    static AccessTokenInfoManager& GetInstance();
    ~AccessTokenInfoManager();
    void Init();
    std::shared_ptr<HapTokenInfoInner> GetHapTokenInfoInner(AccessTokenID id);
    int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& infoParcel);
    std::shared_ptr<NativeTokenInfoInner> GetNativeTokenInfoInner(AccessTokenID id);
    int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& infoParcel);
    std::shared_ptr<PermissionPolicySet> GetNativePermissionPolicySet(AccessTokenID id);
    std::shared_ptr<PermissionPolicySet> GetHapPermissionPolicySet(AccessTokenID id);
    int RemoveHapTokenInfo(AccessTokenID id);
    int RemoveNativeTokenInfo(AccessTokenID id);
    int CreateHapTokenInfo(const HapInfoParams& info, const HapPolicyParams& policy, AccessTokenIDEx& tokenIdEx);
    int CheckNativeDCap(AccessTokenID tokenID, const std::string& dcap);
    AccessTokenID GetHapTokenID(int userID, const std::string& bundleName, int instIndex);
    AccessTokenID AllocLocalTokenID(const std::string& remoteDeviceID, AccessTokenID remoteTokenID);
    void ProcessNativeTokenInfos(const std::vector<std::shared_ptr<NativeTokenInfoInner>>& tokenInfos);
    int UpdateHapToken(
        AccessTokenID tokenID, const std::string& appIDDesc, int32_t apiVersion, const HapPolicyParams& policy);
    void DumpTokenInfo(AccessTokenID tokenID, std::string& dumpInfo);
    void RefreshTokenInfoIfNeeded();
    bool IsTokenIdExist(AccessTokenID id);
    AccessTokenID GetNativeTokenId(const std::string& processName);

#ifdef TOKEN_SYNC_ENABLE
    /* tokensync needed */
    int GetHapTokenSync(AccessTokenID tokenID, HapTokenInfoForSync& hapSync);
    int GetHapTokenInfoFromRemote(AccessTokenID tokenID,
        HapTokenInfoForSync& hapSync);
    void GetAllNativeTokenInfo(std::vector<NativeTokenInfoForSync>& nativeTokenInfosRes);
    int SetRemoteHapTokenInfo(const std::string& deviceID, HapTokenInfoForSync& hapSync);
    int SetRemoteNativeTokenInfo(const std::string& deviceID,
        std::vector<NativeTokenInfoForSync>& nativeTokenInfoList);
    bool IsRemoteHapTokenValid(const std::string& deviceID, const HapTokenInfoForSync& hapSync);
    int DeleteRemoteToken(const std::string& deviceID, AccessTokenID tokenID);
    AccessTokenID GetRemoteNativeTokenID(const std::string& deviceID, AccessTokenID tokenID);
    int DeleteRemoteDeviceTokens(const std::string& deviceID);
    std::string GetUdidByNodeId(const std::string &nodeId);
#endif

private:
    AccessTokenInfoManager();
    DISALLOW_COPY_AND_MOVE(AccessTokenInfoManager);

    void InitHapTokenInfos();
    void InitNativeTokenInfos();
    int AddHapTokenInfo(const std::shared_ptr<HapTokenInfoInner>& info);
    int AddNativeTokenInfo(const std::shared_ptr<NativeTokenInfoInner>& info);
    std::string GetHapUniqueStr(const std::shared_ptr<HapTokenInfoInner>& info) const;
    std::string GetHapUniqueStr(const int& userID, const std::string& bundleName, const int& instIndex) const;
    bool TryUpdateExistNativeToken(const std::shared_ptr<NativeTokenInfoInner>& infoPtr);
    int AllocNativeToken(const std::shared_ptr<NativeTokenInfoInner>& infoPtr);
    void StoreAllTokenInfo();
    int CreateRemoteHapTokenInfo(AccessTokenID mapID, HapTokenInfoForSync& hapSync);
    int UpdateRemoteHapTokenInfo(AccessTokenID mapID, HapTokenInfoForSync& hapSync);

    OHOS::ThreadPool tokenDataWorker_;
    bool hasInited_;

    OHOS::Utils::RWLock hapTokenInfoLock_;
    OHOS::Utils::RWLock nativeTokenInfoLock_;
    OHOS::Utils::RWLock managerLock_;

    std::map<int, std::shared_ptr<HapTokenInfoInner>> hapTokenInfoMap_;
    std::map<std::string, AccessTokenID> hapTokenIdMap_;
    std::map<int, std::shared_ptr<NativeTokenInfoInner>> nativeTokenInfoMap_;
    std::map<std::string, AccessTokenID> nativeTokenIdMap_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_TOKEN_INFO_MANAGER_H
