/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef INSTALL_SESSION_MANAGER_H
#define INSTALL_SESSION_MANAGER_H

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "ability_manager_access_loader.h"
#include "access_token.h"
#include "add_spm_data_task.h"
#include "hap_sign_verify_manager.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "iremote_broker.h"
#include "libraryloader.h"
#include "nocopyable.h"
#include "permission_def.h"
#include "permission_grant_event.h"
#include "permission_kernel_utils.h"
#include "permission_list_state.h"
#include "permission_list_state_parcel.h"
#include "permission_map.h"
#include "permission_state_change_info.h"
#include "permission_status.h"
#include "proxy_death_handler.h"
#include "temp_permission_observer.h"
#include "update_spm_data_task.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

struct InstallCache {
    // Basic info:
    // Input hap list containing hap paths and user ID
    BundleHapList list;
    // Verified bundle info list; front elements from list signature verification,
    // back elements from database verification in MERGE scenario
    std::vector<TrustedBundleInfoInner> bundleInfos;
    // Additional hap paths stored in database for MERGE scenario
    std::vector<std::string> additionalPaths;
    // Hap policy containing permission state list
    HapPolicy policy;
    // Bundle parameters like bundleName, apl, etc.
    BundleParam bundleParam;
    // PID of the calling process for death monitoring
    int32_t callerPid = -1;

    // Install info:
    // Install type: TYPE_INSTALL, TYPE_REPLACE, or TYPE_MERGE
    InstallTypeEnum type;
    // Basic hap info for newly allocated tokenID: userID, bundleName, instIndex
    HapBaseInfo baseInfo;
    // Newly allocated tokenID and uid
    Identity identity;
    // Bundle policy for newly allocated tokenID including pre-authorization and debug grant
    BundlePolicy bundlePolicy;
    // Whether bundleId in uid is newly allocated
    bool isNewBundleId = true;
    // Reserved token flag: 0-normal, 1-reserved for update, 2-reserved token reused
    int32_t reserved = 0;
    // Old token ID for reserved != 0 scenario
    int32_t oldTokenId = 0;
    // Old tokenAttr for reserved is 2
    int32_t oldAttr = 0;

    // Update info:
    // Map of tokenId to bundlePolicy for multi-token scenarios
    std::unordered_map<int32_t, BundlePolicy> tokenIDToBundlePolicy;
};

struct FinishContext {
    BundleNoCachedInfo noCachedInfo;
    std::vector<HapTokenInfo> hapInfos;
    std::vector<std::vector<BriefPermData>> permBriefDataLists;
    std::vector<std::vector<PermissionWithValue>> extendPermLists;
    std::vector<std::shared_ptr<std::vector<BriefPermData>>> oldPermList;
};

struct SpmTaskContext {
    std::vector<SpmDataParam> addParams;
    std::vector<SpmDataParam> updateParams;
    std::shared_ptr<AddSpmDataTask> addTask;
    std::shared_ptr<UpdateSpmDataTask> updateTask;
};

class InstallSessionManager {
public:
    static InstallSessionManager& GetInstance();
    InstallSessionManager();
    virtual ~InstallSessionManager();

    int32_t CheckHapSignInfo(const BundleHapList& list, const sptr<IRemoteObject>& cb, int32_t& sessionId,
        std::vector<TrustedBundleInfo>& bundleInfo);
    int32_t CheckHapPermissionInfo(int32_t sessionId, InstallTypeEnum type, HapInfoCheckResult& result);
    int32_t PrepareHapIdentity(int32_t& sessionId, const HapBaseInfo& info, const BundlePolicy& policy,
        const sptr<IRemoteObject>& cb, Identity& identity);
    int32_t UpdateHapPolicy(int32_t sessionId, int32_t tokenId, const BundlePolicy& policy);
    int32_t FinishInstall(int32_t sessionId, bool isSuccess, const std::map<std::string, std::string>& modulePathMap);
    int32_t GetCacheSignInfoBySessionId(int32_t sessionId, std::vector<TrustedBundleInfo>& bundleInfo);
    int32_t GetHapSignInfo(const std::string& bundleName, std::vector<TrustedBundleInfo>& bundleInfo);
    void ClearSessionByPid(int32_t pid);
    int32_t GetCachePolicyBySessionId(int32_t sessionId, const std::string& bundleName,
        BundlePolicyInfo& bundlePolicyInfo);

    void SetMigrationDone();

private:
    int32_t CheckPermissionList(InstallCache& cache, HapInfoCheckResult& result);
    int32_t GetHapPathFromDb(std::string bundleName, std::vector<std::string>& paths,
        std::vector<std::vector<uint8_t>>& persistDatas);
    int32_t RebuildHapPolicy(InstallCache& cache, const std::vector<std::string>& paths,
        std::vector<std::vector<uint8_t>>& persistDatas);
    void ClearTimeoutData();
    int32_t CreateInstallSession(const HapBaseInfo& info, const BundlePolicy& policy,
        const sptr<IRemoteObject>& cb, int32_t& sessionId);
    int32_t PrepareSessionIdentity(int32_t sessionId, const HapBaseInfo& info,
        const BundlePolicy& policy, Identity& identity);
    int32_t GetAppIdFromDb(const std::string& bundleName, std::string& appId);
    int32_t CheckType(std::vector<std::string>& additionalPaths, InstallTypeEnum type);
    int32_t DeleteFromDbByTokenId(AccessTokenID tokenID);
    int32_t GetTokenIdAndUid(InstallCache& cache, const BundlePolicy& bundlePolicy);
    int32_t MatchBaseInfo(InstallCache& cache, int32_t reserved, AccessTokenID tokenId, int32_t uid, int32_t oldAttr);
    int32_t CreateTokenIdAndUid(InstallCache& cache, const BundlePolicy& bundlePolicy, int32_t bundleId);
    int32_t HandleReservedToken(InstallCache& cache, AccessTokenID tokenId, int32_t uid, int32_t oldAttr);
    int32_t FastVerify(const std::vector<std::string>& paths, std::vector<std::vector<uint8_t>>& persistDatas,
        std::vector<TrustedBundleInfoInner>& bundleInfos, int32_t userId = -1);

    void InitPermissionList(const BundleParam& bundleParam, HapPolicy& policy);
    bool NoNeedPermissionInheritance(const BundleParam& bundleParam, const HapPolicy& policy, AccessTokenAttr oldAttr);
    void MergePermission(std::vector<BriefPermData>& permBriefDataList,
        const std::vector<BriefPermData>& oldPermBriefDataList, bool noNeedPermissionInheritance);

    void SupplementUpdateInfo(InstallCache& cache);
    void FilterPermissionByFeatures(InstallCache& cache);
    int32_t AllocHapInfo(const InstallCache& cache, FinishContext& context);
    int32_t FillPermStateFromDb(AccessTokenID tokenId, std::vector<BriefPermData>& permBriefDataList,
        bool noNeedPermissionInheritance);
    bool GetPermissionBriefData(const PermissionStatus &permState, BriefPermData& briefPermData);
    void FillPermBriefDataList(
        const std::vector<PermissionStatus>& permStateList, std::vector<BriefPermData>& permBriefDataList);
    void CreateUpdateHapInfo(const InstallCache& cache, FinishContext& context);
    int32_t InitDlpPermission(const HapBaseInfo& baseInfo, HapPolicy& policy);
    int32_t DeleteAndInsertValueToDb(const InstallCache& cache,
        const FinishContext& context, const std::map<std::string, std::string>& modulePathMap);
    void RefreshCache(const InstallCache& cache, const FinishContext& context,
        std::shared_ptr<BundleInfoInner>& innerInfo);
    void RefreshExtendedPerm(const InstallCache& cache, const FinishContext& context);
    void RollbackAll(int32_t sessionId, bool eraseCache = true);
    int32_t FillFinishContext(int32_t sessionId, const InstallCache& cache, FinishContext& context);
    int32_t ExecuteSpmKernelTasks(int32_t sessionId, const InstallCache& cache,
        const FinishContext& context, SpmTaskContext& spmContext);
    int32_t FinishInstallInner(int32_t sessionId, InstallCache& cache,
        const std::map<std::string, std::string>& modulePathMap);

    void GenerateHapTokenInfoItem(const InstallCache& cache, const HapTokenInfo& hapInfo,
        std::vector<GenericValues>& genericValues);
    void ConvertBriefPermDataToGenericValues(AccessTokenID tokenId,
        const std::vector<BriefPermData>& briefPermDataList, std::vector<GenericValues>& genericValuesList);
    void GeneratePermDefFromHapPolicy(AccessTokenID tokenId, const HapPolicy& hapPolicy,
        const std::string& bundleName, std::vector<GenericValues>& genericValuesList);
    int32_t ConvertInstallCacheToBundleInfoItems(const InstallCache& cache,
        const std::map<std::string, std::string>& modulePathMap, std::vector<GenericValues>& genericValuesList,
        GenericValues& delCondition);
    void GenerateOneDbInfo(const InstallCache& cache, const HapTokenInfo& hapInfo,
        const std::vector<BriefPermData>& permBriefDataList, std::vector<AddInfo>& addInfoVec,
        std::vector<DelInfo>& delInfoVec);
    int32_t GetHapPathsFromDbAndVerify(const std::string& bundleName,
        std::vector<TrustedBundleInfoInner>& bundleInfos);
    int32_t FillInstallPolicy(const std::string& bundleName,
        const BundlePolicy& bundlePolicy, InstallCache& cache);
    
    std::shared_ptr<ProxyDeathHandler> GetProxyDeathHandler();
    void ProcessProxyDeathStub(const sptr<IRemoteObject>& anonyStub);
    bool HasCallerInSessionCache(int32_t callerPid);
    void ReleaseDeathStub(int32_t callerPid);

    static std::mutex mutex_;
    static InstallSessionManager* implInstance_;

    std::mutex cacheMutex_;
    int32_t sessionCnt = 0;
    std::unordered_map<int32_t, InstallCache> sessionToInstallCache;
    std::unordered_map<int32_t, uint64_t> sessionToTimestamp;

    std::atomic<bool> migrationDone_{false};
    
    std::shared_ptr<ProxyDeathHandler> proxyDeathHandler_;
    std::mutex deathHandlerMutex_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // INSTALL_SESSION_MANAGER_H
