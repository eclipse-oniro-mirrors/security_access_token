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
#include "hisysevent_adapter.h"
#include "install_session_cache.h"
#include "iremote_broker.h"
#include "kernel_and_db_transaction.h"
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

class InstallSessionManager {
public:
    static InstallSessionManager& GetInstance();
    InstallSessionManager();
    virtual ~InstallSessionManager();

    int32_t CheckHapSignInfo(const BundleHapList& list, const sptr<IRemoteObject>& cb, int32_t& sessionId,
        std::vector<TrustedBundleInfo>& bundleInfo, HapVerifyResultInfo& resultInfo, uint32_t flag);
    int32_t CheckHapPermissionInfo(int32_t sessionId, InstallTypeEnum type, HapInfoCheckResult& result);
    int32_t PrepareHapIdentity(int32_t& sessionId, const HapBaseInfo& info, const BundlePolicy& policy,
        const sptr<IRemoteObject>& cb, Identity& identity);
    int32_t UpdateHapPolicy(int32_t sessionId, AccessTokenID tokenId, const BundlePolicy& policy, int32_t& uid);
    int32_t FinishInstall(
        int32_t sessionId, bool isPersistent, const std::map<std::string, std::string>& modulePathMap);
    int32_t GetCacheSignInfoBySessionId(int32_t sessionId, std::vector<TrustedBundleInfo>& bundleInfo,
        uint32_t flag);
    void ClearSessionByPid(int32_t pid);
    int32_t GetCachePolicyBySessionId(int32_t sessionId, const std::string& bundleName,
        BundlePolicyInfo& bundlePolicyInfo);

    void SetMigrationDone();

private:
    int32_t MergeBundleInfos(InstallCache& cache, std::vector<std::string>& paths,
        std::vector<std::vector<uint8_t>>& persistDatas);
    void ClearTimeoutSession();
    int32_t CreateInstallSession(const HapBaseInfo& info, const BundlePolicy& policy,
        const sptr<IRemoteObject>& cb, int32_t& sessionId, const Identity& desired);
    void CreateSessionEntry(InstallCache& cache, const sptr<IRemoteObject>& cb,
        const std::string& bundleName, int32_t& sessionId);
    int32_t PrepareSessionIdentity(int32_t sessionId, const HapBaseInfo& info,
        const BundlePolicy& policy, Identity& identity);
    int32_t CheckInstallType(std::vector<std::string>& installedPaths, InstallTypeEnum type);

    void InitPermissionList(const BundleParam& bundleParam, HapPolicy& policy);
    std::vector<BriefPermData> BuildUpdatedPermList(const BundleParam& bundleParam,
        const BundlePolicy& bundlePolicy, AccessTokenAttr oldAttr, HapPolicy& newPolicy,
        const std::vector<BriefPermData>& oldPermList);
    bool ShouldSkipPermInheritance(const BundleParam& bundleParam, const HapPolicy& policy, AccessTokenAttr oldAttr);
    void MergePermission(std::vector<BriefPermData>& newPerms,
        const std::vector<BriefPermData>& oldPerms, bool skipPermInheritance);

    bool EnsureBundleTokenIdsLoaded(InstallCache& cache);
    void SupplementUpdateInfo(InstallCache& cache);
    int32_t AllocHapInfo(const InstallCache& cache, FinishContext& context);
    std::shared_ptr<HapTokenInfoInner> GetHapTokenInfoForInstall(InstallCache& cache, AccessTokenID tokenId);
    int32_t MergeReservedPermState(const InstallCache& cache, const HapPolicy& policy,
        std::vector<BriefPermData>& newPerms);
    void CreateUpdateHapInfo(InstallCache& cache, FinishContext& context);
    int32_t InitDlpPermission(const HapBaseInfo& baseInfo, HapPolicy& policy);
    void RefreshCache(const InstallCache& cache, const FinishContext& context);
    void RollbackAll(int32_t sessionId, int32_t sceneCode, int32_t errorCode, AccessTokenID tokenId,
        bool eraseCache = true);
    // Local-session counterpart of RollbackAll for a session already taken over
    // by FinishInstall: report, release ids, release the death stub.
    void RollbackFinishedSession(InstallCache& cache, int32_t sceneCode, int32_t errorCode, AccessTokenID tokenId);
    int32_t FillFinishContext(InstallCache& cache, FinishContext& context);
    // Classify each token of the finish context into kernel add/update params (pure builder).
    void BuildSpmKernelParams(const InstallCache& cache, const FinishContext& ctx,
        std::vector<SpmDataParam>& addParams, std::vector<SpmDataParam>& updateParams);
    // Stage the kernel add/update on the transaction (executes immediately,
    // destructor compensation on any early return).
    int32_t StageSpmKernelTasks(const InstallCache& cache, const FinishContext& ctx,
        KernelAndDBWriteTransaction& txn);
    int32_t FinishInstallInner(InstallCache& cache, const std::map<std::string, std::string>& modulePathMap);

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

    std::atomic<bool> migrationDone_{false};
    
    std::shared_ptr<ProxyDeathHandler> proxyDeathHandler_;
    std::mutex deathHandlerMutex_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // INSTALL_SESSION_MANAGER_H
