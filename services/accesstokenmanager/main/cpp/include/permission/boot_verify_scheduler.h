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

#ifndef ACCESS_TOKEN_BOOT_VERIFY_SCHEDULER_H
#define ACCESS_TOKEN_BOOT_VERIFY_SCHEDULER_H

#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "access_token.h"
#include "access_token_db_operator.h"
#include "accesstoken_id_manager.h"

#ifdef IS_SUPPORT_HAP_RUNNING
#include "app_verify_adapter.h"
#include "bundle_sign_info.h"
#include "generic_values.h"
#include "hap_sign_verify_manager.h"
#include "hap_token_info_inner.h"
#include "permission_kernel_utils.h"
#include "permission_map.h"
#include "table_item.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {

#ifdef IS_SUPPORT_HAP_RUNNING
struct VerifiedBundleState final {
    std::string bundleName;
    bool needUpdateSignInfo = false;
    bool needPersistHapInfo = false;
    bool needPersistPermState = false;
};

class AddSpmDataTask;
#endif

struct BootTokenIdInfo final {
    int32_t apl = 0;
    bool isSystemApp = false;
};

class BootVerifyScheduler final {
public:
    static BootVerifyScheduler& GetInstance();

    int32_t VerifyBundleSignInfoWhenStart(uint32_t& hapSize);
    void StartVerifyNormalBundleListAsync();
    int32_t PreVerifyBundle(const std::string& bundleName);
    int32_t PreVerifyBundle(uint32_t tokenID);

#ifdef IS_SUPPORT_HAP_RUNNING
private:
    static std::vector<DelInfo> BuildDeleteInfos(const std::vector<BundleSignInfo>& infos);
    int32_t LoadVerifyDataFromDb();
    void InitBundleVerifyContext(const std::vector<GenericValues>& hapTokenRes,
        const std::vector<GenericValues>& permStateRes, const std::vector<GenericValues>& extendedPermRes);
    void ClearBundleVerifyContext();
    void InitPermStateContext(const std::vector<GenericValues>& permStateRes,
        std::map<AccessTokenID, std::vector<GenericValues>>& permStateMap);
    void InitExtendedPermContext(const std::vector<GenericValues>& extendedPermRes,
        std::map<AccessTokenID, std::vector<GenericValues>>& extendedPermMap);
    void InitHapTokenContext(const std::vector<GenericValues>& hapTokenRes,
        const std::map<AccessTokenID, std::vector<GenericValues>>& permStateMap,
        const std::map<AccessTokenID, std::vector<GenericValues>>& extendedPermMap);
    bool InitSingleHapTokenContext(const GenericValues& tokenValue,
        const std::map<AccessTokenID, std::vector<GenericValues>>& permStateMap,
        const std::map<AccessTokenID, std::vector<GenericValues>>& extendedPermMap);
    static bool BuildHapTokenInfoItemFromDb(AccessTokenID tokenId, const GenericValues& tokenValue,
        HapTokenInfoItem& hapTokenInfoItem);
    static void BuildBriefPermDataFromDb(const std::vector<GenericValues>& permStateValues,
        std::vector<BriefPermData>& briefPermData);
    int32_t InitPermissionList(HapPolicy& policy, BundleParam& bundleParam, HapInfoCheckResult& result);
    void UpdateBundleVerifyContext(const std::string& bundleName, AccessTokenID tokenId,
        const GenericValues& tokenValue, const std::vector<BriefPermData>& briefPermData);
    void BuildPriorityBundleList();
    int32_t RefreshBundleSignInfoMap();
    void VerifyNormalBundleListAsync();
    bool IsAllBundlesVerified() const;
    int32_t BuildVerifyBundleData(const std::string& bundleName, BundleSignInfo& signInfo);
    int32_t VerifyBundleWithState(const std::string& bundleName, bool isPreVerify = false);
    void VerifyBundleList(std::atomic_size_t& nextBundleIndex,
        std::map<std::string, VerifiedBundleState>& stateMap);
    int32_t VerifySingleBundle(const std::string& bundleName, BundleSignInfo& updatedInfo,
        VerifiedBundleState& state);
    void UpdateVerifiedSignInfo(const std::string& bundleName, BundleSignInfo& updatedInfo,
        const std::vector<uint32_t>& changedIndexList, const std::vector<TrustedBundleInfoInner>& trustedInfos,
        VerifiedBundleState& state);
    int32_t ReconcileVerifiedBundleCache(const std::string& bundleName, const HapPolicy& policy,
        const BundleParam& param, VerifiedBundleState& state);
    int32_t BuildSpmParams(const std::string& bundleName, BundleNoCachedInfo& noCachedInfo,
        std::vector<HapTokenInfo>& hapInfoCache, std::vector<std::vector<BriefPermData>>& permBriefDataListCache,
        std::vector<std::vector<PermissionWithValue>>& extendPermListCache, std::vector<SpmDataParam>& params);
    bool ShouldSkipVerifyLocked(const std::string& bundleName) const;
    void FinishSkippedBundleVerifyLocked(const std::string& bundleName);
    int32_t AddSpmDataAndCommitCache(
        const std::string& bundleName, const VerifiedBundleState& state);
    int32_t AddSpmDataForBundle(const std::string& bundleName);
    int32_t GetBundleTokenIds(const std::string& bundleName, std::vector<AccessTokenID>& tokenIds);
    int32_t BuildVerifiedBundlePersistInfo(const std::string& bundleName, const VerifiedBundleState& state,
        std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec);
    void BuildBundlePersistInfos(AccessTokenID tokenId, const VerifiedBundleState& state,
        std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec);
    void BuildSignInfoPersistInfo(
        const std::string& bundleName, std::vector<DelInfo>& delInfoVec, std::vector<AddInfo>& addInfoVec);
    int32_t PersistVerifiedBundleState(const std::string& bundleName, const VerifiedBundleState& state);
    int32_t PersistVerifiedBundleStates(
        const std::vector<std::pair<std::string, VerifiedBundleState>>& bundleStates);
    void FinishCommitBundleVerifyLocked(const std::string& bundleName);
    bool PrepareBundleForBatchVerifyLocked(const std::string& bundleName, BundleSignInfo& updatedInfo);
    void HandleVerifyBundleFailure(const std::string& bundleName, int32_t ret);
    void CommitBundleCacheLocked(const std::string& bundleName);
    void ChangeTokenIdToUntrustedStatus(const std::string& bundleName);
    static bool IsPermissionValid(int32_t hapApl, const PermissionBriefDef& data,
        const std::string& value, bool isAcl);
    static void UpdateBundleSignInfoByTrustedInfos(BundleSignInfo& signInfo,
        const std::vector<uint32_t>& changedIndexList,
        const std::vector<TrustedBundleInfoInner>& trustedInfos);
    void VerifyHighPrivilegeBundleList(std::map<std::string, VerifiedBundleState>& stateMap);
    void RunHighPrivilegeBundleVerifyTasks(std::vector<std::map<std::string, VerifiedBundleState>>& stateGroups);
    void HandleHighPrivilegeBundleSpmData(const std::map<std::string, VerifiedBundleState>& stateMap);
    bool HandleHapInfoUid(const std::string& bundleName, AccessTokenID tokenId, int32_t uid);
    int32_t PreVerifyBundleInner(const std::string& bundleName);
    BootVerifyScheduler() = default;
    ~BootVerifyScheduler() = default;
    DISALLOW_COPY_AND_MOVE(BootVerifyScheduler);

    std::vector<std::string> highPrivilegeBundleList_;
    std::vector<std::string> normalBundleList_;
    std::map<int, HapTokenInfoItem> hapTokenInfoMap_;
    std::map<std::string, std::shared_ptr<BundleInfoInner>> bundleInfoMap_;
    std::map<std::string, BundleNoCachedInfo> bundleNoCachedInfoMap_;
    std::map<uint32_t, std::vector<BriefPermData>> requestedPermData_;
    std::map<AccessTokenID, std::vector<PermissionWithValue>> extendedPermMap_;
    std::map<std::string, BundleSignInfo> bundleSignInfoMap_;
    std::map<std::string, bool> isVerifiedMap_;
    std::map<std::string, bool> isVerifyingMap_;
    std::atomic_bool isAllHapBundlesVerified_ = false;
    std::mutex verifyMutex_;
    std::condition_variable verifyCondition_;
    std::set<int32_t> uidSet_;
#endif
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_BOOT_VERIFY_SCHEDULER_H
