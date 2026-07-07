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

#ifndef ACCESS_TOKEN_MIGRATION_MANAGER_H
#define ACCESS_TOKEN_MIGRATION_MANAGER_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>

#include "access_token.h"
#include "access_event_handler.h"
#include "generic_values.h"
#include "idl_common.h"
#include "hap_token_info_inner.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct MigratedInfoIdl;
struct BundleMigrateResultIdl;

struct PreparedMigrationBundle final {
    MigratedInfoIdl migratedInfo;
    std::vector<std::shared_ptr<HapTokenInfoInner>> cachedInfos;
    std::vector<bool> newTokenFlags;
    bool needVerification = false;
};

class AccessTokenMigrationManager final {
public:
    static AccessTokenMigrationManager& GetInstance();

    int32_t MigrateInstalledBundles(const std::vector<MigratedInfoIdl>& migratedInfoList,
        std::vector<BundleMigrateResultIdl>& results);
    int32_t FinishMigration();
    bool IsMigrationCompleted() const;
    void Initialize();
    
private:
    AccessTokenMigrationManager() = default;
    
    int32_t AppendHapTokenDbInfo(const PreparedMigrationBundle& preparedBundle,
        std::vector<GenericValues>& addValues);

    static int32_t MarkMigrationCompleted();
    static int32_t ValidateMigratedInfo(const MigratedInfoIdl& migratedInfo);
    static int32_t GetCachedTokenInfo(AccessTokenID tokenId, const std::string& bundleName,
        std::shared_ptr<HapTokenInfoInner>& infoPtr);
    static int32_t CheckCachedUid(const std::shared_ptr<HapTokenInfoInner>& infoPtr, int32_t uid);
    static int32_t CreateNewTokenInfoForHap(PreparedMigrationBundle& preparedBundle, size_t index,
        std::shared_ptr<HapTokenInfoInner>& infoPtr);
    static int32_t CheckDuplicateHapBaseInfo(const HapBaseInfoIdl& hapBaseInfo,
        std::unordered_set<std::string>& seenHapBaseInfos);
    static int32_t QueryAllHapTokenRows(std::vector<GenericValues>& dbResults);
    static std::unordered_map<int32_t, GenericValues> BuildDbRowCache(std::vector<GenericValues>& dbResults);
    int32_t BuildUidBundleCaches();
    int32_t CheckUidConflict(const MigratedInfoIdl& migratedInfo, int32_t uid,
        std::unordered_set<int32_t>& seenInBundle) const;
    int32_t CheckBundleIdConflict(const MigratedInfoIdl& migratedInfo, const HapBaseInfoIdl& hapBaseInfo, int32_t uid,
        std::unordered_map<int32_t, int32_t>& bundleIdByInstIndex) const;
    int32_t CheckMigrationConflicts(const MigratedInfoIdl& migratedInfo) const;
    static void FillFailedMigrationResult(const MigratedInfoIdl& migratedInfo, BundleMigrateResultIdl& migrateResult);
    int32_t PrepareIdentityInfos(PreparedMigrationBundle& preparedBundle);
    int32_t PersistMigratedBundles(const PreparedMigrationBundle& preparedBundles);
    int32_t ExecutePreparedMigration(PreparedMigrationBundle& preparedBundles);
    int32_t MigrateSingleBundle(const MigratedInfoIdl& migratedInfo,
        BundleMigrateResultIdl& result);
    int32_t LoadDbCacheIfNeeded();
    BundleMigrateResultIdl ProcessBundleMigration(const MigratedInfoIdl& migratedInfo);
    void SchedulePostVerifyTask();
    void ResetMigrationCache();
    void ReportInvalidUidsIfNeeded();
    std::shared_ptr<AccessEventHandler> GetEventHandler();

    std::unordered_map<int32_t, GenericValues> dbRowCache_;
    std::unordered_map<int32_t, std::string> uidOwnerBundles_;
    std::unordered_map<int32_t, std::string> bundleIdOwnerBundles_;
    bool cacheLoaded_ = false;
    std::mutex migrationMutex_;
    std::shared_ptr<AccessEventHandler> eventHandler_ = nullptr;
    std::mutex eventHandlerLock_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_MIGRATION_MANAGER_H
