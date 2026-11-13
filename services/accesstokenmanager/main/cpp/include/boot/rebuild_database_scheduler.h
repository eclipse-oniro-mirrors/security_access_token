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

#ifndef REBUILD_DATABASE_SCHEDULER_H
#define REBUILD_DATABASE_SCHEDULER_H

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "atm_data_type.h"
#include "atm_bundle_recovery_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

/**
 * Rebuild item for a single app: extends the AtmBundleRecoveryInfo with the data dir name
 * for locating hap files.
 */
struct RebuildDatabaseItem final {
    AppExecFwk::AtmBundleRecoveryInfo info;
    std::string dataDirName;
};

struct RebuildDatabaseData final {
    std::vector<GenericValues> hapTokenInfoRes;
    std::vector<GenericValues> permStateRes;
    std::vector<GenericValues> extendedPermRes;
    std::vector<GenericValues> hapSignInfoRes;
};

/**
 * Scheduler used when both the access_token.db master and replica are corrupted, rebuilding the
 * database. Flow: (1) fetch app info -> (2) get the data dir name -> (3) parse hap pre-authorization ->
 * (4) write access_token.db in a single transaction; a single-app failure is skipped;
 * the rebuild runs in a single transaction, so interruption rolls back (db empty, full
 * rebuild reruns next boot).
 */
class RebuildDatabaseScheduler final {
public:
    static RebuildDatabaseScheduler& GetInstance();

    int32_t StartRebuildDatabase(RebuildDatabaseData& rebuildDatabaseData);

#ifdef ATM_TEST_ENABLE
    void SetQueryResult(const AppExecFwk::AtmBundleRecoveryResult& result);
#endif

private:
    RebuildDatabaseScheduler() = default;
    ~RebuildDatabaseScheduler() = default;
    RebuildDatabaseScheduler(const RebuildDatabaseScheduler&) = delete;
    RebuildDatabaseScheduler& operator=(const RebuildDatabaseScheduler&) = delete;

    int32_t FetchAppInfoList(std::vector<AppExecFwk::AtmBundleRecoveryInfo>& appInfoList);
    void RebuildBundles(const std::vector<AppExecFwk::AtmBundleRecoveryInfo>& appInfoList);
    int32_t RebuildOneBundle(const RebuildDatabaseItem& item);
    void BuildHapTokenRecord(const RebuildDatabaseItem& item, int32_t realUid);
    void BuildHapInfoRecord(const RebuildDatabaseItem& item);
    int32_t PersistRebuildDatabase();
    void FillRebuildDatabaseData(RebuildDatabaseData& rebuildDatabaseData);
    void ClearRebuildCaches();

    // Accumulates db records of all apps to rebuild, committed once in a single transaction.
    std::vector<AddInfo> addInfoVec_;
    // Dedup sets to avoid primary-key conflicts when writing the database (take the first).
    std::set<uint32_t> addedTokenId_;
    std::set<std::string> addedHapTokenKey_;
    std::set<std::string> addedBundleKey_;
#ifdef ATM_TEST_ENABLE
    AppExecFwk::AtmBundleRecoveryResult testQueryResult_;
    bool hasTestQueryResult_ = false;
#endif
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // REBUILD_DATABASE_SCHEDULER_H