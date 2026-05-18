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

#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "access_token.h"
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
};

class AccessTokenMigrationManager final {
public:
    static AccessTokenMigrationManager& GetInstance();

    int32_t MigrateInstalledBundles(const std::vector<MigratedInfoIdl>& migratedInfoList,
        std::vector<BundleMigrateResultIdl>& results);
    int32_t PreMigrateUIDList(const std::vector<int32_t>& uidList);
    int32_t FinishMigration() const;
    bool IsMigrationCompleted() const;
    void Initialize();

    int32_t AppendHapTokenDbInfo(const PreparedMigrationBundle& preparedBundle,
        std::vector<GenericValues>& addValues);

private:
    AccessTokenMigrationManager() = default;

    mutable std::mutex preMigratedUidLock_;
    std::unordered_set<int32_t> preMigratedUidSet_;

    std::unordered_map<int32_t, GenericValues> dbRowCache_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACCESS_TOKEN_MIGRATION_MANAGER_H
