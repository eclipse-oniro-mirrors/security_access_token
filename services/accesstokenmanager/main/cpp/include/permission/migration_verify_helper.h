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

#ifndef MIGRATION_VERIFY_HELPER_H
#define MIGRATION_VERIFY_HELPER_H

#include <memory>
#include <vector>

#include "access_token.h"
#include "bundle_sign_info.h"
#include "hap_sign_verify_manager.h"
#include "hap_token_info.h"
#include "hap_token_info_inner.h"
#include "idl_common.h"
#include "add_spm_data_task.h"
#include "atm_data_type.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

struct VerifiedMigrationBundle final {
    std::vector<TrustedBundleInfoInner> verifiedInfos;
    HapPolicy policy;
    BundleParam installParam;
};

class MigrationVerifyHelper final {
public:
    static MigrationVerifyHelper& GetInstance();
    int32_t VerifyMigratedBundle(const MigratedInfoIdl& migratedInfo,
        const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos);

private:
    MigrationVerifyHelper() = default;

    int32_t PersistDbInfo(const MigratedInfoIdl& migratedInfo,
        const VerifiedMigrationBundle& verifiedBundle,
        const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos);
    int32_t AddKernelData(const BundleNoCachedInfo& noCachedInfo,
        const std::vector<PermissionWithValue>& extendPermList,
        const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos,
        const std::vector<std::vector<BriefPermData>>& permBriefDataPerToken,
        std::unique_ptr<AddSpmDataTask>& kernelTask);

    int32_t DoVerifyMigratedBundle(const MigratedInfoIdl& migratedInfo,
        VerifiedMigrationBundle& verifiedBundle);
    void FixBriefPermDataPerToken(const VerifiedMigrationBundle& verifiedBundle,
        const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos,
        BundleNoCachedInfo& noCached,
        std::vector<std::vector<BriefPermData>>& fixedPermBriefPerToken);
    std::vector<GenericValues> BuildPermStateValues(
        AccessTokenID tokenId, const std::vector<BriefPermData>& data);
    int32_t BuildBundleSignInfo(const MigratedInfoIdl& migratedInfo,
        const VerifiedMigrationBundle& verifiedBundle, BundleSignInfo& bundleSignInfo);
    int32_t PrepareBundleInfoOperations(const BundleSignInfo& bundleSignInfo);
    void PrepareHapInfoOperations(const BundleParam& param, const HapPolicy& policy,
        const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos);

    std::vector<DelInfo> delInfoVec_;
    std::vector<AddInfo> addInfoVec_;
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // MIGRATION_VERIFY_HELPER_H
