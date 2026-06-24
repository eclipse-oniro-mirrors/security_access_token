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

#include "accesstokenmigrationmanager_fuzzer.h"

#include <string>
#include <vector>

#include "access_token_db.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_info_utils.h"
#include "fuzzer/FuzzedDataProvider.h"
#define private public
#include "accesstoken_id_manager.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_migration_manager.h"
#undef private
#include "parameter.h"
#include "permission_kernel_utils.h"
#include "spm_setproc.h"
#include "token_field_const.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
constexpr const char* BMS_MIGRATE_COMPLETED = "bms_migrate_completed";
constexpr size_t MAX_SUFFIX_LEN = 24;
constexpr int32_t BASE_UID = 220000;
constexpr int32_t MAX_UID_SPAN = 200000;

void ClearMigrationCompletedRecord()
{
    GenericValues delValue;
    delValue.Put(TokenFiledConst::FIELD_NAME, BMS_MIGRATE_COMPLETED);
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    delInfo.delValue = delValue;
    std::vector<DelInfo> delInfoVec = { delInfo };
    std::vector<AddInfo> addInfoVec;
    (void)AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec);

    AccessTokenIDManager::GetInstance().migrationDone_ = false;
    auto& manager = AccessTokenMigrationManager::GetInstance();
    manager.dbRowCache_.clear();
    manager.existingUids_.clear();
    manager.cacheLoaded_ = false;
}

void CleanupBundleArtifacts(const std::string& bundleName)
{
    GenericValues condition;
    condition.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    std::vector<GenericValues> results;
    if (AccessTokenDbOperator::Find(AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO, condition, results) != RET_SUCCESS) {
        return;
    }

    for (const auto& row : results) {
        AccessTokenID tokenId = static_cast<AccessTokenID>(row.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
        (void)SpmRemoveEntry(tokenId);
        (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
    }
}

std::string ConsumeBundleName(FuzzedDataProvider& provider)
{
    std::string suffix = provider.ConsumeRandomLengthString(MAX_SUFFIX_LEN);
    if (suffix.empty()) {
        suffix = "default";
    }
    return "com.example.migrationfuzz." + suffix;
}

MigratedInfoIdl BuildHappyPathMigratedInfo(FuzzedDataProvider& provider)
{
    MigratedInfoIdl migratedInfo;
    migratedInfo.bundleName = ConsumeBundleName(provider);
    migratedInfo.pathList.isPreInstalled = provider.ConsumeBool();

    HapBaseInfoIdl baseInfo;
    baseInfo.userID = provider.ConsumeIntegralInRange<int32_t>(0, MAX_UID_SPAN);
    baseInfo.bundleName = migratedInfo.bundleName;
    baseInfo.instIndex = 0;
    migratedInfo.hapBaseInfoList = { baseInfo };
    migratedInfo.uidList = { BASE_UID + provider.ConsumeIntegralInRange<int32_t>(1, MAX_UID_SPAN) };
    migratedInfo.reservedTypeList = { ReservedTypeIdl::NONE };
    return migratedInfo;
}

int32_t FindAvailableUid(AccessTokenMigrationManager& manager, int32_t preferredUid)
{
    for (int32_t offset = 0; offset < MAX_UID_SPAN; ++offset) {
        int32_t candidate = preferredUid + offset;
        if (manager.existingUids_.count(candidate) == 0) {
            return candidate;
        }
    }
    return preferredUid + MAX_UID_SPAN + 1;
}
} // namespace

bool AccessTokenMigrationManagerFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    SetParameter(ACCESS_TOKEN_SERVICE_SPM_ENFORCING_KEY, "0");

    auto migratedInfo = BuildHappyPathMigratedInfo(provider);
    CleanupBundleArtifacts(migratedInfo.bundleName);
    ClearMigrationCompletedRecord();

    auto& manager = AccessTokenMigrationManager::GetInstance();
    if (manager.LoadDbCacheIfNeeded() != RET_SUCCESS) {
        ClearMigrationCompletedRecord();
        return false;
    }
    migratedInfo.uidList[0] = FindAvailableUid(
        manager, BASE_UID + provider.ConsumeIntegralInRange<int32_t>(1, MAX_UID_SPAN));

    std::vector<MigratedInfoIdl> migratedInfoList = { migratedInfo };
    std::vector<BundleMigrateResultIdl> results;
    (void)manager.MigrateInstalledBundles(migratedInfoList, results);
    (void)manager.FinishMigration();

    CleanupBundleArtifacts(migratedInfo.bundleName);
    ClearMigrationCompletedRecord();
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::AccessTokenMigrationManagerFuzzTest(data, size);
    return 0;
}
