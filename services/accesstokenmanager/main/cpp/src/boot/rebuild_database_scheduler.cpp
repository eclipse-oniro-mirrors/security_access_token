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

#include "rebuild_database_scheduler.h"

#include <string>
#include <sys/stat.h>
#include <utility>

#include "accesstoken_common_log.h"
#include "access_token_basic_type.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_info_utils.h"
#include "bms_adapter.h"
#include "hisysevent_adapter.h"
#include "multiple_mode_utils.h"
#include "spm_module_parser.h"
#include "table_item.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* HAP_APP_DATA_BASE = "/data/app/el1/";
// The upper 32 bits of accessTokenIdEx are tokenAttr; shift bits to extract it.
constexpr int32_t TOKEN_ID_EX_ATTR_SHIFT_BITS = 32;
// Reserved flag of tokenAttr, set when an app is uninstalled with data/identity reserved.
constexpr uint32_t TOKEN_RESERVED_FLAG = 0x0004;

// Resolve the real uid via fstat on the sandbox data dir (/data/app/el1/<userId>/<dataDirName>).
// The returned uid is unreliable (may be -1); use the sandbox dir owner instead.
int32_t ResolveUidByFstat(const AppExecFwk::AtmBundleRecoveryInfo& info, int32_t& uid)
{
    std::string dataDirName = BmsAdapter::GetAppDataDirName(info.bundleName, info.appIndex);
    std::string sandboxPath = std::string(HAP_APP_DATA_BASE) + std::to_string(info.userId) + "/base/" + dataDirName;
    struct stat statBuf = {0};
    if (stat(sandboxPath.c_str(), &statBuf) != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "stat sandbox path failed: %{public}s.", sandboxPath.c_str());
        return AccessTokenError::ERR_FILE_OPERATE_FAILED;
    }
    uid = static_cast<int32_t>(statBuf.st_uid);
    return RET_SUCCESS;
}
}

RebuildDatabaseScheduler& RebuildDatabaseScheduler::GetInstance()
{
    static RebuildDatabaseScheduler instance;
    return instance;
}

#ifdef ATM_TEST_ENABLE
void RebuildDatabaseScheduler::SetQueryResult(const AppExecFwk::AtmBundleRecoveryResult& result)
{
    testQueryResult_ = result;
    hasTestQueryResult_ = true;
}
#endif

int32_t RebuildDatabaseScheduler::StartRebuildDatabase(RebuildDatabaseData& rebuildDatabaseData)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Rebuild database start.");
    rebuildDatabaseData = RebuildDatabaseData();
    ClearThreadErrorMsg();
    ClearRebuildCaches();

    std::vector<AppExecFwk::AtmBundleRecoveryInfo> appInfoList;
    int32_t ret = FetchAppInfoList(appInfoList);
    if (ret != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Fetch app info list failed, ret=%{public}d.", ret);
        return ret;
    }
    if (appInfoList.empty()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "No app to rebuild, done with empty list.");
        return RET_SUCCESS;
    }

    RebuildBundles(appInfoList);

    // Persist in a single transaction: commit all parsed apps at once for atomicity
    // (interruption rolls back, leaving the db empty).
    ret = PersistRebuildDatabase();
    if (ret != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Persist rebuilt database failed, ret=%{public}d.", ret);
        ClearRebuildCaches();
        if (GetThreadErrorMsgLen() > 0) {
            ReportSysCommonEventError(AccessTokenServiceStartSceneCode::REBUILD_DATABASE, ret);
        }
        return ret;
    }

    FillRebuildDatabaseData(rebuildDatabaseData);
    ClearRebuildCaches();
    if (GetThreadErrorMsgLen() > 0) {
        ReportSysCommonEventError(AccessTokenServiceStartSceneCode::REBUILD_DATABASE, ret);
    }
    return RET_SUCCESS;
}

void RebuildDatabaseScheduler::ClearRebuildCaches()
{
    addInfoVec_.clear();
    addedTokenId_.clear();
    addedHapTokenKey_.clear();
    addedBundleKey_.clear();
}

void RebuildDatabaseScheduler::FillRebuildDatabaseData(RebuildDatabaseData& rebuildDatabaseData)
{
    for (const auto& addInfo : addInfoVec_) {
        switch (addInfo.addType) {
            case AtmDataType::ACCESSTOKEN_HAP_TOKEN_INFO:
                rebuildDatabaseData.hapTokenInfoRes.insert(rebuildDatabaseData.hapTokenInfoRes.end(),
                    addInfo.addValues.begin(), addInfo.addValues.end());
                break;
            case AtmDataType::ACCESSTOKEN_HAP_PACKAGE_INFO:
                rebuildDatabaseData.hapSignInfoRes.insert(rebuildDatabaseData.hapSignInfoRes.end(),
                    addInfo.addValues.begin(), addInfo.addValues.end());
                break;
            default:
                break;
        }
    }
}

int32_t RebuildDatabaseScheduler::FetchAppInfoList(std::vector<AppExecFwk::AtmBundleRecoveryInfo>& appInfoList)
{
#ifdef ATM_TEST_ENABLE
    if (hasTestQueryResult_) {
        appInfoList = testQueryResult_.infos;
        return testQueryResult_.code;
    }
#endif
    return BmsAdapter::QueryAppInfoList(appInfoList);
}

void RebuildDatabaseScheduler::RebuildBundles(const std::vector<AppExecFwk::AtmBundleRecoveryInfo>& appInfoList)
{
    for (const auto& info : appInfoList) {
        RebuildDatabaseItem item;
        item.info = info;
        item.dataDirName = BmsAdapter::GetAppDataDirName(info.bundleName, info.appIndex);
        (void)RebuildOneBundle(item);
    }
}

int32_t RebuildDatabaseScheduler::RebuildOneBundle(const RebuildDatabaseItem& item)
{
    // Resolve the real uid via fstat on the sandbox path; on failure keep uid as -1.
    int32_t realUid = -1;
    if (ResolveUidByFstat(item.info, realUid) != 0) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Resolve uid by fstat failed for %{public}s.", item.info.bundleName.c_str());
    }

    BuildHapTokenRecord(item, realUid);

    // App uninstalled with data kept (RESERVED_DATA) has no hap_info_table record, skip building it.
    if (!item.info.isUninstalled) {
        BuildHapInfoRecord(item);
    }

    LOGI(ATM_DOMAIN, ATM_TAG, "Rebuild bundle %{public}s (preInstall=%{public}d, uninstalled=%{public}d).",
        item.info.bundleName.c_str(), item.info.isPreInstallApp, item.info.isUninstalled);
    return RET_SUCCESS;
}

void RebuildDatabaseScheduler::BuildHapTokenRecord(const RebuildDatabaseItem& item, int32_t realUid)
{
    // Build the hap_token_info_table record. Skip when tokenId is 0.
    if (item.info.accessTokenId == 0) {
        return;
    }
    // Dedup by accessTokenId (low 32 bits): take the first and skip duplicates to avoid primary-key conflicts.
    if (addedTokenId_.find(item.info.accessTokenId) != addedTokenId_.end()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Duplicate app %{public}s, skip.", item.info.bundleName.c_str());
        return;
    }
    addedTokenId_.insert(item.info.accessTokenId);

    // Dedup by bundleName + userId + instIndex: take the first and skip duplicates to avoid
    // primary-key conflicts on db write.
    std::string hapTokenKey =
        AccessTokenInfoUtils::GetHapUniqueStr(item.info.userId, item.info.bundleName, item.info.appIndex);
    if (addedHapTokenKey_.find(hapTokenKey) != addedHapTokenKey_.end()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Duplicate app %{public}s, skip.", item.info.bundleName.c_str());
        return;
    }
    addedHapTokenKey_.insert(hapTokenKey);

    // Fields marked below are assigned default values and will be updated after hap sign verification.
    HapTokenInfoItem tokenItem;
    tokenItem.tokenId = item.info.accessTokenId;
    tokenItem.userId = static_cast<uint32_t>(item.info.userId);
    tokenItem.bundleName = item.info.bundleName;
    tokenItem.instIndex = static_cast<uint32_t>(item.info.appIndex);
    tokenItem.dlpType = DLP_COMMON;
    tokenItem.appId = ""; // default empty, updated after sign verification
    tokenItem.deviceId = "0";
    // A reserved (uninstalled-with-data-kept) app has no hap to verify, so its APL cannot be
    // restored; keep APL_INVALID(=0) to stay consistent with the normal reserve-uninstall path.
    tokenItem.apl = item.info.isUninstalled ? APL_INVALID : APL_NORMAL;
    tokenItem.version = DEFAULT_TOKEN_VERSION;
    uint32_t tokenAttr = static_cast<uint32_t>(item.info.accessTokenIdEx >> TOKEN_ID_EX_ATTR_SHIFT_BITS);
    // Mark the reserved flag on tokenAttr for reserved apps, consistent with DeleteBundleManager.
    tokenItem.tokenAttr = item.info.isUninstalled ? (tokenAttr | TOKEN_RESERVED_FLAG) : tokenAttr;
    tokenItem.apiVersion = 0; // default 0, updated after sign verification
    tokenItem.permDialogCapState = false;
    tokenItem.uid = realUid;
    tokenItem.migrated = true;
    // App uninstalled with data kept: set reserved to RESERVED_DATA(=2).
    tokenItem.reserved = item.info.isUninstalled ? ReservedType::RESERVED_DATA : ReservedType::NONE;
    tokenItem.isSideload = false; // default false, updated after sign verification
    std::vector<GenericValues> tokenValues;
    tokenItem.BuildAddValue(tokenValues);
    HapTokenInfoItem::GenerateAddList(tokenValues, addInfoVec_);
}

void RebuildDatabaseScheduler::BuildHapInfoRecord(const RebuildDatabaseItem& item)
{
    MultipleMode mode = MultipleModeUtils::GetTokenMode(item.info.appIndex);
    std::string bundleKey = item.info.bundleName + std::to_string(static_cast<int32_t>(mode));
    if (addedBundleKey_.find(bundleKey) != addedBundleKey_.end()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Duplicate bundle %{public}s, skip.", item.info.bundleName.c_str());
        return;
    }
    addedBundleKey_.insert(bundleKey);

    // Build the hap_info_table record (hap package info).
    BundleInfoItems bundleItems;
    bundleItems.bundleName = item.info.bundleName;
    bundleItems.mode = mode;
    bundleItems.isPreInstalled = item.info.isPreInstallApp;
    // moduleName has no real source during rebuild; use "#N" placeholder (N increments from 1) to avoid
    // hap_info_table primary-key (bundle+module+mode) conflicts. It will be overwritten by the real
    // moduleName after sign verification.
    int32_t moduleIndex = 1;
    for (const auto& hapPath : item.info.hapPaths) {
        ModuleInfoItem moduleInfo;
        moduleInfo.moduleName = "#" + std::to_string(moduleIndex);
        moduleInfo.path = hapPath;
        moduleInfo.bundleType = static_cast<int32_t>(AppExecFwk::Spm::BundleType::APP);
        bundleItems.moduleInfoItems.emplace_back(std::move(moduleInfo));
        moduleIndex++;
    }
    std::vector<GenericValues> bundleValues;
    bundleItems.BuildAddValue(bundleValues);
    BundleInfoItems::GenerateAddList(bundleValues, addInfoVec_);
}

int32_t RebuildDatabaseScheduler::PersistRebuildDatabase()
{
    if (addInfoVec_.empty()) {
        LOGW(ATM_DOMAIN, ATM_TAG, "No bundle record to persist.");
        return RET_SUCCESS;
    }
    // Step 4: write access_token.db in a single transaction
    // (no sign verification, no AccessTokenInfoManager cache update).
    // The db has been rebuilt as empty tables, so there are no deletions;
    // all new records are committed in one transaction.
    std::vector<DelInfo> delInfoVec;
    return AccessTokenDbOperator::DeleteAndInsertValues(delInfoVec, addInfoVec_);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS