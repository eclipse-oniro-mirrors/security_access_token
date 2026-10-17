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

#ifndef INSTALL_DB_REPOSITORY_H
#define INSTALL_DB_REPOSITORY_H

#include <map>
#include <string>
#include <vector>

#include "access_token.h"
#include "atm_data_type.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "install_session_cache.h"
#include "permission_data_brief.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

/**
 * @brief Database access layer for install sessions.
 *
 * Contains pure db read/write operations and db record assembly for the install
 * flow: reading installed bundle info, querying hap token records, assembling
 * hap token / permission state / permission def / package info records, and
 * submitting all inserts and deletes in one transaction.
 *
 * Install business rules (permission inheritance, verify, policy merge) stay in
 * InstallSessionManager and call into this repository.
 */
class InstallDbRepository final {
public:
    // Read the installed bundle module records (path/persistData) of the bundle.
    static int32_t GetInstalledBundleInfo(std::string bundleName, std::vector<std::string>& paths,
        std::vector<std::vector<uint8_t>>& persistDatas);
    // Strict query: only the rows of the given mode (no fallback).
    static int32_t GetInstalledBundleInfo(std::string bundleName, MultipleMode mode,
        std::vector<std::string>& paths, std::vector<std::vector<uint8_t>>& persistDatas);
    // Query hap token records by bundleName and instIndex.
    static int32_t QueryBundleTokenbyIndex(const std::string& bundleName, int32_t instIndex,
        std::vector<GenericValues>& hapTokenResults);
    // Query all hap token records of the bundle by bundleName; assemble the
    // session-level tokenId list into the cache (ACTIVE tokens only, filtered
    // by the id manager status) and mark the session cache loaded.
    static int32_t QueryBundleTokens(const std::string& bundleName, InstallCache& cache,
        std::vector<GenericValues>& hapTokenResults);
    // Read permission states of the token from db and convert to brief permission data.
    static int32_t FillPermStateFromDb(AccessTokenID tokenId, std::vector<BriefPermData>& oldPermBriefDataList);
    // Remove residual records of the token from hap token related tables.
    static int32_t DeleteFromDbByTokenId(AccessTokenID tokenID);
    // Assemble all db records for the finish context (token, permission and
    // package info ops) into op vectors; the caller submits them in one
    // transaction (KernelAndDBWriteTransaction::CommitDb).
    static int32_t BuildDbOpsVec(const InstallCache& cache, const FinishContext& context,
        const std::map<std::string, std::string>& modulePathMap, std::vector<AddInfo>& addInfoVec,
        std::vector<DelInfo>& delInfoVec);

private:
    // Resolve the final on-disk path for every module in cache.bundleInfos:
    // new modules via BMS's modulePathMap, merge-surviving old modules via cache.oldModulePaths.
    static int32_t ResolveModulePaths(const InstallCache& cache,
        const std::map<std::string, std::string>& modulePathMap, std::vector<std::string>& modulePaths);
    static void GenerateHapTokenInfoItem(const InstallCache& cache, const HapTokenInfo& hapInfo,
        std::vector<GenericValues>& genericValues);
    static void ConvertBriefPermDataToGenericValues(AccessTokenID tokenId,
        const std::vector<BriefPermData>& briefPermDataList, std::vector<GenericValues>& genericValuesList);
    static void GeneratePermDefFromHapPolicy(AccessTokenID tokenId, const HapPolicy& hapPolicy,
        const std::string& bundleName, std::vector<GenericValues>& genericValuesList);
    static int32_t ConvertInstallCacheToBundleInfoItems(const InstallCache& cache,
        const std::map<std::string, std::string>& modulePathMap, std::vector<GenericValues>& genericValuesList,
        GenericValues& delCondition);
    static void GenerateTokenDbOpsVec(const InstallCache& cache, const HapTokenInfo& hapInfo,
        const std::vector<BriefPermData>& permBriefDataList, std::vector<AddInfo>& addInfoVec,
        std::vector<DelInfo>& delInfoVec);
    static void TranslateGenericValuesToPermState(const std::vector<GenericValues>& permStateResults,
        std::vector<PermissionStatus>& existingPermList);
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // INSTALL_DB_REPOSITORY_H
