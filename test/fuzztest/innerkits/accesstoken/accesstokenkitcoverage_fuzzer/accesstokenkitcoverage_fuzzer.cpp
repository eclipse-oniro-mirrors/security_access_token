/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "accesstokenkitcoverage_fuzzer.h"

#include <iostream>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <vector>
#undef private
#include "accesstoken_fuzzdata.h"
#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "mock_permission.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace {
// Fuzz ranges are derived from enum endpoints (one invalid sentinel on each side)
// to cover invalid-value rejection paths, so they track enum changes automatically.
const int32_t RESERVED_TYPE_MIN = static_cast<int32_t>(ReservedType::NONE) - 1;
const int32_t RESERVED_TYPE_MAX = static_cast<int32_t>(ReservedType::RESERVED_DATA) + 1;
const int32_t INSTALL_TYPE_MIN = static_cast<int32_t>(InstallTypeEnum::TYPE_INSTALL) - 1;
const int32_t INSTALL_TYPE_MAX = static_cast<int32_t>(InstallTypeEnum::TYPE_MERGE) + 1;
const int32_t DLP_TYPE_MIN = static_cast<int32_t>(DlpType::DLP_COMMON) - 1;
const int32_t DLP_TYPE_MAX = static_cast<int32_t>(DlpType::BUTT_DLP_TYPE);
const int32_t MODE_FUZZ_MIN = -1;
const int32_t MODE_FUZZ_MAX = 3;
const int32_t USER_ID_MIN = -1;
const int32_t USER_ID_MAX = 100;
const int32_t ENTRY_COUNT_MIN = 0;
const int32_t ENTRY_COUNT_MAX = 3;
const int32_t MIGRATE_INFO_COUNT_MAX = 2;
}

namespace OHOS {

static HapBaseInfo ConsumeHapBaseInfo(FuzzedDataProvider& provider)
{
    HapBaseInfo info;
    info.userID = provider.ConsumeIntegralInRange<int32_t>(USER_ID_MIN, USER_ID_MAX);
    info.bundleName = provider.ConsumeRandomLengthString();
    info.instIndex = provider.ConsumeIntegral<int32_t>();
    return info;
}

static BundlePolicy ConsumeBundlePolicy(FuzzedDataProvider& provider)
{
    BundlePolicy policy = {};
    policy.dlpType = static_cast<DlpType>(provider.ConsumeIntegralInRange<int32_t>(DLP_TYPE_MIN, DLP_TYPE_MAX));
    policy.isDebugGrant = provider.ConsumeBool();
    return policy;
}

static BundleHapList ConsumeBundleHapList(FuzzedDataProvider& provider)
{
    BundleHapList list;
    int32_t pathCount = provider.ConsumeIntegralInRange<int32_t>(ENTRY_COUNT_MIN, ENTRY_COUNT_MAX);
    for (int32_t i = 0; i < pathCount; i++) {
        list.hapPaths.push_back(provider.ConsumeRandomLengthString());
    }
    list.isPreInstalled = provider.ConsumeBool();
    list.userId = provider.ConsumeIntegral<int32_t>();
    list.mode = provider.ConsumeIntegralInRange<int32_t>(MODE_FUZZ_MIN, MODE_FUZZ_MAX);
    return list;
}

enum SpmApiSelector {
    SPM_API_DELETE_IDENTITY = 0,
    SPM_API_MIGRATE_INSTALLED_BUNDLES,
    SPM_API_FINISH_MIGRATION,
    SPM_API_CHECK_MIGRATED_UID_SET,
    SPM_API_CHECK_HAP_SIGN_INFO,
    SPM_API_CHECK_HAP_PERMISSION_INFO,
    SPM_API_PREPARE_HAP_IDENTITY,
    SPM_API_UPDATE_HAP_POLICY,
    SPM_API_FINISH_INSTALL,
    SPM_API_GET_HAP_SIGN_INFO,
    SPM_API_GET_CACHE_SIGN_INFO_BY_SESSION_ID,
    SPM_API_GET_CACHE_POLICY_BY_SESSION_ID,
    SPM_API_GET_HAP_IDENTITY,
    SPM_API_GET_HAP_BASE_INFO_BY_UID,
    SPM_API_BUTT,
};

static void DispatchSpmInterface(FuzzedDataProvider& provider, uint32_t spmSelector)
{
    switch (spmSelector) {
        case SPM_API_DELETE_IDENTITY: {
            AccessTokenID tokenId = provider.ConsumeBool() ? 0 : ConsumeTokenId(provider);
            AccessTokenKit::DeleteIdentity(tokenId, provider.ConsumeRandomLengthString(),
                static_cast<ReservedType>(
                    provider.ConsumeIntegralInRange<int32_t>(RESERVED_TYPE_MIN, RESERVED_TYPE_MAX)));
            break;
        }
        case SPM_API_MIGRATE_INSTALLED_BUNDLES: {
            std::vector<MigratedInfo> migratedInfoList;
            int32_t entryCount = provider.ConsumeIntegralInRange<int32_t>(ENTRY_COUNT_MIN, MIGRATE_INFO_COUNT_MAX);
            for (int32_t i = 0; i < entryCount; i++) {
                MigratedInfo migratedInfo;
                migratedInfo.bundleName = provider.ConsumeRandomLengthString();
                migratedInfo.pathList = ConsumeBundleHapList(provider);
                migratedInfo.hapBaseInfoList.push_back(ConsumeHapBaseInfo(provider));
                migratedInfo.uidList.push_back(provider.ConsumeIntegral<int32_t>());
                migratedInfo.reservedTypeList.push_back(
                    static_cast<ReservedType>(
                        provider.ConsumeIntegralInRange<int32_t>(RESERVED_TYPE_MIN, RESERVED_TYPE_MAX)));
                migratedInfoList.push_back(migratedInfo);
            }
            std::vector<BundleMigrateResult> results;
            AccessTokenKit::MigrateInstalledBundles(migratedInfoList, results);
            break;
        }
        case SPM_API_FINISH_MIGRATION: {
            AccessTokenKit::FinishMigration();
            break;
        }
        case SPM_API_CHECK_MIGRATED_UID_SET: {
            std::set<int32_t> totalUids;
            int32_t entryCount = provider.ConsumeIntegralInRange<int32_t>(ENTRY_COUNT_MIN, ENTRY_COUNT_MAX);
            for (int32_t i = 0; i < entryCount; i++) {
                totalUids.insert(provider.ConsumeIntegral<int32_t>());
            }
            std::set<int32_t> unreceivedUids;
            AccessTokenKit::CheckMigratedUidSet(totalUids, unreceivedUids);
            break;
        }
        case SPM_API_CHECK_HAP_SIGN_INFO: {
            std::vector<TrustedBundleInfo> bundleInfo;
            HapVerifyResultInfo resultInfo;
            int32_t sessionId = provider.ConsumeIntegral<int32_t>();
            AccessTokenKit::CheckHapSignInfo(ConsumeBundleHapList(provider),
                provider.ConsumeIntegral<uint32_t>(), sessionId, bundleInfo, resultInfo);
            break;
        }
        case SPM_API_CHECK_HAP_PERMISSION_INFO: {
            HapInfoCheckResult result;
            AccessTokenKit::CheckHapPermissionInfo(provider.ConsumeIntegral<int32_t>(),
                static_cast<InstallTypeEnum>(
                    provider.ConsumeIntegralInRange<int32_t>(INSTALL_TYPE_MIN, INSTALL_TYPE_MAX)),
                result);
            break;
        }
        case SPM_API_PREPARE_HAP_IDENTITY: {
            int32_t sessionId = provider.ConsumeIntegral<int32_t>();
            Identity identity;
            AccessTokenKit::PrepareHapIdentity(sessionId, ConsumeHapBaseInfo(provider),
                ConsumeBundlePolicy(provider), identity);
            break;
        }
        case SPM_API_UPDATE_HAP_POLICY: {
            int32_t uid = provider.ConsumeIntegral<int32_t>();
            AccessTokenKit::UpdateHapPolicy(provider.ConsumeIntegral<int32_t>(),
                provider.ConsumeIntegral<int32_t>(), ConsumeBundlePolicy(provider), uid);
            break;
        }
        case SPM_API_FINISH_INSTALL: {
            std::map<std::string, std::string> modulePathMap;
            int32_t entryCount = provider.ConsumeIntegralInRange<int32_t>(ENTRY_COUNT_MIN, ENTRY_COUNT_MAX);
            for (int32_t i = 0; i < entryCount; i++) {
                modulePathMap[provider.ConsumeRandomLengthString()] = provider.ConsumeRandomLengthString();
            }
            AccessTokenKit::FinishInstall(provider.ConsumeIntegral<int32_t>(), provider.ConsumeBool(),
                modulePathMap);
            break;
        }
        case SPM_API_GET_HAP_SIGN_INFO: {
            std::vector<TrustedBundleInfo> bundleInfo;
            AccessTokenKit::GetHapSignInfo(provider.ConsumeRandomLengthString(),
                provider.ConsumeIntegral<uint32_t>(), bundleInfo);
            break;
        }
        case SPM_API_GET_CACHE_SIGN_INFO_BY_SESSION_ID: {
            std::vector<TrustedBundleInfo> bundleInfo;
            AccessTokenKit::GetCacheSignInfoBySessionId(provider.ConsumeIntegral<int32_t>(),
                provider.ConsumeIntegral<uint32_t>(), bundleInfo);
            break;
        }
        case SPM_API_GET_CACHE_POLICY_BY_SESSION_ID: {
            BundlePolicyInfo bundlePolicyInfo;
            AccessTokenKit::GetCachePolicyBySessionId(provider.ConsumeIntegral<int32_t>(),
                provider.ConsumeRandomLengthString(), bundlePolicyInfo);
            break;
        }
        case SPM_API_GET_HAP_IDENTITY: {
            Identity identity;
            AccessTokenKit::GetHapIdentity(ConsumeHapBaseInfo(provider), identity);
            break;
        }
        case SPM_API_GET_HAP_BASE_INFO_BY_UID: {
            HapBaseInfo info;
            AccessTokenKit::GetHapBaseInfoByUid(provider.ConsumeIntegral<int32_t>(), info);
            break;
        }
        default:
            break;
    }
}

bool AccessTokenKitCoverageFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    MockToken mock({}, false);

    uint32_t spmSelector = provider.ConsumeIntegralInRange<uint32_t>(0, SPM_API_BUTT - 1);
    std::string permissionName = ConsumePermissionName(provider);
    AccessTokenID tokenID = ConsumeTokenId(provider);
    HapTokenInfoExt info;
    AccessTokenKit::GetHapTokenInfoExtension(tokenID, info);
    std::vector<PermissionWithValue> kernelPermList;
    AccessTokenKit::GetKernelPermissions(tokenID, kernelPermList);
    std::string value;
    AccessTokenKit::GetReqPermissionByName(tokenID, permissionName, value);
    uint32_t version;
    AccessTokenKit::GetVersion(version);
    PermissionGrantInfo grantInfo;
    AccessTokenKit::GetPermissionManagerInfo(grantInfo);
    (void)AccessTokenKit::ResetDatabaseRecoveryStatus();

    DispatchSpmInterface(provider, spmSelector);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AccessTokenKitCoverageFuzzTest(data, size);
    return 0;
}
