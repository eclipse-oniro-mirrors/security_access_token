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

#include "installsessionmanagermockstub_fuzzer.h"

#include <string>
#include <vector>

#undef private
#include "accesstoken_fuzzdata.h"
#define private public
#include "accesstoken_manager_service.h"
#include "install_session_manager.h"
#undef private
#include "fuzzer/FuzzedDataProvider.h"
#include "iaccess_token_manager.h"
#include "mock_permission.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
constexpr uint32_t MAX_HAP_PATHS_COUNT = 128;
constexpr int32_t MAX_USER_ID = 1000;
constexpr size_t MAX_PATH_SIZE = 256;
}

void InitBundleHapList(FuzzedDataProvider& provider, BundleHapList& hapList)
{
    uint32_t pathCount = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_HAP_PATHS_COUNT);
    for (uint32_t i = 0; i < pathCount; i++) {
        hapList.hapPaths.emplace_back(provider.ConsumeRandomLengthString(MAX_PATH_SIZE));
    }
    hapList.isPreInstalled = provider.ConsumeBool();
    hapList.userId = provider.ConsumeIntegralInRange<int32_t>(0, MAX_USER_ID);
}

void InitPrepareInfo(FuzzedDataProvider& provider, HapBaseInfo& baseInfo)
{
    baseInfo.userID = provider.ConsumeIntegralInRange<int32_t>(0, MAX_USER_ID);
    baseInfo.bundleName = "install_session_manager_fuzz_mock_test";
    baseInfo.instIndex = provider.ConsumeIntegralInRange<int32_t>(0, MAX_USER_ID);
}

void GetInfoBySessionTest(int32_t sessionId, const std::string& bundleName)
{
    std::vector<TrustedBundleInfo> bundleInfo;
    InstallSessionManager::GetInstance().GetCacheSignInfoBySessionId(sessionId, bundleInfo);

    BundlePolicyInfo bundlePolicyInfo;
    InstallSessionManager::GetInstance().GetCachePolicyBySessionId(sessionId, bundleName, bundlePolicyInfo);
}

void GetHapSignInfoTest(const std::string& bundleName)
{
    std::vector<TrustedBundleInfo> bundleInfo;
    InstallSessionManager::GetInstance().GetHapSignInfo(bundleName, bundleInfo);
}

bool InstallSessionManagerMockStubFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    BundleHapList hapList;
    InitBundleHapList(provider, hapList);
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    HapVerifyResultInfo resultInfo;
    InstallSessionManager::GetInstance().CheckHapSignInfo(hapList, nullptr, sessionId, bundleInfo, resultInfo);
    HapInfoCheckResult result;
    InstallSessionManager::GetInstance().CheckHapPermissionInfo(sessionId, TYPE_INSTALL, result);
    HapBaseInfo baseInfo;
    BundlePolicy bundlePolicy;
    Identity identity;
    InitPrepareInfo(provider, baseInfo);
    InstallSessionManager::GetInstance().PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, nullptr, identity);

    GetInfoBySessionTest(sessionId, "install_session_manager_fuzz_mock_test");

    std::map<std::string, std::string> modulePathMap;
    for (auto& path : hapList.hapPaths) {
        modulePathMap[path] = path;
    }
    InstallSessionManager::GetInstance().FinishInstall(sessionId, true, modulePathMap);

    int32_t sessionId2 = 0;
    HapBaseInfo baseInfo2;
    Identity identity2;
    InitPrepareInfo(provider, baseInfo2);
    InstallSessionManager::GetInstance().PrepareHapIdentity(sessionId2, baseInfo2, bundlePolicy, nullptr, identity2);
    InstallSessionManager::GetInstance().FinishInstall(sessionId2, true, modulePathMap);

    int32_t sessionId3 = 0;
    std::vector<TrustedBundleInfo> bundleInfo3;
    InstallSessionManager::GetInstance().CheckHapSignInfo(hapList, nullptr, sessionId3, bundleInfo3, resultInfo);
    InstallSessionManager::GetInstance().CheckHapPermissionInfo(sessionId3, TYPE_REPLACE, result);
    InstallSessionManager::GetInstance().FinishInstall(sessionId3, false, modulePathMap);

    int32_t sessionId4 = 0;
    std::vector<TrustedBundleInfo> bundleInfo4;
    InstallSessionManager::GetInstance().CheckHapSignInfo(hapList, nullptr, sessionId4, bundleInfo4, resultInfo);
    InstallSessionManager::GetInstance().CheckHapPermissionInfo(sessionId4, TYPE_REPLACE, result);
    InstallSessionManager::GetInstance().UpdateHapPolicy(
        sessionId4, static_cast<int32_t>(identity.tokenId & 0xffffffff), bundlePolicy, identity.uid);
    InstallSessionManager::GetInstance().FinishInstall(sessionId4, true, modulePathMap);

    GetHapSignInfoTest("install_session_manager_fuzz_mock_test");

    int32_t sceneCode = 0;
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->DeleteIdentityCore(
        0, "install_session_manager_fuzz_mock_test", ReservedType::NONE, sceneCode);

    return true;
}

void Initialize()
{
    DelayedSingleton<AccessTokenManagerService>::GetInstance()->Initialize();
    InstallSessionManager::GetInstance().SetMigrationDone();
}

} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Initialize();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::InstallSessionManagerMockStubFuzzTest(data, size);
    return 0;
}
