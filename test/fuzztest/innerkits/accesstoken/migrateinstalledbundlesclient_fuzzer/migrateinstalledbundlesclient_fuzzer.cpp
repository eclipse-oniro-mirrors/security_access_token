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

#include "migrateinstalledbundlesclient_fuzzer.h"

#include <climits>
#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
constexpr int32_t MAX_BUNDLE_COUNT = 4;
constexpr int32_t MAX_HAP_COUNT = 3;
constexpr int32_t MAX_PATH_COUNT = 3;
constexpr size_t MAX_STRING_SIZE = 96;

std::string ConsumeBundleName(FuzzedDataProvider& provider)
{
    std::string suffix = provider.ConsumeRandomLengthString(MAX_STRING_SIZE / 2);
    if (suffix.empty()) {
        suffix = "default";
    }
    return "com.example." + suffix;
}

MigratedInfo ConsumeMigratedInfo(FuzzedDataProvider& provider)
{
    MigratedInfo migratedInfo;
    migratedInfo.bundleName = ConsumeBundleName(provider);
    migratedInfo.pathList.isPreInstalled = provider.ConsumeBool();

    int32_t pathCount = provider.ConsumeIntegralInRange<int32_t>(1, MAX_PATH_COUNT);
    for (int32_t i = 0; i < pathCount; ++i) {
        migratedInfo.pathList.hapPaths.emplace_back("/data/test/" + ConsumeBundleName(provider) + ".hap");
    }

    int32_t hapCount = provider.ConsumeIntegralInRange<int32_t>(1, MAX_HAP_COUNT);
    for (int32_t i = 0; i < hapCount; ++i) {
        HapBaseInfo baseInfo;
        baseInfo.userID = provider.ConsumeIntegralInRange<int32_t>(0, INT_MAX);
        baseInfo.bundleName = migratedInfo.bundleName;
        baseInfo.instIndex = provider.ConsumeIntegral<int32_t>();
        migratedInfo.hapBaseInfoList.emplace_back(baseInfo);
        migratedInfo.uidList.emplace_back(provider.ConsumeIntegral<int32_t>());
        migratedInfo.reservedTypeList.emplace_back(provider.ConsumeBool() ?
            ReservedType::NONE : ReservedType::RESERVED_DATA);
    }
    return migratedInfo;
}
} // namespace

bool MigrateInstalledBundlesClientFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider provider(data, size);
    std::vector<MigratedInfo> migratedInfoList;
    int32_t bundleCount = provider.ConsumeIntegralInRange<int32_t>(1, MAX_BUNDLE_COUNT);
    for (int32_t i = 0; i < bundleCount; ++i) {
        migratedInfoList.emplace_back(ConsumeMigratedInfo(provider));
    }

    std::vector<BundleMigrateResult> results;
    (void)AccessTokenKit::MigrateInstalledBundles(migratedInfoList, results);
    return true;
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::MigrateInstalledBundlesClientFuzzTest(data, size);
    return 0;
}
