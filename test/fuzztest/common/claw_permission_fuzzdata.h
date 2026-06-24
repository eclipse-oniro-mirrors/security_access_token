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

#ifndef TEST_FUZZTEST_COMMON_CLAW_PERMISSION_FUZZDATA_H
#define TEST_FUZZTEST_COMMON_CLAW_PERMISSION_FUZZDATA_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "claw_permission_info.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr size_t MAX_CLAW_FUZZ_LIST_SIZE = 4;
constexpr size_t MAX_CLAW_FUZZ_PERMISSION_SIZE = 4;
constexpr size_t MAX_CLAW_FUZZ_STRING_LENGTH = 64;
const std::string DEFAULT_CLI_NAME = "ohos-queryTime";
const std::string DEFAULT_SUB_CLI_NAME = "get-wall-time";
const std::string DEFAULT_CLI_PERMISSION = "ohos.permission.APPROXIMATELY_LOCATION";
const std::string POWER_MANAGER_CLI_PERMISSION = "ohos.permission.cli.POWER_MANAGER";
const std::string CAMERA_PERMISSION = "ohos.permission.CAMERA";
}

inline std::string ConsumeClawString(FuzzedDataProvider& provider)
{
    return provider.ConsumeRandomLengthString(MAX_CLAW_FUZZ_STRING_LENGTH);
}

inline std::string ConsumeAgentID(FuzzedDataProvider& provider)
{
    return provider.ConsumeRandomLengthString(MAX_CLAW_AGENT_ID_LEN);
}

inline CliInfo ConsumeCliInfo(FuzzedDataProvider& provider)
{
    CliInfo info;
    info.cliName = ConsumeClawString(provider);
    info.subCliName = ConsumeClawString(provider);
    return info;
}

inline std::vector<std::string> ConsumePermissionNames(FuzzedDataProvider& provider)
{
    std::vector<std::string> permissions;
    size_t size = provider.ConsumeIntegralInRange<size_t>(0, MAX_CLAW_FUZZ_PERMISSION_SIZE);
    permissions.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        permissions.emplace_back(ConsumeClawString(provider));
    }
    return permissions;
}

inline std::vector<bool> ConsumeAuthorizationResults(FuzzedDataProvider& provider, size_t size)
{
    std::vector<bool> results;
    results.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        results.emplace_back(provider.ConsumeBool());
    }
    return results;
}

inline std::vector<CliInfo> ConsumeCliInfoList(FuzzedDataProvider& provider)
{
    std::vector<CliInfo> infos;
    size_t size = provider.ConsumeIntegralInRange<size_t>(0, MAX_CLAW_FUZZ_LIST_SIZE);
    infos.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        infos.emplace_back(ConsumeCliInfo(provider));
    }
    return infos;
}

inline CliAuthInfo ConsumeCliAuthInfo(FuzzedDataProvider& provider)
{
    CliAuthInfo info;
    info.cliInfo = ConsumeCliInfo(provider);
    info.permissionNames = ConsumePermissionNames(provider);
    size_t resultSize = provider.ConsumeBool() ? info.permissionNames.size() :
        provider.ConsumeIntegralInRange<size_t>(0, MAX_CLAW_FUZZ_PERMISSION_SIZE);
    info.authorizationResults = ConsumeAuthorizationResults(provider, resultSize);
    return info;
}

inline std::vector<CliAuthInfo> ConsumeCliAuthInfoList(FuzzedDataProvider& provider)
{
    std::vector<CliAuthInfo> infos;
    size_t size = provider.ConsumeIntegralInRange<size_t>(0, MAX_CLAW_FUZZ_LIST_SIZE);
    infos.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        infos.emplace_back(ConsumeCliAuthInfo(provider));
    }
    return infos;
}

inline std::vector<CliInfo> BuildKnownCliInfoList()
{
    return {
        { DEFAULT_CLI_NAME, DEFAULT_SUB_CLI_NAME },
        { "tooltokenstub", "stubsubtool" },
        { "camera", "capture" },
        { "resolved", "run" },
    };
}

inline CliAuthInfo BuildKnownQueryTimeCliAuthInfo()
{
    return {
        .cliInfo = { DEFAULT_CLI_NAME, DEFAULT_SUB_CLI_NAME },
        .permissionNames = { DEFAULT_CLI_PERMISSION, POWER_MANAGER_CLI_PERMISSION },
        .authorizationResults = { true, false },
    };
}

inline CliAuthInfo BuildKnownToolTokenCliAuthInfo()
{
    return {
        .cliInfo = { "tooltokenstub", "stubsubtool" },
        .permissionNames = { DEFAULT_CLI_PERMISSION, POWER_MANAGER_CLI_PERMISSION },
        .authorizationResults = { true, true },
    };
}

inline CliAuthInfo BuildKnownCameraCliAuthInfo()
{
    return {
        .cliInfo = { "camera", "capture" },
        .permissionNames = { CAMERA_PERMISSION, POWER_MANAGER_CLI_PERMISSION },
        .authorizationResults = { true, true },
    };
}

inline std::vector<CliAuthInfo> BuildKnownCliAuthInfoList()
{
    return {
        BuildKnownQueryTimeCliAuthInfo(),
        BuildKnownToolTokenCliAuthInfo(),
        BuildKnownCameraCliAuthInfo(),
    };
}

inline bool CanAppendKnownValue(size_t currentSize)
{
    return currentSize < MAX_CLAW_FUZZ_LIST_SIZE;
}

inline bool ShouldAppendKnownValue(FuzzedDataProvider& provider, size_t currentSize)
{
    return (currentSize == 0) || provider.ConsumeBool();
}

template <typename T>
inline void AppendOneKnownValue(FuzzedDataProvider& provider, std::vector<T>& values, const std::vector<T>& defaults)
{
    size_t index = provider.ConsumeIntegralInRange<size_t>(0, defaults.size() - 1);
    values.emplace_back(defaults[index]);
}

inline void AppendKnownCliInfos(FuzzedDataProvider& provider, std::vector<CliInfo>& infos)
{
    if (!CanAppendKnownValue(infos.size())) {
        return;
    }
    const auto defaults = BuildKnownCliInfoList();
    if (!ShouldAppendKnownValue(provider, infos.size())) {
        return;
    }
    AppendOneKnownValue(provider, infos, defaults);
}

inline void AppendKnownCliAuthInfos(FuzzedDataProvider& provider, std::vector<CliAuthInfo>& infos)
{
    if (!CanAppendKnownValue(infos.size())) {
        return;
    }
    const auto defaults = BuildKnownCliAuthInfoList();
    if (!ShouldAppendKnownValue(provider, infos.size())) {
        return;
    }
    AppendOneKnownValue(provider, infos, defaults);
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // TEST_FUZZTEST_COMMON_CLAW_PERMISSION_FUZZDATA_H
