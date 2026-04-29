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

inline SkillInfo ConsumeSkillInfo(FuzzedDataProvider& provider)
{
    SkillInfo info;
    info.skillName = ConsumeClawString(provider);
    info.bundleName = ConsumeClawString(provider);
    info.moduleName = ConsumeClawString(provider);
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

inline std::vector<SkillInfo> ConsumeSkillInfoList(FuzzedDataProvider& provider)
{
    std::vector<SkillInfo> infos;
    size_t size = provider.ConsumeIntegralInRange<size_t>(0, MAX_CLAW_FUZZ_LIST_SIZE);
    infos.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        infos.emplace_back(ConsumeSkillInfo(provider));
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

inline SkillAuthInfo ConsumeSkillAuthInfo(FuzzedDataProvider& provider)
{
    SkillAuthInfo info;
    info.skillInfo = ConsumeSkillInfo(provider);
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

inline std::vector<SkillAuthInfo> ConsumeSkillAuthInfoList(FuzzedDataProvider& provider)
{
    std::vector<SkillAuthInfo> infos;
    size_t size = provider.ConsumeIntegralInRange<size_t>(0, MAX_CLAW_FUZZ_LIST_SIZE);
    infos.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        infos.emplace_back(ConsumeSkillAuthInfo(provider));
    }
    return infos;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // TEST_FUZZTEST_COMMON_CLAW_PERMISSION_FUZZDATA_H
