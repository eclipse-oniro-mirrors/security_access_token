/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "multiple_mode_utils.h"

#include "accesstoken_info_utils.h"
#include "parameters.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr const char *IS_PC_MODE_PARAM = "persist.sceneboard.ispcmode";
static constexpr const char *MAIN_MODE_PARAM = "persist.sceneboard.mainmode";
}

namespace MultipleModeUtils {
MultipleMode GetTokenMode(int32_t instIndex)
{
    // negative indexes never map to a valid mode: clamp to the main mode so a
    // bogus instIndex cannot leak the query-only CURRENT_MODE value
    if (instIndex < 0) {
        return MultipleMode::DEFAULT_OR_MAIN_MODE;
    }
    return static_cast<MultipleMode>(instIndex / MAIN_CLONE_INDEX_BASE);
}

bool IsMainAppIndex(int32_t instIndex)
{
    return (instIndex % MAIN_CLONE_INDEX_BASE) == 0;
}

bool IsModeInstIndexMatch(int32_t mode, int32_t instIndex)
{
    if (instIndex < 0) {
        return false;
    }
    return static_cast<int32_t>(GetTokenMode(instIndex)) == mode;
}

MultipleMode GetCurrentMode()
{
    int32_t isPcMode = OHOS::system::GetIntParameter(IS_PC_MODE_PARAM,
        static_cast<int32_t>(MultipleMode::DEFAULT_OR_MAIN_MODE));
    int32_t mainMode = OHOS::system::GetIntParameter(MAIN_MODE_PARAM,
        static_cast<int32_t>(MultipleMode::DEFAULT_OR_MAIN_MODE));
    return (isPcMode == mainMode) ? MultipleMode::DEFAULT_OR_MAIN_MODE : MultipleMode::SUB_MODE;
}

std::string GetBundleModeKey(const std::string& bundleName, int32_t mode)
{
    return bundleName + std::to_string(mode);
}
} // namespace MultipleModeUtils
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
