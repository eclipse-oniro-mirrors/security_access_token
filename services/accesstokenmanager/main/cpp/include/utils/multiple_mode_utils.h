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

#ifndef MULTIPLE_MODE_UTILS_H
#define MULTIPLE_MODE_UTILS_H

#include <string>

#include "hap_token_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace MultipleModeUtils {
MultipleMode GetTokenMode(int32_t instIndex);
bool IsMainAppIndex(int32_t instIndex);
bool IsModeInstIndexMatch(int32_t mode, int32_t instIndex);
MultipleMode GetCurrentMode();
std::string GetBundleModeKey(const std::string& bundleName, int32_t mode);
} // namespace MultipleModeUtils
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // MULTIPLE_MODE_UTILS_H
