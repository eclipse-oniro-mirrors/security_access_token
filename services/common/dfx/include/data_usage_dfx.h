/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ACCESSTOKEN_DATA_USAGE_DFX_H
#define ACCESSTOKEN_DATA_USAGE_DFX_H

#include <string>
#include <vector>
#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
uint64_t GetUserDataRemainSize();
uint64_t GetFileSize(const char* filePath);
void GetDatabaseFileSize(const std::string& name, std::vector<std::string>& filePath, std::vector<uint64_t>& fileSize);
void ReportAccessTokenUserData();
void ReportPrivacyUserData();
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_DATA_USAGE_DFX_H
