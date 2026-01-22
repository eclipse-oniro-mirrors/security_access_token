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

#ifndef SECURITY_ACCESSTOKEN_REMOTE_ADD_PERM_PARAM_INFO_H
#define SECURITY_ACCESSTOKEN_REMOTE_ADD_PERM_PARAM_INFO_H

#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief add remote permission param info
 */
struct RemoteAddPermParamInfo {
    std::string deviceId;
    std::string deviceName;
    std::string permissionName;
    int32_t successCount = 0;
    int32_t failCount = 0;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // SECURITY_ACCESSTOKEN_REMOTE_ADD_PERM_PARAM_INFO_H
