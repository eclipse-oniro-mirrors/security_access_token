/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ACTIVE_CHANGE_RESPONSE_INFO_H
#define ACTIVE_CHANGE_RESPONSE_INFO_H

#include <string>
#include <vector>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
enum ActiveChangeType {
    PERM_INACTIVE = 0,
    PERM_ACTIVE_IN_FOREGROUND = 1,
    PERM_ACTIVE_IN_BACKGROUND = 2,
};

struct ActiveChangeResponse {
    AccessTokenID tokenID;
    std::string permissionName;
    std::string deviceId;
    ActiveChangeType type;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ACTIVE_CHANGE_RESPONSE_INFO_H