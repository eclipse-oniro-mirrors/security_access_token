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

#ifndef INTERFACES_INNER_KITS_PERMISSION_STATE_CHANGE_INFO_H
#define INTERFACES_INNER_KITS_PERMISSION_STATE_CHANGE_INFO_H

#include <string>
#include <vector>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
#define TOKENIDS_LIST_SIZE_MAX 1024
#define PERMS_LIST_SIZE_MAX 1024

struct PermStateChangeInfo {
    int32_t PermStateChangeType;
    AccessTokenID tokenID;
    std::string permissionName;
};

struct PermStateChangeScope {
    std::vector<AccessTokenID> tokenIDs;
    std::vector<std::string> permList;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // INTERFACES_INNER_KITS_PERMISSION_STATE_CHANGE_INFO_H
