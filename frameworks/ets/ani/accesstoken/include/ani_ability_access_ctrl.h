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

#ifndef ABILITY_ACCESS_CTRL_H
#define ABILITY_ACCESS_CTRL_H

#include "access_token.h"
#include "ani_error.h"
namespace OHOS {
namespace Security {
namespace AccessToken {
const int32_t PARAM_DEFAULT_VALUE = -1;
struct AtManagerAsyncContext {
    AccessTokenID tokenId = 0;
    std::string permissionName;
    union {
        uint32_t flag = 0;
        uint32_t status;
    };
    int32_t grantStatus = PERMISSION_DENIED;
    AtmResult result;
};

struct PermissionParamCache {
    long long sysCommitIdCache = PARAM_DEFAULT_VALUE;
    int32_t commitIdCache = PARAM_DEFAULT_VALUE;
    int32_t handle = PARAM_DEFAULT_VALUE;
    std::string sysParamCache;
};

struct GrantStatusCache {
    int32_t status;
    std::string paramValue;
};

struct AtManagerSyncContext {
    std::string permissionName;
    PermissionOper permissionsStatus = PermissionOper::INVALID_OPER;
    int32_t result = RET_FAILED;
};

struct PermStatusCache {
    PermissionOper status;
    std::string paramValue;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ABILITY_ACCESS_CTRL_H