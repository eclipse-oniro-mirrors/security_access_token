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

#ifndef PERMISSION_USED_REQUEST_H
#define PERMISSION_USED_REQUEST_H

#include <string>
#include <vector>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef enum PermissionUsageFlagEnum {
    FLAG_PERMISSION_USAGE_SUMMARY = 0,
    FLAG_PERMISSION_USAGE_DETAIL = 1,
} PermissionUsageFlag;

struct PermissionUsedRequest {
    AccessTokenID tokenId = 0;
    bool isRemote = false;
    std::string deviceId;
    std::string bundleName;
    std::vector<std::string> permissionList;
    int64_t beginTimeMillis = 0;
    int64_t endTimeMillis = 0;
    PermissionUsageFlag flag = FLAG_PERMISSION_USAGE_SUMMARY;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_USED_REQUEST_H
