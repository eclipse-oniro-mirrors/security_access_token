/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

/**
 * @addtogroup Privacy
 * @{
 *
 * @brief Provides sensitive data access management.
 *
 * @since 8.0
 * @version 8.0
 */

/**
 * @file permission_used_request.h
 *
 * @brief Declares enum PermissionUsageFlagEnum and struct PermissionUsedRequest.
 *
 * @since 8.0
 * @version 8.0
 */

#ifndef PERMISSION_USED_REQUEST_H
#define PERMISSION_USED_REQUEST_H

#include <string>
#include <vector>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief permission usage flag values
 */
typedef enum PermissionUsageFlagEnum {
    /** permission usage for summary */
    FLAG_PERMISSION_USAGE_SUMMARY = 0,
    /** permission usage for detail */
    FLAG_PERMISSION_USAGE_DETAIL = 1,
    /** permission usage for screen locked summary */
    FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_LOCKED = 2,
    /** permission usage for screen unlocked summary */
    FLAG_PERMISSION_USAGE_SUMMARY_IN_SCREEN_UNLOCKED = 3,
    /** permission usage for app in background summary */
    FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_BACKGROUND = 4,
    /** permission usage for app in foreground summary */
    FLAG_PERMISSION_USAGE_SUMMARY_IN_APP_FOREGROUND = 5,
} PermissionUsageFlag;

/**
 * @brief permission usage flag values
 */
struct PermissionUsedRequest {
    AccessTokenID tokenId = 0;
    /** indicats whether the tokenID is remote tokenID */
    bool isRemote = false;
    std::string deviceId = "";
    std::string bundleName = "";
    /** permission name list */
    std::vector<std::string> permissionList;
    int64_t beginTimeMillis = 0L;
    int64_t endTimeMillis = 0L;
    PermissionUsageFlag flag = FLAG_PERMISSION_USAGE_SUMMARY;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_USED_REQUEST_H
