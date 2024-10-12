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
 * @file permission_used_result.h
 *
 * @brief Declares structs.
 *
 * @since 8.0
 * @version 8.0
 */

#ifndef PERMISSION_USED_RESPONSE_H
#define PERMISSION_USED_RESPONSE_H

#include <string>
#include <vector>
#include "access_token.h"
#include "active_change_response_info.h"
#include "permission_used_type.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
/**
 * @brief Record used detail struct
 */
struct UsedRecordDetail {
    /**
     * permission active state, for details about the valid values,
     * see the definition of ActiveChangeType in
     * the active_change_response_info.h file.
     */
    int32_t status = 0;
    /**
     * permission lockscreen state, for details about the valid values,
     * see the definition of ActiveChangeType in
     * the active_change_response_info.h file.
     */
    int32_t lockScreenStatus = LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED;
    /** permission active state change timestamp */
    int64_t timestamp = 0L;
    /** permission active state remain times */
    int64_t accessDuration = 0L;
    /** The value of successCount or failCount passed in to addPermissionUsedRecord */
    int32_t count = 0;
    /** permission used type */
    PermissionUsedType type;
};

/**
 * @brief Permission used record struct
 */
struct PermissionUsedRecord {
    /** permission name */
    std::string permissionName;
    /** permission access count */
    int32_t accessCount = 0;
    /** permission reject count */
    int32_t rejectCount = 0;
    /** permission last access timestamp */
    int64_t lastAccessTime = 0L;
    /** permission last reject timestamp */
    int64_t lastRejectTime = 0L;
    /** permission last access remain time */
    int64_t lastAccessDuration = 0L;
    /** UsedRecordDetail list */
    std::vector<UsedRecordDetail> accessRecords;
    /** UsedRecordDetail list */
    std::vector<UsedRecordDetail> rejectRecords;
};

/**
 * @brief Bundle used record struct
 */
struct BundleUsedRecord {
    /** token id */
    AccessTokenID tokenId;
    /** is remote token */
    bool isRemote;
    /** device id */
    std::string deviceId;
    /** bundle name */
    std::string bundleName;
    /** PermissionUsedRecord list */
    std::vector<PermissionUsedRecord> permissionRecords;
};

/**
 * @brief Permission used result struct
 */
struct PermissionUsedResult {
    /** begin timestamp */
    int64_t beginTimeMillis = 0L;
    /** end timestamp */
    int64_t endTimeMillis = 0L;
    /** BundleUsedRecord list */
    std::vector<BundleUsedRecord> bundleRecords;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_USED_RESPONSE_H
