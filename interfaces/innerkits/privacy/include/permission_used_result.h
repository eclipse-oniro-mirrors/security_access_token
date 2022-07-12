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

#ifndef PERMISSION_USED_RESPONSE_H
#define PERMISSION_USED_RESPONSE_H

#include <string>
#include <vector>
#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct UsedRecordDetail {
    int32_t status = 0;
    int64_t timestamp = 0L;
    int64_t accessDuration = 0L;
};

struct PermissionUsedRecord {
    std::string permissionName;
    int32_t accessCount = 0;
    int32_t rejectCount = 0;
    int64_t lastAccessTime = 0L;
    int64_t lastRejectTime = 0L;
    int64_t lastAccessDuration = 0L;
    std::vector<UsedRecordDetail> accessRecords;
    std::vector<UsedRecordDetail> rejectRecords;
};

struct BundleUsedRecord {
    AccessTokenID tokenId;
    bool isRemote;
    std::string deviceId;
    std::string bundleName;
    std::vector<PermissionUsedRecord> permissionRecords;
};

struct PermissionUsedResult {
    int64_t beginTimeMillis = 0L;
    int64_t endTimeMillis = 0L;
    std::vector<BundleUsedRecord> bundleRecords;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_USED_RESPONSE_H
