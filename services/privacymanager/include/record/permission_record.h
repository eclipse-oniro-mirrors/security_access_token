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

#ifndef PERMISSION_RECORD_H
#define PERMISSION_RECORD_H

#include <set>
#include "active_change_response_info.h"
#include "generic_values.h"
#include "permission_used_type.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct PermissionRecord {
    uint32_t tokenId = 0;
    int32_t opCode = 0;
    int32_t status = 0;
    int64_t timestamp = 0L;
    int64_t accessDuration = 0L;
    PermissionUsedType type = PermissionUsedType::NORMAL_TYPE;
    int32_t accessCount = 0;
    int32_t rejectCount = 0;
    int32_t lockScreenStatus = LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED;

    PermissionRecord() = default;

    static void TranslationIntoGenericValues(const PermissionRecord& record, GenericValues& values);
    static void TranslationIntoPermissionRecord(const GenericValues& values, PermissionRecord& record);
};

struct ContinusPermissionRecord {
    uint32_t tokenId = 0;
    int32_t opCode = 0;
    int32_t status = 0;
    int32_t pid = 0;
    int32_t callerPid = 0;
    PermissionUsedType usedType = NORMAL_TYPE;
    uint32_t callertokenId = 0;

    bool operator < (const ContinusPermissionRecord& other) const;

    uint64_t GetTokenIdAndPermCode() const;
    uint64_t GetTokenIdAndPid() const;
    bool IsEqualRecord(const ContinusPermissionRecord& record) const;
    bool IsEqualTokenId(const ContinusPermissionRecord& record) const;
    bool IsEqualPermCode(const ContinusPermissionRecord& record) const;
    bool IsEqualCallerPid(const ContinusPermissionRecord& record) const;
    bool IsEqualPid(const ContinusPermissionRecord& record) const;
    bool IsEqualTokenIdAndPid(const ContinusPermissionRecord& record) const;
    static bool IsPidValid(int32_t pid);
};

struct PermissionRecordCache {
    PermissionRecord record;
    bool needUpdateToDb = false;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_RECORD_H
