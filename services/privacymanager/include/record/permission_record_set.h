/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef PERMISSION_RECORD_SET_H
#define PERMISSION_RECORD_SET_H

#include <set>
#include "permission_record.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
using IsEqualFunc=bool (ContinuousPermissionRecord::*)(const ContinuousPermissionRecord& record) const;

class PermissionRecordSet {
public:
    static void GetInActiveUniqueRecord(const std::set<ContinuousPermissionRecord>& recordList,
    const std::vector<ContinuousPermissionRecord>& removedList, std::vector<ContinuousPermissionRecord>& retList);
    static void GetUnusedCameraRecords(const std::set<ContinuousPermissionRecord>& recordList,
        const std::vector<ContinuousPermissionRecord>& removedList, std::vector<ContinuousPermissionRecord>& retList);
    static void RemoveByKey(std::set<ContinuousPermissionRecord>& recordList,
        const ContinuousPermissionRecord& record, const IsEqualFunc& isEqualFunc,
        std::vector<ContinuousPermissionRecord>& retList);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_RECORD_SET_H
