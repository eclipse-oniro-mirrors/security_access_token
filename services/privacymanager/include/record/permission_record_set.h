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
using IsEqualFunc=bool (ContinusPermissionRecord::*)(const ContinusPermissionRecord& record) const;

class PermissionRecordSet {
public:
    static void GetInActiveUniqueRecord(const std::set<ContinusPermissionRecord>& recordList,
    const std::vector<ContinusPermissionRecord>& removedList, std::vector<ContinusPermissionRecord>& retList);
    static void GetUnusedCameraRecords(const std::set<ContinusPermissionRecord>& recordList,
        const std::vector<ContinusPermissionRecord>& removedList, std::vector<ContinusPermissionRecord>& retList);
    static void RemoveByKey(std::set<ContinusPermissionRecord>& recordList,
        const ContinusPermissionRecord& record, const IsEqualFunc& isEqualFunc,
        std::vector<ContinusPermissionRecord>& retList);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_RECORD_SET_H
