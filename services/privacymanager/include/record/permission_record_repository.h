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

#ifndef PERMISSION_RECORD_REPOSITORY_H
#define PERMISSION_RECORD_REPOSITORY_H

#include <set>
#include <vector>
#include "generic_values.h"
#include "permission_used_record_db.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionRecordRepository final {
public:
    virtual ~PermissionRecordRepository();
    PermissionRecordRepository();

    static PermissionRecordRepository& GetInstance();

    bool Add(const PermissionUsedRecordDb::DataType type, const std::vector<GenericValues>& recordValues);
    bool FindRecordValues(const std::set<int32_t>& opCodeList, const GenericValues& andConditionValues,
        std::vector<GenericValues>& recordValues, int32_t databaseQueryCount);
    bool Remove(const PermissionUsedRecordDb::DataType type, const GenericValues& conditionValues);
    bool GetAllRecordValuesByKey(const std::string& condition, std::vector<GenericValues>& resultValues);
    void CountRecordValues(GenericValues& resultValues);
    bool DeleteExpireRecordsValues(const GenericValues& andConditions);
    bool DeleteExcessiveSizeRecordValues(uint32_t excessiveSize);
    bool Update(const PermissionUsedRecordDb::DataType type, const GenericValues& modifyValue,
        const GenericValues& conditionValue);
    bool Query(const PermissionUsedRecordDb::DataType type, const GenericValues& conditionValue,
        std::vector<GenericValues>& results);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_RECORD_REPOSITORY_H
