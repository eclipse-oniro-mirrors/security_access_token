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

#include <vector>
#include "generic_values.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionRecordRepository final {
public:
    virtual ~PermissionRecordRepository();
    PermissionRecordRepository();

    static PermissionRecordRepository& GetInstance();

    bool AddRecordValues(const std::vector<GenericValues>& recordValues);
    bool FindRecordValues(const GenericValues& andConditionValues,
        const GenericValues& orConditionValues, std::vector<GenericValues>& recordValues);
    bool RemoveRecordValues(const GenericValues& conditionValues);
    bool GetAllRecordValuesByKey(const std::string& condition, std::vector<GenericValues>& resultValues);
    void CountRecordValues(GenericValues& resultValues);
    bool DeleteExpireRecordsValues(const GenericValues& andConditions);
    bool DeleteExcessiveSizeRecordValues(uint32_t excessiveSize);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_RECORD_REPOSITORY_H
