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

#include "permission_record_repository.h"

#include <mutex>
#include "permission_used_record_db.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::recursive_mutex g_instanceMutex;
}

PermissionRecordRepository& PermissionRecordRepository::GetInstance()
{
    static PermissionRecordRepository* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new PermissionRecordRepository();
        }
    }
    return *instance;
}

PermissionRecordRepository::PermissionRecordRepository()
{
}

PermissionRecordRepository::~PermissionRecordRepository()
{
}

bool PermissionRecordRepository::Add(const PermissionUsedRecordDb::DataType type,
    const std::vector<GenericValues>& recordValues)
{
    int32_t res = PermissionUsedRecordDb::GetInstance().Add(type, recordValues);
    return res == PermissionUsedRecordDb::SUCCESS;
}

bool PermissionRecordRepository::FindRecordValues(const std::set<int32_t>& opCodeList,
    const GenericValues& andConditionValues, std::vector<GenericValues>& recordValues, int32_t databaseQueryCount)
{
    int32_t res = PermissionUsedRecordDb::GetInstance().FindByConditions(PermissionUsedRecordDb::PERMISSION_RECORD,
        opCodeList, andConditionValues, recordValues, databaseQueryCount);
    return res == PermissionUsedRecordDb::SUCCESS;
}

bool PermissionRecordRepository::Remove(const PermissionUsedRecordDb::DataType type,
    const GenericValues& conditionValues)
{
    int32_t res = PermissionUsedRecordDb::GetInstance().Remove(type, conditionValues);
    return res == PermissionUsedRecordDb::SUCCESS;
}

int32_t PermissionRecordRepository::CountRecordValues()
{
    return PermissionUsedRecordDb::GetInstance().Count(PermissionUsedRecordDb::PERMISSION_RECORD);
}

bool PermissionRecordRepository::DeleteExpireRecordsValues(const GenericValues& andConditions)
{
    int32_t res = PermissionUsedRecordDb::GetInstance().DeleteExpireRecords(PermissionUsedRecordDb::PERMISSION_RECORD,
        andConditions);
    return res == PermissionUsedRecordDb::SUCCESS;
}

bool PermissionRecordRepository::DeleteExcessiveSizeRecordValues(uint32_t excessiveSize)
{
    int32_t res = PermissionUsedRecordDb::GetInstance().DeleteExcessiveRecords(
        PermissionUsedRecordDb::PERMISSION_RECORD, excessiveSize);
    if (res != PermissionUsedRecordDb::SUCCESS) {
            return false;
    }
    return true;
}

bool PermissionRecordRepository::Update(const PermissionUsedRecordDb::DataType type,
    const GenericValues& modifyValue, const GenericValues& conditionValue)
{
    int32_t res = PermissionUsedRecordDb::GetInstance().Update(type, modifyValue, conditionValue);
    return res == PermissionUsedRecordDb::SUCCESS;
}

bool PermissionRecordRepository::Query(const PermissionUsedRecordDb::DataType type,
    const GenericValues& conditionValue, std::vector<GenericValues>& results)
{
    int32_t res = PermissionUsedRecordDb::GetInstance().Query(type, conditionValue, results);
    return res == PermissionUsedRecordDb::SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS