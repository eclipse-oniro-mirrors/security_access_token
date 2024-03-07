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

#include "accesstoken_log.h"
#include "permission_used_record_db.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PermissionRecordRepository"
};
}

PermissionRecordRepository& PermissionRecordRepository::GetInstance()
{
    static PermissionRecordRepository instance;
    return instance;
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
    if (PermissionUsedRecordDb::GetInstance().Add(type, recordValues) != PermissionUsedRecordDb::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "type %{public}d(0-PERMISSION_RECORD 1-PERMISSION_USED_TYPE) table add fail",
            type);
        return false;
    }
    return true;
}

bool PermissionRecordRepository::FindRecordValues(const std::set<int32_t>& opCodeList, 
    const GenericValues& andConditionValues, std::vector<GenericValues>& recordValues, int32_t databaseQueryCount)
{
    if (PermissionUsedRecordDb::GetInstance().FindByConditions(PermissionUsedRecordDb::PERMISSION_RECORD,
        opCodeList, andConditionValues, recordValues, databaseQueryCount) != PermissionUsedRecordDb::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PERMISSION_RECORD table find fail");
        return false;
    }
    return true;
}

bool PermissionRecordRepository::Remove(const PermissionUsedRecordDb::DataType type,
    const GenericValues& conditionValues)
{
    if (PermissionUsedRecordDb::GetInstance().Remove(type, conditionValues) != PermissionUsedRecordDb::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "type %{public}d(0-PERMISSION_RECORD 1-PERMISSION_USED_TYPE) table remove fail",
            type);
        return false;
    }
    return true;
}

bool PermissionRecordRepository::GetAllRecordValuesByKey(
    const std::string& condition, std::vector<GenericValues>& resultValues)
{
    if (PermissionUsedRecordDb::GetInstance().GetDistinctValue(PermissionUsedRecordDb::PERMISSION_RECORD,
        condition, resultValues) != PermissionUsedRecordDb::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PERMISSION_RECORD table add fail");
        return false;
    }
    return true;
}

void PermissionRecordRepository::CountRecordValues(GenericValues& resultValues)
{
    PermissionUsedRecordDb::GetInstance().Count(PermissionUsedRecordDb::PERMISSION_RECORD, resultValues);
}

bool PermissionRecordRepository::DeleteExpireRecordsValues(const GenericValues& andConditions)
{
    if (PermissionUsedRecordDb::GetInstance().DeleteExpireRecords(PermissionUsedRecordDb::PERMISSION_RECORD,
        andConditions) != PermissionUsedRecordDb::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PERMISSION_RECORD delete fail");
        return false;
    }
    return true;
}

bool PermissionRecordRepository::DeleteExcessiveSizeRecordValues(uint32_t excessiveSize)
{
    if (PermissionUsedRecordDb::GetInstance().DeleteExcessiveRecords(PermissionUsedRecordDb::PERMISSION_RECORD,
        excessiveSize) != PermissionUsedRecordDb::SUCCESS) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "PERMISSION_RECORD delete fail");
            return false;
    }
    return true;
}

bool PermissionRecordRepository::Update(const PermissionUsedRecordDb::DataType type,
    const GenericValues& modifyValue, const GenericValues& conditionValue)
{
    if (PermissionUsedRecordDb::GetInstance().Update(
        type, modifyValue, conditionValue) != PermissionUsedRecordDb::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PERMISSION_USED_TYPE table update fail");
        return false;
    }
    return true;
}

bool PermissionRecordRepository::Query(const PermissionUsedRecordDb::DataType type,
    const GenericValues& conditionValue, std::vector<GenericValues>& results)
{
    if (PermissionUsedRecordDb::GetInstance().Query(type, conditionValue, results) != PermissionUsedRecordDb::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PERMISSION_USED_TYPE table add fail");
        return false;
    }
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS