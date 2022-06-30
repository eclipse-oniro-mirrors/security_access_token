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

bool PermissionRecordRepository::AddRecordValues(const std::vector<GenericValues>& recordValues)
{
    if (PermissionUsedRecordDb::GetInstance().Add(PermissionUsedRecordDb::PERMISSION_RECORD, recordValues)
        != PermissionUsedRecordDb::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PERMISSION_RECORD table add fail");
        return false;
    }
    return true;
}

bool PermissionRecordRepository::FindRecordValues(const GenericValues& andConditionValues,
    const GenericValues& orConditionValues, std::vector<GenericValues>& recordValues)
{
    if (PermissionUsedRecordDb::GetInstance().FindByConditions(PermissionUsedRecordDb::PERMISSION_RECORD,
        andConditionValues, orConditionValues, recordValues) != PermissionUsedRecordDb::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PERMISSION_RECORD table find fail");
        return false;
    }
    return true;
}

bool PermissionRecordRepository::RemoveRecordValues(const GenericValues& conditionValues)
{
    if (PermissionUsedRecordDb::GetInstance().Remove(PermissionUsedRecordDb::PERMISSION_RECORD, conditionValues)
        != PermissionUsedRecordDb::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PERMISSION_RECORD table add fail");
        return false;
    }
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS