/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "sqlite_storage.h"

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
    if (SqliteStorage::GetInstance().Add(SqliteStorage::PERMISSION_RECORD, recordValues) != SqliteStorage::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s PERMISSION_VISITOR table add fail", __func__);
        return false;
    }
    return true;
}

bool PermissionRecordRepository::FindRecordValues(const GenericValues& andConditionValues,
    const GenericValues& orConditionValues, std::vector<GenericValues>& recordValues)
{
    if (SqliteStorage::GetInstance().FindByConditions(SqliteStorage::PERMISSION_RECORD, andConditionValues,
        orConditionValues, recordValues) != SqliteStorage::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s PERMISSION_VISITOR table find fail", __func__);
        return false;
    }
    return true;
}

bool PermissionRecordRepository::RemoveRecordValues(const GenericValues& conditionValues)
{
    if (SqliteStorage::GetInstance().Remove(SqliteStorage::PERMISSION_RECORD, conditionValues)
        != SqliteStorage::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s PERMISSION_VISITOR table add fail", __func__);
        return false;
    }
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS