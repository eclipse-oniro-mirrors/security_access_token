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

#include "permission_visitor_repository.h"

#include "accesstoken_log.h"
#include "permission_used_record_db.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PermissionVisitorRepository"
};
}

PermissionVisitorRepository& PermissionVisitorRepository::GetInstance()
{
    static PermissionVisitorRepository instance;
    return instance;
}

PermissionVisitorRepository::PermissionVisitorRepository()
{
}

PermissionVisitorRepository::~PermissionVisitorRepository()
{
}

bool PermissionVisitorRepository::AddVisitorValues(const GenericValues& visitorValues)
{
    GenericValues nullValues;
    std::vector<GenericValues> insertValues;
    std::vector<GenericValues> resultValues;
    if (PermissionUsedRecordDb::GetInstance().FindByConditions(PermissionUsedRecordDb::PERMISSION_VISITOR,
        visitorValues, nullValues, resultValues) != PermissionUsedRecordDb::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PERMISSION_VISITOR table find fail");
        return false;
    }
    if (!resultValues.empty()) {
        return true;
    }

    insertValues.emplace_back(visitorValues);
    if (PermissionUsedRecordDb::GetInstance().Add(PermissionUsedRecordDb::PERMISSION_VISITOR, insertValues)
        != PermissionUsedRecordDb::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PERMISSION_VISITOR table add fail");
        return false;
    }
    return true;
}

bool PermissionVisitorRepository::FindVisitorValues(
    const GenericValues& andValues, const GenericValues& orValues, std::vector<GenericValues>& visitorValues)
{
    if (PermissionUsedRecordDb::GetInstance().FindByConditions(PermissionUsedRecordDb::PERMISSION_VISITOR, andValues,
        orValues, visitorValues) != PermissionUsedRecordDb::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PERMISSION_VISITOR table find fail");
        return false;
    }
    return true;
}

bool PermissionVisitorRepository::RemoveVisitorValues(const GenericValues& conditionValues)
{
    if (PermissionUsedRecordDb::GetInstance().Remove(PermissionUsedRecordDb::PERMISSION_VISITOR, conditionValues)
        != PermissionUsedRecordDb::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "PERMISSION_VISITOR table remove fail");
        return false;
    }
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS