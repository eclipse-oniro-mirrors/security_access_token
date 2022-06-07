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
#include "sqlite_storage.h"

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
    if (SqliteStorage::GetInstance().FindByConditions(SqliteStorage::PERMISSION_VISITOR, visitorValues,
        nullValues, resultValues) != SqliteStorage::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s PERMISSION_VISITOR table find fail", __func__);
        return false;
    }
    if (!resultValues.empty()) {
        return true;
    }

    insertValues.emplace_back(visitorValues);
    if (SqliteStorage::GetInstance().Add(SqliteStorage::PERMISSION_VISITOR, insertValues) != SqliteStorage::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s PERMISSION_VISITOR table add fail", __func__);
        return false;
    }
    return true;
}

bool PermissionVisitorRepository::FindVisitorValues(
    const GenericValues& andValues, const GenericValues& orValues, std::vector<GenericValues>& visitorValues)
{
    if (SqliteStorage::GetInstance().FindByConditions(SqliteStorage::PERMISSION_VISITOR, andValues,
        orValues, visitorValues) != SqliteStorage::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s PERMISSION_VISITOR table find fail", __func__);
        return false;
    }
    return true;
}

bool PermissionVisitorRepository::RemoveVisitorValues(const GenericValues& conditionValues)
{
    if (SqliteStorage::GetInstance().Remove(SqliteStorage::PERMISSION_VISITOR, conditionValues) != SqliteStorage::SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s PERMISSION_VISITOR table remove fail", __func__);
        return false;
    }
    return true;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS