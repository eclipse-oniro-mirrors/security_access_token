/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef REMOTE_PERMISSION_USED_RECORD_DB_H
#define REMOTE_PERMISSION_USED_RECORD_DB_H

#include <set>
#include <shared_mutex>
#include <unordered_set>

#include "generic_values.h"
#include "permission_record.h"

#include "nocopyable.h"
#include "sqlite_helper.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class RemotePermissionUsedRecordDb : public SqliteHelper {
public:
    enum ExecuteResult { FAILURE = -1, SUCCESS };
    
    RemotePermissionUsedRecordDb(const std::string& dbPath, const std::string& dbName);
    ~RemotePermissionUsedRecordDb() override;

    int32_t Add(const std::vector<GenericValues>& values);
    int32_t Remove(const GenericValues& conditions);
    int32_t FindByConditions(const std::set<int32_t>& opCodeList, const GenericValues& andConditions,
        std::vector<GenericValues>& results, int32_t databaseQueryCount);
    int32_t Count();
    int32_t DeleteExpireRecords(const GenericValues& andConditions);
    int32_t DeleteExcessiveRecords(uint32_t excessiveSize);
    int32_t Update(const GenericValues& modifyValue, const GenericValues& conditionValue);

    void OnCreate() override;
    void OnUpdate(int32_t version) override;

private:
    std::shared_mutex rwLock_;

    int32_t CreateRemotePermissionRecordTable() const;

    std::string CreateInsertPrepareSqlCmd() const;
    std::string CreateDeletePrepareSqlCmd(const std::vector<std::string>& columnNames) const;
    std::string CreateSelectByConditionPrepareSqlCmd(const std::set<int32_t>& opCodeList,
        const std::vector<std::string>& andColumns, int32_t databaseQueryCount) const;
    std::string CreateUpdatePrepareSqlCmd(const std::vector<std::string>& modifyColumns,
        const std::vector<std::string>& conditionColumns) const;
    std::string CreateCountPrepareSqlCmd() const;
    std::string CreateDeleteExpireRecordsPrepareSqlCmd(const std::vector<std::string>& andColumns) const;
    std::string CreateDeleteExcessiveRecordsPrepareSqlCmd(uint32_t excessiveSize) const;

    static const int32_t DATABASE_VERSION = 1;
};

class RemotePermUsedRecordDbManager {
public:
    static RemotePermUsedRecordDbManager& GetInstance();

    int32_t Add(const int32_t userId, const std::vector<GenericValues>& values);
    int32_t Remove(const int32_t userId, const GenericValues& conditions);
    int32_t FindByConditions(const int32_t userId, const std::set<int32_t>& opCodeList,
        const GenericValues& andConditions, std::vector<GenericValues>& results, int32_t databaseQueryCount);
    int32_t Count(const int32_t userId);
    int32_t DeleteExpireRecords(const int32_t userId, const GenericValues& andConditions);
    int32_t DeleteExcessiveRecords(const int32_t userId, uint32_t excessiveSize);
    int32_t Update(const int32_t userId, const GenericValues& modifyValue, const GenericValues& conditionValue);

private:
    RemotePermUsedRecordDbManager();
    DISALLOW_COPY_AND_MOVE(RemotePermUsedRecordDbManager);

    std::shared_ptr<RemotePermissionUsedRecordDb> GetDatabase(const int32_t userId, const bool needCreate);

    std::mutex dbMutex_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // REMOTE_PERMISSION_USED_RECORD_DB_H
