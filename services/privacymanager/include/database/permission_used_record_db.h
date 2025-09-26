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

#ifndef PERMISSION_USED_RECORD_DB_H
#define PERMISSION_USED_RECORD_DB_H

#include <set>
#include <unordered_set>

#include "generic_values.h"
#include "permission_record.h"

#include "nocopyable.h"
#include "rwlock.h"
#include "sqlite_helper.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct SqliteTable {
public:
    std::string tableName_;
    std::vector<std::string> tableColumnNames_;
};
class PermissionUsedRecordDb : public SqliteHelper {
public:
    enum DataType {
        PERMISSION_RECORD,
        PERMISSION_USED_TYPE,
        PERMISSION_USED_RECORD_TOGGLE_STATUS,
        PERMISSION_DISABLE_POLICY,
    };
    enum ExecuteResult { FAILURE = -1, SUCCESS };
    static PermissionUsedRecordDb& GetInstance();

    ~PermissionUsedRecordDb() override;

    int32_t Add(DataType type, const std::vector<GenericValues>& values);
    int32_t Remove(DataType type, const GenericValues& conditions);
    int32_t FindByConditions(DataType type, const std::set<int32_t>& opCodeList, const GenericValues& andConditions,
        std::vector<GenericValues>& results, int32_t databaseQueryCount);
    int32_t Count(DataType type);
    int32_t DeleteExpireRecords(DataType type, const GenericValues& andConditions);
    int32_t DeleteHistoryRecordsInTables(std::vector<DataType> dateTypes,
        const std::unordered_set<AccessTokenID>& tokenIDList);
    int32_t DeleteExcessiveRecords(DataType type, uint32_t excessiveSize);
    int32_t Update(DataType type, const GenericValues& modifyValue, const GenericValues& conditionValue);
    int32_t Query(DataType type, const GenericValues& conditionValue, std::vector<GenericValues>& results);

    void OnCreate() override;
    void OnUpdate(int32_t version) override;

private:
    void InitPermRecordTableInfo(SqliteTable& permissionRecordTable);
    void InitPermUsedTypeTableInfo(SqliteTable& permissionRecordTable);
    void InitPermUsedRecordToggleStatusTableInfo(SqliteTable& permissionRecordTable);
    void InitPermDisablePolicyTableInfo(SqliteTable& permissionRecordTable);

    PermissionUsedRecordDb();
    DISALLOW_COPY_AND_MOVE(PermissionUsedRecordDb);

    std::map<DataType, SqliteTable> dataTypeToSqlTable_;
    OHOS::Utils::RWLock rwLock_;

    int32_t CreatePermissionRecordTable() const;
    int32_t CreatePermissionUsedTypeTable() const;
    int32_t CreatePermissionUsedRecordToggleStatusTable() const;
    int32_t InsertLockScreenStatusColumn() const;
    int32_t InsertPermissionUsedTypeColumn() const;
    int32_t UpdatePermissionRecordTablePrimaryKey() const;
    int32_t CreatePermissionDisablePolicyTable() const;

    std::string CreateDeleteHistoryRecordsPrepareSqlCmd(DataType type,
        const std::unordered_set<AccessTokenID>& tokenIDList) const;
    std::string CreateInsertPrepareSqlCmd(DataType type) const;
    std::string CreateDeletePrepareSqlCmd(
        DataType type, const std::vector<std::string>& columnNames = std::vector<std::string>()) const;
    std::string CreateSelectByConditionPrepareSqlCmd(const int32_t tokenId, DataType type,
        const std::set<int32_t>& opCodeList, const std::vector<std::string>& andColumns,
        int32_t databaseQueryCount) const;
    std::string CreateUpdatePrepareSqlCmd(DataType type, const std::vector<std::string>& modifyColumns,
        const std::vector<std::string>& conditionColumns) const;
    std::string CreateCountPrepareSqlCmd(DataType type) const;
    std::string CreateDeleteExpireRecordsPrepareSqlCmd(DataType type,
        const std::vector<std::string>& andColumns) const;
    std::string CreateDeleteExcessiveRecordsPrepareSqlCmd(DataType type, uint32_t excessiveSize) const;
    std::string CreateQueryPrepareSqlCmd(DataType type, const std::vector<std::string>& conditionColumns) const;

private:
    inline static constexpr const char* PERMISSION_RECORD_TABLE = "permission_record_table";
    inline static constexpr const char* PERMISSION_USED_TYPE_TABLE = "permission_used_type_table";
    inline static constexpr const char* PERMISSION_USED_RECORD_TOGGLE_STATUS_TABLE =
        "permission_used_record_toggle_status_table";
    inline static constexpr const char* PERMISSION_DISABLE_POLICY_TABLE = "permission_disable_policy_table";
    inline static constexpr const char* DATABASE_NAME = "permission_used_record.db";
    inline static constexpr const char* DATABASE_PATH = "/data/service/el1/public/access_token/";
    static const int32_t DATABASE_VERSION = 6;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // PERMISSION_USED_RECORD_DB_H
