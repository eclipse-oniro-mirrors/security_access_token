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

#include "permission_used_record_db.h"

#include "accesstoken_log.h"
#include "field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PrivacySqliteStorage"
};
}

SqliteStorage& SqliteStorage::GetInstance()
{
    static SqliteStorage instance;
    return instance;
}

SqliteStorage::~SqliteStorage()
{
    Close();
}

void SqliteStorage::OnCreate()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Entry");
    CreatePermissionVisitorTable();
    CreatePermissionRecordTable();
}

void SqliteStorage::OnUpdate()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Entry");
}

SqliteStorage::SqliteStorage() : SqliteHelper(DATABASE_NAME, DATABASE_PATH, DATABASE_VERSION)
{
    SqliteTable permissionVisorTable;
    permissionVisorTable.tableName_ = PERMISSION_VISITOR_TABLE;
    permissionVisorTable.tableColumnNames_ = {
        FIELD_ID,
        FIELD_TOKEN_ID,
        FIELD_IS_REMOTE_DEVICE,
        FIELD_DEVICE_ID,
        FIELD_USER_ID,
        FIELD_BUNDLE_NAME
    };

    SqliteTable permissionRecordTable;
    permissionRecordTable.tableName_ = PERMISSION_RECORD_TABLE;
    permissionRecordTable.tableColumnNames_ = {
        FIELD_VISITOR_ID,
        FIELD_OP_CODE,
        FIELD_STATUS,
        FIELD_TIMESTAMP,
        FIELD_ACCESS_DURATION,
        FIELD_ACCESS_COUNT,
        FIELD_REJECT_COUNT
    };

    dataTypeToSqlTable_ = {
        {PERMISSION_VISITOR, permissionVisorTable},
        {PERMISSION_RECORD, permissionRecordTable},
    };
    Open();
}

int32_t SqliteStorage::Add(const DataType type, const std::vector<GenericValues>& values)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::string prepareSql = CreateInsertPrepareSqlCmd(type);
    auto statement = Prepare(prepareSql);
    BeginTransaction();
    bool isExecuteSuccessfully = true;
    for (auto value : values) {
        std::vector<std::string> columnNames = value.GetAllKeys();
        for (auto columnName : columnNames) {
            statement.Bind(columnName, value.Get(columnName));
        }
        int32_t ret = statement.Step();
        if (ret != Statement::State::DONE) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "failed, errorMsg: %{public}s", SpitError().c_str());
            isExecuteSuccessfully = false;
        }
        statement.Reset();
    }
    if (!isExecuteSuccessfully) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "rollback transaction.");
        RollbackTransaction();
        return FAILURE;
    }
    ACCESSTOKEN_LOG_DEBUG(LABEL, "commit transaction.");
    CommitTransaction();
    return SUCCESS;
}

int32_t SqliteStorage::Remove(const DataType type, const GenericValues& conditions)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::vector<std::string> columnNames = conditions.GetAllKeys();
    std::string prepareSql = CreateDeletePrepareSqlCmd(type, columnNames);
    auto statement = Prepare(prepareSql);
    for (auto columnName : columnNames) {
        statement.Bind(columnName, conditions.Get(columnName));
    }
    int32_t ret = statement.Step();
    return (ret == Statement::State::DONE) ? SUCCESS : FAILURE;
}

int32_t SqliteStorage::Modify(const DataType type, const GenericValues& modifyValues, const GenericValues& conditions)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::vector<std::string> modifyColumns = modifyValues.GetAllKeys();
    std::vector<std::string> conditionColumns = conditions.GetAllKeys();
    std::string prepareSql = CreateUpdatePrepareSqlCmd(type, modifyColumns, conditionColumns);
    auto statement = Prepare(prepareSql);
    for (auto columnName : modifyColumns) {
        statement.Bind(columnName, modifyValues.Get(columnName));
    }
    for (auto columnName : conditionColumns) {
        statement.Bind(columnName, conditions.Get(columnName));
    }
    int32_t ret = statement.Step();
    return (ret == Statement::State::DONE) ? SUCCESS : FAILURE;
}

int32_t SqliteStorage::Find(const DataType type, std::vector<GenericValues>& results)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::string prepareSql = CreateSelectPrepareSqlCmd(type);
    auto statement = Prepare(prepareSql);
    while (statement.Step() == Statement::State::ROW) {
        int32_t columnCount = statement.GetColumnCount();
        GenericValues value;
        for (int32_t i = 0; i < columnCount; i++) {
            if (statement.GetColumnName(i) == FIELD_TIMESTAMP || statement.GetColumnName(i) == FIELD_ACCESS_DURATION) {
                value.Put(statement.GetColumnName(i), statement.GetValue(i, true));
            } else {
                value.Put(statement.GetColumnName(i), statement.GetValue(i, false));
            }
        }
        results.emplace_back(value);
    }
    return SUCCESS;
}

int32_t SqliteStorage::FindByConditions(const DataType type, const GenericValues& andConditions,
    const GenericValues& orConditions, std::vector<GenericValues>& results)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::vector<std::string> andColumns = andConditions.GetAllKeys();
    std::vector<std::string> orColumns = orConditions.GetAllKeys();
    std::string prepareSql = CreateSelectByConditionPrepareSqlCmd(type, andColumns, orColumns);
    auto statement = Prepare(prepareSql);

    for (auto columnName : andColumns) {
        statement.Bind(columnName, andConditions.Get(columnName));
    }
    for (auto columnName : orColumns) {
        statement.Bind(columnName, orConditions.Get(columnName));
    }

    while (statement.Step() == Statement::State::ROW) {
        int32_t columnCount = statement.GetColumnCount();
        GenericValues value;
        for (int32_t i = 0; i < columnCount; i++) {
            if (statement.GetColumnName(i) == FIELD_TIMESTAMP || statement.GetColumnName(i) == FIELD_ACCESS_DURATION) {
                value.Put(statement.GetColumnName(i), statement.GetValue(i, true));
            } else {
                value.Put(statement.GetColumnName(i), statement.GetValue(i, false));
            }
        }
        results.emplace_back(value);
    }
    return SUCCESS;
}

int32_t SqliteStorage::RefreshAll(const DataType type, const std::vector<GenericValues>& values)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::string deleteSql = CreateDeletePrepareSqlCmd(type);
    std::string insertSql = CreateInsertPrepareSqlCmd(type);
    auto deleteStatement = Prepare(deleteSql);
    auto insertStatement = Prepare(insertSql);
    BeginTransaction();
    bool canCommit = deleteStatement.Step() == Statement::State::DONE;
    for (auto value : values) {
        std::vector<std::string> columnNames = value.GetAllKeys();
        for (auto columnName : columnNames) {
            insertStatement.Bind(columnName, value.Get(columnName));
        }
        int32_t ret = insertStatement.Step();
        if (ret != Statement::State::DONE) {
            ACCESSTOKEN_LOG_ERROR(
                LABEL, "insert failed, errorMsg: %{public}s", SpitError().c_str());
            canCommit = false;
        }
        insertStatement.Reset();
    }
    if (!canCommit) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "rollback transaction.");
        RollbackTransaction();
        return FAILURE;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "commit transaction.");
    CommitTransaction();
    return SUCCESS;
}

std::string SqliteStorage::CreateInsertPrepareSqlCmd(const DataType type) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "insert into " + it->second.tableName_ + " values(";
    int32_t i = 1;
    for (const auto& columnName : it->second.tableColumnNames_) {
        sql.append(":" + columnName);
        if (i < (int32_t) it->second.tableColumnNames_.size()) {
            sql.append(",");
        }
        i += 1;
    }
    sql.append(")");
    return sql;
}

std::string SqliteStorage::CreateDeletePrepareSqlCmd(
    const DataType type, const std::vector<std::string>& columnNames) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "delete from " + it->second.tableName_ + " where 1 = 1";
    for (auto columnName : columnNames) {
        sql.append(" and ");
        sql.append(columnName + "=:" + columnName);
    }
    return sql;
}

std::string SqliteStorage::CreateUpdatePrepareSqlCmd(const DataType type, const std::vector<std::string>& modifyColumns,
    const std::vector<std::string>& conditionColumns) const
{
    if (modifyColumns.empty()) {
        return std::string();
    }

    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }

    std::string sql = "update " + it->second.tableName_ + " set ";
    int32_t i = 1;
    for (const auto& columnName : modifyColumns) {
        sql.append(columnName + "=:" + columnName);
        if (i < (int32_t) modifyColumns.size()) {
            sql.append(",");
        }
        i += 1;
    }

    if (!conditionColumns.empty()) {
        sql.append(" where 1 = 1");
        for (const auto& columnName : conditionColumns) {
            sql.append(" and ");
            sql.append(columnName + "=:" + columnName);
        }
    }
    return sql;
}

std::string SqliteStorage::CreateSelectPrepareSqlCmd(const DataType type) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "select * from " + it->second.tableName_;
    return sql;
}

std::string SqliteStorage::CreateSelectByConditionPrepareSqlCmd(const DataType type,
    const std::vector<std::string>& andColumns, const std::vector<std::string>& orColumns) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }

    std::string sql = "select * from " + it->second.tableName_ + " where 1 = 1";
    for (const auto& andColName : andColumns) {
        if (andColName == FIELD_TIMESTAMP_BEGIN) {
            sql.append(" and ");
            sql.append(FIELD_TIMESTAMP + " >=:" + andColName);
        } else if (andColName == FIELD_TIMESTAMP_END) {
            sql.append(" and ");
            sql.append(FIELD_TIMESTAMP + " <=:" + andColName);
        } else {
            sql.append(" and ");
            sql.append(andColName + "=:" + andColName);
        }
    }
    if (orColumns.size() > 0) {
        sql.append(" and (");
        for (const auto& orColName : orColumns) {
            if (orColName.find(FIELD_OP_CODE) != std::string::npos) {
                sql.append(FIELD_OP_CODE  + " =:" + orColName);
                sql.append(" or ");
            }
        }
        sql.append("0)");
    }
    return sql;
}

int32_t SqliteStorage::CreatePermissionVisitorTable() const
{
    auto it = dataTypeToSqlTable_.find(DataType::PERMISSION_VISITOR);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }
    std::string sql = "create table if not exists ";
    sql.append(it->second.tableName_ + " (")
        .append(FIELD_ID + " integer PRIMARY KEY autoincrement not null,")
        .append(FIELD_TOKEN_ID + " integer not null,")
        .append(FIELD_IS_REMOTE_DEVICE + " integer not null,")
        .append(FIELD_DEVICE_ID + " text not null,")
        .append(FIELD_USER_ID + " integer not null,")
        .append(FIELD_BUNDLE_NAME + " text not null")
        .append(")");
    return ExecuteSql(sql);
}

int32_t SqliteStorage::CreatePermissionRecordTable() const
{
    auto it = dataTypeToSqlTable_.find(DataType::PERMISSION_RECORD);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }
    std::string sql = "create table if not exists ";
    sql.append(it->second.tableName_ + " (")
        .append(FIELD_VISITOR_ID + " integer not null,")
        .append(FIELD_OP_CODE + " integer not null,")
        .append(FIELD_STATUS + " integer not null,")
        .append(FIELD_TIMESTAMP + " integer not null,")
        .append(FIELD_ACCESS_DURATION + " integer not null,")
        .append(FIELD_ACCESS_COUNT + " integer not null,")
        .append(FIELD_REJECT_COUNT + " integer not null,")
        .append("primary key(" + FIELD_VISITOR_ID)
        .append("," + FIELD_OP_CODE)
        .append("," + FIELD_STATUS)
        .append("," + FIELD_TIMESTAMP)
        .append("))");
    return ExecuteSql(sql);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
