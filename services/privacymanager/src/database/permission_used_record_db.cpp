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

#include "permission_used_record_db.h"

#include "accesstoken_log.h"
#include "constant.h"
#include "privacy_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_PRIVACY, "PermissionUsedRecordDb"
};
static const std::string FIELD_COUNT_NUMBER = "count";
static const std::string INTEGER_STR = " integer not null,";

}

PermissionUsedRecordDb& PermissionUsedRecordDb::GetInstance()
{
    static PermissionUsedRecordDb instance;
    return instance;
}

PermissionUsedRecordDb::~PermissionUsedRecordDb()
{
    Close();
}

void PermissionUsedRecordDb::OnCreate()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Entry");
    CreatePermissionRecordTable();
}

void PermissionUsedRecordDb::OnUpdate()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "Entry");
}

PermissionUsedRecordDb::PermissionUsedRecordDb() : SqliteHelper(DATABASE_NAME, DATABASE_PATH, DATABASE_VERSION)
{
    SqliteTable permissionRecordTable;
    permissionRecordTable.tableName_ = PERMISSION_RECORD_TABLE;
    permissionRecordTable.tableColumnNames_ = {
        PrivacyFiledConst::FIELD_TOKEN_ID,
        PrivacyFiledConst::FIELD_OP_CODE,
        PrivacyFiledConst::FIELD_STATUS,
        PrivacyFiledConst::FIELD_TIMESTAMP,
        PrivacyFiledConst::FIELD_ACCESS_DURATION,
        PrivacyFiledConst::FIELD_ACCESS_COUNT,
        PrivacyFiledConst::FIELD_REJECT_COUNT
    };

    dataTypeToSqlTable_ = {
        {PERMISSION_RECORD, permissionRecordTable},
    };
    Open();
}

int32_t PermissionUsedRecordDb::Add(DataType type, const std::vector<GenericValues>& values)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::string prepareSql = CreateInsertPrepareSqlCmd(type);
    auto statement = Prepare(prepareSql);
    BeginTransaction();
    bool isExecuteSuccessfully = true;
    for (const auto& value : values) {
        std::vector<std::string> columnNames = value.GetAllKeys();
        for (const auto& columnName : columnNames) {
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

int32_t PermissionUsedRecordDb::Remove(DataType type, const GenericValues& conditions)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::vector<std::string> columnNames = conditions.GetAllKeys();
    std::string prepareSql = CreateDeletePrepareSqlCmd(type, columnNames);
    auto statement = Prepare(prepareSql);
    for (const auto& columnName : columnNames) {
        statement.Bind(columnName, conditions.Get(columnName));
    }
    int32_t ret = statement.Step();
    return (ret == Statement::State::DONE) ? SUCCESS : FAILURE;
}

int32_t PermissionUsedRecordDb::Modify(
    DataType type, const GenericValues& modifyValues, const GenericValues& conditions)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::vector<std::string> modifyColumns = modifyValues.GetAllKeys();
    std::vector<std::string> conditionColumns = conditions.GetAllKeys();
    std::string prepareSql = CreateUpdatePrepareSqlCmd(type, modifyColumns, conditionColumns);
    auto statement = Prepare(prepareSql);
    for (const auto& columnName : modifyColumns) {
        statement.Bind(columnName, modifyValues.Get(columnName));
    }
    for (const auto& columnName : conditionColumns) {
        statement.Bind(columnName, conditions.Get(columnName));
    }
    int32_t ret = statement.Step();
    return (ret == Statement::State::DONE) ? SUCCESS : FAILURE;
}

int32_t PermissionUsedRecordDb::FindByConditions(DataType type, const GenericValues& andConditions,
    const GenericValues& orConditions, std::vector<GenericValues>& results)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::vector<std::string> andColumns = andConditions.GetAllKeys();
    std::vector<std::string> orColumns = orConditions.GetAllKeys();
    std::string prepareSql = CreateSelectByConditionPrepareSqlCmd(type, andColumns, orColumns);
    auto statement = Prepare(prepareSql);

    for (const auto& columnName : andColumns) {
        statement.Bind(columnName, andConditions.Get(columnName));
    }
    for (const auto& columnName : orColumns) {
        statement.Bind(columnName, orConditions.Get(columnName));
    }

    while (statement.Step() == Statement::State::ROW) {
        int32_t columnCount = statement.GetColumnCount();
        GenericValues value;
        for (int32_t i = 0; i < columnCount; i++) {
            if ((statement.GetColumnName(i) == PrivacyFiledConst::FIELD_TIMESTAMP) ||
                (statement.GetColumnName(i) == PrivacyFiledConst::FIELD_ACCESS_DURATION)) {
                value.Put(statement.GetColumnName(i), statement.GetValue(i, true));
            } else {
                value.Put(statement.GetColumnName(i), statement.GetValue(i, false));
            }
        }
        results.emplace_back(value);
    }
    return SUCCESS;
}

int32_t PermissionUsedRecordDb::GetDistinctValue(DataType type,
    const std::string& condition, std::vector<GenericValues>& results)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::string getDistinctValueSql = CreateGetDistinctValue(type, condition);
    auto statement = Prepare(getDistinctValueSql);
    while (statement.Step() == Statement::State::ROW) {
        int32_t columnCount = statement.GetColumnCount();
        GenericValues value;
        for (int32_t i = 0; i < columnCount; i++) {
            if (statement.GetColumnName(i) == PrivacyFiledConst::FIELD_TOKEN_ID) {
                value.Put(statement.GetColumnName(i), statement.GetValue(i, false));
            } else if (statement.GetColumnName(i) == PrivacyFiledConst::FIELD_DEVICE_ID) {
                value.Put(statement.GetColumnName(i), statement.GetColumnString(i));
            }
        }
        results.emplace_back(value);
    }
    return SUCCESS;
}

void PermissionUsedRecordDb::Count(DataType type, GenericValues& result)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::string countSql = CreateCountPrepareSqlCmd(type);
    auto countStatement = Prepare(countSql);
    if (countStatement.Step() == Statement::State::ROW) {
        int32_t column = 0;
        result.Put(FIELD_COUNT_NUMBER, countStatement.GetValue(column, true));
    }
}

int32_t PermissionUsedRecordDb::DeleteExpireRecords(DataType type,
    const GenericValues& andConditions)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::vector<std::string> andColumns = andConditions.GetAllKeys();
    if (!andColumns.empty()) {
        std::string deleteExpireSql = CreateDeleteExpireRecordsPrepareSqlCmd(type, andColumns);
        auto deleteExpireStatement = Prepare(deleteExpireSql);
        for (const auto& columnName : andColumns) {
            deleteExpireStatement.Bind(columnName, andConditions.Get(columnName));
        }
        if (deleteExpireStatement.Step() != Statement::State::DONE) {
            return FAILURE;
        }
    }
    return SUCCESS;
}

int32_t PermissionUsedRecordDb::DeleteExcessiveRecords(DataType type, uint32_t excessiveSize)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::string deleteExcessiveSql = CreateDeleteExcessiveRecordsPrepareSqlCmd(type, excessiveSize);
    auto deleteExcessiveStatement = Prepare(deleteExcessiveSql);
    if (deleteExcessiveStatement.Step() != Statement::State::DONE) {
        return FAILURE;
    }
    return SUCCESS;
}

std::string PermissionUsedRecordDb::CreateInsertPrepareSqlCmd(DataType type) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "insert into " + it->second.tableName_ + " values(";
    int32_t i = 1;
    for (const auto& columnName : it->second.tableColumnNames_) {
        sql.append(":" + columnName);
        if (i < static_cast<int32_t>(it->second.tableColumnNames_.size())) {
            sql.append(",");
        }
        i += 1;
    }
    sql.append(")");
    return sql;
}

std::string PermissionUsedRecordDb::CreateDeletePrepareSqlCmd(
    DataType type, const std::vector<std::string>& columnNames) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "delete from " + it->second.tableName_ + " where 1 = 1";
    for (const auto& columnName : columnNames) {
        sql.append(" and ");
        sql.append(columnName + "=:" + columnName);
    }
    return sql;
}

std::string PermissionUsedRecordDb::CreateUpdatePrepareSqlCmd(DataType type,
    const std::vector<std::string>& modifyColumns, const std::vector<std::string>& conditionColumns) const
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
        if (i < static_cast<int32_t>(modifyColumns.size())) {
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

std::string PermissionUsedRecordDb::CreateSelectByConditionPrepareSqlCmd(DataType type,
    const std::vector<std::string>& andColumns, const std::vector<std::string>& orColumns) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }

    std::string sql = "select * from " + it->second.tableName_ + " where 1 = 1";
    for (const auto& andColName : andColumns) {
        if (andColName == PrivacyFiledConst::FIELD_TIMESTAMP_BEGIN) {
            sql.append(" and ");
            sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
            sql.append(" >=:" + andColName);
        } else if (andColName == PrivacyFiledConst::FIELD_TIMESTAMP_END) {
            sql.append(" and ");
            sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
            sql.append(" <=:" + andColName);
        } else {
            sql.append(" and ");
            sql.append(andColName + "=:" + andColName);
        }
    }
    if (!orColumns.empty()) {
        sql.append(" and (");
        for (const auto& orColName : orColumns) {
            if (orColName.find(PrivacyFiledConst::FIELD_OP_CODE) != std::string::npos) {
                sql.append(PrivacyFiledConst::FIELD_OP_CODE);
                sql.append(+ " =:" + orColName);
                sql.append(" or ");
            }
        }
        sql.append("0)");
    }
    return sql;
}

std::string PermissionUsedRecordDb::CreateCountPrepareSqlCmd(DataType type) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "select count(*) from " + it->second.tableName_;
    return sql;
}

std::string PermissionUsedRecordDb::CreateDeleteExpireRecordsPrepareSqlCmd(DataType type,
    const std::vector<std::string>& andColumns) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "delete from " + it->second.tableName_ + " where ";
    sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
    sql.append(" in (select ");
    sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
    sql.append(" from " + it->second.tableName_ + " where 1 = 1");
    for (const auto& andColName : andColumns) {
        if (andColName == PrivacyFiledConst::FIELD_TIMESTAMP_BEGIN) {
            sql.append(" and ");
            sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
            sql.append(" >=:" + andColName);
        } else if (andColName == PrivacyFiledConst::FIELD_TIMESTAMP_END) {
            sql.append(" and ");
            sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
            sql.append(" <=:" + andColName);
        } else {
            sql.append(" and ");
            sql.append(andColName + "=:" + andColName);
        }
    }
    sql.append(" )");
    return sql;
}

std::string PermissionUsedRecordDb::CreateDeleteExcessiveRecordsPrepareSqlCmd(DataType type,
    uint32_t excessiveSize) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "delete from " + it->second.tableName_ + " where ";
    sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
    sql.append(" in (select ");
    sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
    sql.append(" from " + it->second.tableName_ + " order by ");
    sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
    sql.append(" limit ");
    sql.append(std::to_string(excessiveSize) + " )");
    return sql;
}

std::string PermissionUsedRecordDb::CreateGetDistinctValue(DataType type,
    const std::string conditionColumns) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "select distinct ";
    sql.append(conditionColumns + " from "+ it->second.tableName_);
    return sql;
}

int32_t PermissionUsedRecordDb::CreatePermissionRecordTable() const
{
    auto it = dataTypeToSqlTable_.find(DataType::PERMISSION_RECORD);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }
    std::string sql = "create table if not exists ";
    sql.append(it->second.tableName_ + " (")
        .append(PrivacyFiledConst::FIELD_TOKEN_ID)
        .append(" integer not null,")
        .append(PrivacyFiledConst::FIELD_OP_CODE)
        .append(" integer not null,")
        .append(PrivacyFiledConst::FIELD_STATUS)
        .append(" integer not null,")
        .append(PrivacyFiledConst::FIELD_TIMESTAMP)
        .append(" integer not null,")
        .append(PrivacyFiledConst::FIELD_ACCESS_DURATION)
        .append(" integer not null,")
        .append(PrivacyFiledConst::FIELD_ACCESS_COUNT)
        .append(" integer not null,")
        .append(PrivacyFiledConst::FIELD_REJECT_COUNT)
        .append(" integer not null,")
        .append("primary key(")
        .append(PrivacyFiledConst::FIELD_TOKEN_ID)
        .append(",")
        .append(PrivacyFiledConst::FIELD_OP_CODE)
        .append(",")
        .append(PrivacyFiledConst::FIELD_STATUS)
        .append(",")
        .append(PrivacyFiledConst::FIELD_TIMESTAMP)
        .append("))");
    return ExecuteSql(sql);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
