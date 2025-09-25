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

#include <cinttypes>
#include <mutex>

#include "accesstoken_common_log.h"
#include "active_change_response_info.h"
#include "constant.h"
#include "permission_used_type.h"
#include "privacy_field_const.h"
#include "time_util.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* FIELD_COUNT_NUMBER = "count";
constexpr const char* INTEGER_STR = " integer not null,";
constexpr const char* CREATE_TABLE_STR = "create table if not exists ";
constexpr const char* WHERE_1_STR = " where 1 = 1";
constexpr const size_t TOKEN_ID_LENGTH = 11;

std::recursive_mutex g_instanceMutex;
}

PermissionUsedRecordDb& PermissionUsedRecordDb::GetInstance()
{
    static PermissionUsedRecordDb* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            PermissionUsedRecordDb* tmp = new (std::nothrow) PermissionUsedRecordDb();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

PermissionUsedRecordDb::~PermissionUsedRecordDb()
{
    Close();
}

void PermissionUsedRecordDb::OnCreate()
{
    LOGI(PRI_DOMAIN, PRI_TAG, "Entry");
    CreatePermissionRecordTable();
    CreatePermissionUsedTypeTable();
    CreatePermissionUsedRecordToggleStatusTable();
}

void PermissionUsedRecordDb::OnUpdate(int32_t version)
{
    LOGI(PRI_DOMAIN, PRI_TAG, "Entry");
    if (version == DataBaseVersion::VERISION_1) {
        InsertLockScreenStatusColumn();
        InsertPermissionUsedTypeColumn();
        CreatePermissionUsedTypeTable();
        UpdatePermissionRecordTablePrimaryKey();
        CreatePermissionUsedRecordToggleStatusTable();
    } else if (version == DataBaseVersion::VERISION_2) {
        InsertPermissionUsedTypeColumn();
        CreatePermissionUsedTypeTable();
        UpdatePermissionRecordTablePrimaryKey();
        CreatePermissionUsedRecordToggleStatusTable();
    } else if (version == DataBaseVersion::VERISION_3) {
        UpdatePermissionRecordTablePrimaryKey();
        CreatePermissionUsedRecordToggleStatusTable();
    } else if (version == DataBaseVersion::VERISION_4) {
        CreatePermissionUsedRecordToggleStatusTable();
    }
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
        PrivacyFiledConst::FIELD_REJECT_COUNT,
        PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS,
        PrivacyFiledConst::FIELD_USED_TYPE
    };

    SqliteTable permissionUsedTypeTable;
    permissionUsedTypeTable.tableName_ = PERMISSION_USED_TYPE_TABLE;
    permissionUsedTypeTable.tableColumnNames_ = {
        PrivacyFiledConst::FIELD_TOKEN_ID,
        PrivacyFiledConst::FIELD_PERMISSION_CODE,
        /**
         * bit operation:
         * 1 -> 001, NORMAL_TYPE
         * 2 -> 010, PICKER_TYPE
         * 3 -> 011, NORMAL_TYPE + PICKER_TYPE
         * 4 -> 100, SECURITY_COMPONENT_TYPE
         * 5 -> 101, NORMAL_TYPE + SECURITY_COMPONENT_TYPE
         * 6 -> 110, PICKER_TYPE + SECURITY_COMPONENT_TYPE
         * 7 -> 111, NORMAL_TYPE + PICKER_TYPE + SECURITY_COMPONENT_TYPE
         */
        PrivacyFiledConst::FIELD_USED_TYPE
    };

    SqliteTable permissionUsedRecordToggleStatusTable;
    permissionUsedRecordToggleStatusTable.tableName_ = PERMISSION_USED_RECORD_TOGGLE_STATUS_TABLE;
    permissionUsedRecordToggleStatusTable.tableColumnNames_ = {
        PrivacyFiledConst::FIELD_USER_ID,
        PrivacyFiledConst::FIELD_STATUS
    };

    dataTypeToSqlTable_ = {
        {PERMISSION_RECORD, permissionRecordTable},
        {PERMISSION_USED_TYPE, permissionUsedTypeTable},
        {PERMISSION_USED_RECORD_TOGGLE_STATUS, permissionUsedRecordToggleStatusTable},
    };
    Open();
}

int32_t PermissionUsedRecordDb::Add(DataType type, const std::vector<GenericValues>& values)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::unique_lock<std::shared_mutex> lock(this->rwLock_);
    std::string prepareSql = CreateInsertPrepareSqlCmd(type);
    if (prepareSql.empty()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Type %{public}u invalid", type);
        return FAILURE;
    }
    LOGD(PRI_DOMAIN, PRI_TAG, "Add sql is %{public}s.", prepareSql.c_str());

    auto statement = Prepare(prepareSql);
    BeginTransaction();
    bool isAddSuccessfully = true;
    for (const auto& value : values) {
        std::vector<std::string> columnNames = value.GetAllKeys();
        for (const auto& name : columnNames) {
            statement.Bind(name, value.Get(name));
        }
        int32_t ret = statement.Step();
        if (ret != Statement::State::DONE) {
            LOGE(PRI_DOMAIN, PRI_TAG, "Failed, errorMsg: %{public}s", SpitError().c_str());
            isAddSuccessfully = false;
        }
        statement.Reset();
    }
    if (!isAddSuccessfully) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Rollback transaction.");
        RollbackTransaction();
        return FAILURE;
    }
    LOGD(PRI_DOMAIN, PRI_TAG, "Commit transaction.");
    CommitTransaction();

    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(PRI_DOMAIN, PRI_TAG, "Add cost %{public}" PRId64 ".", endTime - beginTime);

    return SUCCESS;
}

int32_t PermissionUsedRecordDb::Remove(DataType type, const GenericValues& conditions)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::unique_lock<std::shared_mutex> lock(this->rwLock_);
    std::vector<std::string> columnNames = conditions.GetAllKeys();
    std::string prepareSql = CreateDeletePrepareSqlCmd(type, columnNames);
    if (prepareSql.empty()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Type %{public}u invalid", type);
        return FAILURE;
    }
    LOGD(PRI_DOMAIN, PRI_TAG, "Remove sql is %{public}s.", prepareSql.c_str());

    auto statement = Prepare(prepareSql);
    for (const auto& columnName : columnNames) {
        statement.Bind(columnName, conditions.Get(columnName));
    }
    int32_t ret = statement.Step();
    
    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(PRI_DOMAIN, PRI_TAG, "Remove cost %{public}" PRId64 ".", endTime - beginTime);

    return (ret == Statement::State::DONE) ? SUCCESS : FAILURE;
}

int32_t PermissionUsedRecordDb::FindByConditions(DataType type, const std::set<int32_t>& opCodeList,
    const GenericValues& andConditions, std::vector<GenericValues>& results, int32_t databaseQueryCount)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::shared_lock<std::shared_mutex> lock(this->rwLock_);
    std::vector<std::string> andColumns = andConditions.GetAllKeys();
    int32_t tokenId = andConditions.GetInt(PrivacyFiledConst::FIELD_TOKEN_ID);
    std::string prepareSql = CreateSelectByConditionPrepareSqlCmd(tokenId, type, opCodeList, andColumns,
        databaseQueryCount);
    if (prepareSql.empty()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Type %{public}u invalid", type);
        return FAILURE;
    }
    LOGD(PRI_DOMAIN, PRI_TAG, "FindByConditions sql is %{public}s.", prepareSql.c_str());

    auto statement = Prepare(prepareSql);

    for (const auto& columnName : andColumns) {
        statement.Bind(columnName, andConditions.Get(columnName));
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
    
    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(PRI_DOMAIN, PRI_TAG, "FindByConditions cost %{public}" PRId64 ".", endTime - beginTime);

    return SUCCESS;
}

int32_t PermissionUsedRecordDb::Count(DataType type)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::shared_lock<std::shared_mutex> lock(this->rwLock_);
    GenericValues countValue;
    std::string countSql = CreateCountPrepareSqlCmd(type);
    LOGD(PRI_DOMAIN, PRI_TAG, "Count sql is %{public}s.", countSql.c_str());
    auto countStatement = Prepare(countSql);
    if (countStatement.Step() == Statement::State::ROW) {
        int32_t column = 0;
        countValue.Put(FIELD_COUNT_NUMBER, countStatement.GetValue(column, false));
    }
    
    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(PRI_DOMAIN, PRI_TAG, "Count cost %{public}" PRId64 ".", endTime - beginTime);

    return countValue.GetInt(FIELD_COUNT_NUMBER);
}

int32_t PermissionUsedRecordDb::DeleteExpireRecords(DataType type,
    const GenericValues& andConditions)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::unique_lock<std::shared_mutex> lock(this->rwLock_);
    std::vector<std::string> andColumns = andConditions.GetAllKeys();
    if (!andColumns.empty()) {
        std::string deleteExpireSql = CreateDeleteExpireRecordsPrepareSqlCmd(type, andColumns);
        LOGD(PRI_DOMAIN, PRI_TAG, "DeleteExpireRecords sql is %{public}s.", deleteExpireSql.c_str());
        auto deleteExpireStatement = Prepare(deleteExpireSql);
        for (const auto& columnName : andColumns) {
            deleteExpireStatement.Bind(columnName, andConditions.Get(columnName));
        }
        if (deleteExpireStatement.Step() != Statement::State::DONE) {
            return FAILURE;
        }
    }
    
    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(PRI_DOMAIN, PRI_TAG, "DeleteExpireRecords cost %{public}" PRId64 ".", endTime - beginTime);

    return SUCCESS;
}

int32_t PermissionUsedRecordDb::DeleteHistoryRecordsInTables(std::vector<DataType> dateTypes,
    const std::unordered_set<AccessTokenID>& tokenIDList)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::unique_lock<std::shared_mutex> lock(this->rwLock_);
    BeginTransaction();
    for (const auto& type : dateTypes) {
        std::string deleteHistorySql = CreateDeleteHistoryRecordsPrepareSqlCmd(type, tokenIDList);
        LOGD(PRI_DOMAIN, PRI_TAG, "DeleteHistoryRecordsInTables sql is %{public}s.", deleteHistorySql.c_str());
        auto deleteHistoryStatement = Prepare(deleteHistorySql);
        if (deleteHistoryStatement.Step() != Statement::State::DONE) {
            LOGE(PRI_DOMAIN, PRI_TAG, "Rollback transaction.");
            RollbackTransaction();
            return FAILURE;
        }
    }

    LOGD(PRI_DOMAIN, PRI_TAG, "Commit transaction.");
    CommitTransaction();

    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(PRI_DOMAIN, PRI_TAG, "DeleteHistoryRecordsInTables cost %{public}" PRId64 ".", endTime - beginTime);

    return SUCCESS;
}

int32_t PermissionUsedRecordDb::DeleteExcessiveRecords(DataType type, uint32_t excessiveSize)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::unique_lock<std::shared_mutex> lock(this->rwLock_);
    std::string deleteExcessiveSql = CreateDeleteExcessiveRecordsPrepareSqlCmd(type, excessiveSize);
    LOGD(PRI_DOMAIN, PRI_TAG, "DeleteExcessiveRecords sql is %{public}s.", deleteExcessiveSql.c_str());
    auto deleteExcessiveStatement = Prepare(deleteExcessiveSql);
    if (deleteExcessiveStatement.Step() != Statement::State::DONE) {
        return FAILURE;
    }

    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(PRI_DOMAIN, PRI_TAG, "DeleteExcessiveRecords cost %{public}" PRId64 ".", endTime - beginTime);

    return SUCCESS;
}

int32_t PermissionUsedRecordDb::Update(DataType type, const GenericValues& modifyValue,
    const GenericValues& conditionValue)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::vector<std::string> modifyNames = modifyValue.GetAllKeys();
    std::vector<std::string> conditionNames = conditionValue.GetAllKeys();

    std::unique_lock<std::shared_mutex> lock(this->rwLock_);
    std::string prepareSql = CreateUpdatePrepareSqlCmd(type, modifyNames, conditionNames);
    if (prepareSql.empty()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Type %{public}u invalid", type);
        return FAILURE;
    }
    LOGD(PRI_DOMAIN, PRI_TAG, "Update sql is %{public}s.", prepareSql.c_str());

    auto statement = Prepare(prepareSql);

    for (const auto& modifyName : modifyNames) {
        statement.Bind(modifyName, modifyValue.Get(modifyName));
    }

    for (const auto& conditionName : conditionNames) {
        statement.Bind(conditionName, conditionValue.Get(conditionName));
    }

    int32_t ret = statement.Step();
    if (ret != Statement::State::DONE) {
        LOGE(PRI_DOMAIN, PRI_TAG,
            "Update table Type %{public}u failed, errCode is %{public}d, errMsg is %{public}s.", type, ret,
            SpitError().c_str());
        return FAILURE;
    }

    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(PRI_DOMAIN, PRI_TAG, "Update cost %{public}" PRId64 ".", endTime - beginTime);

    return SUCCESS;
}

int32_t PermissionUsedRecordDb::Query(DataType type, const GenericValues& conditionValue,
    std::vector<GenericValues>& results)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::vector<std::string> conditionColumns = conditionValue.GetAllKeys();

    std::shared_lock<std::shared_mutex> lock(this->rwLock_);
    std::string prepareSql = CreateQueryPrepareSqlCmd(type, conditionColumns);
    if (prepareSql.empty()) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Type %{public}u invalid.", type);
        return FAILURE;
    }
    LOGD(PRI_DOMAIN, PRI_TAG, "Query sql is %{public}s.", prepareSql.c_str());

    auto statement = Prepare(prepareSql);
    for (const auto& conditionColumn : conditionColumns) {
        statement.Bind(conditionColumn, conditionValue.Get(conditionColumn));
    }

    while (statement.Step() == Statement::State::ROW) {
        int32_t columnCount = statement.GetColumnCount();
        GenericValues value;

        for (int32_t i = 0; i < columnCount; i++) {
            value.Put(statement.GetColumnName(i), statement.GetValue(i, false));
        }

        results.emplace_back(value);
    }

    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(PRI_DOMAIN, PRI_TAG, "Query cost %{public}" PRId64 ".", endTime - beginTime);

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
    for (const auto& name : it->second.tableColumnNames_) {
        sql.append(":" + name);
        if (i < static_cast<int32_t>(it->second.tableColumnNames_.size())) {
            sql.append(",");
        }
        i += 1;
    }
    sql.append(")");
    return sql;
}

std::string PermissionUsedRecordDb::CreateQueryPrepareSqlCmd(DataType type,
    const std::vector<std::string>& conditionColumns) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "select * from " + it->second.tableName_ + WHERE_1_STR;

    for (const auto& andColumn : conditionColumns) {
        sql.append(" and ");
        sql.append(andColumn + "=:" + andColumn);
    }

    return sql;
}

std::string PermissionUsedRecordDb::CreateDeletePrepareSqlCmd(
    DataType type, const std::vector<std::string>& columnNames) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "delete from " + it->second.tableName_ + WHERE_1_STR;
    for (const auto& name : columnNames) {
        sql.append(" and ");
        sql.append(name + "=:" + name);
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
    for (const auto& name : modifyColumns) {
        sql.append(name + "=:" + name);
        if (i < static_cast<int32_t>(modifyColumns.size())) {
            sql.append(",");
        }
        i += 1;
    }

    if (!conditionColumns.empty()) {
        sql.append(WHERE_1_STR);
        for (const auto& columnName : conditionColumns) {
            sql.append(" and ");
            sql.append(columnName + "=:" + columnName);
        }
    }
    return sql;
}

std::string PermissionUsedRecordDb::CreateSelectByConditionPrepareSqlCmd(const int32_t tokenId, DataType type,
    const std::set<int32_t>& opCodeList, const std::vector<std::string>& andColumns, int32_t databaseQueryCount) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }

    std::string sql = "select * from " + it->second.tableName_ + WHERE_1_STR;

    for (const auto& andColName : andColumns) {
        if (andColName == PrivacyFiledConst::FIELD_TIMESTAMP_BEGIN) {
            sql.append(" and ");
            sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
            sql.append(" >=:" + andColName);
        } else if (andColName == PrivacyFiledConst::FIELD_TIMESTAMP_END) {
            sql.append(" and ");
            sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
            sql.append(" <=:" + andColName);
        } else if (andColName == PrivacyFiledConst::FIELD_TOKEN_ID) {
            if (tokenId != 0) {
                sql.append(" and ");
                sql.append(PrivacyFiledConst::FIELD_TOKEN_ID);
                sql.append(" =:" + andColName);
            }
        } else {
            sql.append(" and ");
            sql.append(andColName + "=:" + andColName);
        }
    }
    if (!opCodeList.empty()) {
        sql.append(" and (");
        for (const auto& opCode : opCodeList) {
            if (opCode != Constant::OP_INVALID) {
                sql.append(PrivacyFiledConst::FIELD_OP_CODE);
                sql.append(+ " = " + std::to_string(opCode));
                sql.append(" or ");
            }
        }
        sql.append("0)");
    }
    sql.append(" order by timestamp desc");
    sql.append(" limit " + std::to_string(databaseQueryCount));
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
    sql.append(" from " + it->second.tableName_ + WHERE_1_STR);
    for (const auto& name : andColumns) {
        if (name == PrivacyFiledConst::FIELD_TIMESTAMP_BEGIN) {
            sql.append(" and ");
            sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
            sql.append(" >=:" + name);
        } else if (name == PrivacyFiledConst::FIELD_TIMESTAMP_END) {
            sql.append(" and ");
            sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
            sql.append(" <=:" + name);
        } else {
            sql.append(" and ");
            sql.append(name + "=:" + name);
        }
    }
    sql.append(" )");
    return sql;
}

std::string PermissionUsedRecordDb::CreateDeleteHistoryRecordsPrepareSqlCmd(DataType type,
    const std::unordered_set<AccessTokenID>& tokenIDList) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "delete from " + it->second.tableName_ + " where ";
    sql.append(PrivacyFiledConst::FIELD_TOKEN_ID);
    sql.append(" in ( ");

    size_t sqlLen = sql.size();
    sqlLen += TOKEN_ID_LENGTH * tokenIDList.size();
    sql.reserve(sqlLen);

    for (auto token = tokenIDList.begin(); token != tokenIDList.end(); ++token) {
        sql.append(std::to_string(*token));
        if (std::next(token) != tokenIDList.end()) {
            sql.append(", ");
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

int32_t PermissionUsedRecordDb::CreatePermissionRecordTable() const
{
    auto it = dataTypeToSqlTable_.find(DataType::PERMISSION_RECORD);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }
    std::string sql = CREATE_TABLE_STR;
    sql.append(it->second.tableName_ + " (")
        .append(PrivacyFiledConst::FIELD_TOKEN_ID)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_OP_CODE)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_STATUS)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_TIMESTAMP)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_ACCESS_DURATION)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_ACCESS_COUNT)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_REJECT_COUNT)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_USED_TYPE)
        .append(INTEGER_STR)
        .append("primary key(")
        .append(PrivacyFiledConst::FIELD_TOKEN_ID)
        .append(",")
        .append(PrivacyFiledConst::FIELD_OP_CODE)
        .append(",")
        .append(PrivacyFiledConst::FIELD_STATUS)
        .append(",")
        .append(PrivacyFiledConst::FIELD_TIMESTAMP)
        .append(",")
        .append(PrivacyFiledConst::FIELD_USED_TYPE)
        .append("))");
    return ExecuteSql(sql);
}

int32_t PermissionUsedRecordDb::CreatePermissionUsedTypeTable() const
{
    auto it = dataTypeToSqlTable_.find(DataType::PERMISSION_USED_TYPE);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }
    std::string sql = CREATE_TABLE_STR;
    sql.append(it->second.tableName_ + " (")
        .append(PrivacyFiledConst::FIELD_TOKEN_ID)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_PERMISSION_CODE)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_USED_TYPE)
        .append(INTEGER_STR)
        .append("primary key(")
        .append(PrivacyFiledConst::FIELD_TOKEN_ID)
        .append(",")
        .append(PrivacyFiledConst::FIELD_PERMISSION_CODE)
        .append("))");
    return ExecuteSql(sql);
}

int32_t PermissionUsedRecordDb::CreatePermissionUsedRecordToggleStatusTable() const
{
    auto it = dataTypeToSqlTable_.find(DataType::PERMISSION_USED_RECORD_TOGGLE_STATUS);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }
    std::string sql = CREATE_TABLE_STR;
    sql.append(it->second.tableName_ + " (")
        .append(PrivacyFiledConst::FIELD_USER_ID)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_STATUS)
        .append(INTEGER_STR)
        .append("primary key(")
        .append(PrivacyFiledConst::FIELD_USER_ID)
        .append("))");
    return ExecuteSql(sql);
}

int32_t PermissionUsedRecordDb::InsertLockScreenStatusColumn() const
{
    auto it = dataTypeToSqlTable_.find(DataType::PERMISSION_RECORD);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }
    std::string checkSql = "SELECT 1 FROM " + it->second.tableName_ + " WHERE " +
        PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS + "=" +
        std::to_string(LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED);
    int32_t checkResult = ExecuteSql(checkSql);
    LOGI(PRI_DOMAIN, PRI_TAG, "Check result:%{public}d", checkResult);
    if (checkResult != -1) {
        return SUCCESS;
    }

    std::string sql = "alter table ";
    sql.append(it->second.tableName_ + " add column ")
        .append(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS)
        .append(" integer default ")
        .append(std::to_string(LockScreenStatusChangeType::PERM_ACTIVE_IN_UNLOCKED));
    int32_t insertResult = ExecuteSql(sql);
    LOGI(PRI_DOMAIN, PRI_TAG, "Insert column result:%{public}d", insertResult);
    return insertResult;
}

int32_t PermissionUsedRecordDb::InsertPermissionUsedTypeColumn() const
{
    auto it = dataTypeToSqlTable_.find(DataType::PERMISSION_RECORD);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }
    std::string checkSql = "SELECT 1 FROM " + it->second.tableName_ + " WHERE " +
        PrivacyFiledConst::FIELD_USED_TYPE + "=" +
        std::to_string(PermissionUsedType::NORMAL_TYPE);
    int32_t checkResult = ExecuteSql(checkSql);
    LOGI(PRI_DOMAIN, PRI_TAG, "Check result:%{public}d", checkResult);
    if (checkResult != -1) {
        return SUCCESS;
    }

    std::string sql = "alter table ";
    sql.append(it->second.tableName_ + " add column ")
        .append(PrivacyFiledConst::FIELD_USED_TYPE)
        .append(" integer default ")
        .append(std::to_string(PermissionUsedType::NORMAL_TYPE));
    int32_t insertResult = ExecuteSql(sql);
    LOGI(PRI_DOMAIN, PRI_TAG, "Insert column result:%{public}d", insertResult);
    return insertResult;
}

static void CreateNewPermissionRecordTable(std::string& newTableName, std::string& createNewSql)
{
    createNewSql = CREATE_TABLE_STR;
    createNewSql.append(newTableName + " (")
        .append(PrivacyFiledConst::FIELD_TOKEN_ID)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_OP_CODE)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_STATUS)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_TIMESTAMP)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_ACCESS_DURATION)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_ACCESS_COUNT)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_REJECT_COUNT)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_LOCKSCREEN_STATUS)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_USED_TYPE)
        .append(INTEGER_STR)
        .append("primary key(")
        .append(PrivacyFiledConst::FIELD_TOKEN_ID)
        .append(",")
        .append(PrivacyFiledConst::FIELD_OP_CODE)
        .append(",")
        .append(PrivacyFiledConst::FIELD_STATUS)
        .append(",")
        .append(PrivacyFiledConst::FIELD_TIMESTAMP)
        .append(",")
        .append(PrivacyFiledConst::FIELD_USED_TYPE)
        .append("))");
}

int32_t PermissionUsedRecordDb::UpdatePermissionRecordTablePrimaryKey() const
{
    auto it = dataTypeToSqlTable_.find(DataType::PERMISSION_RECORD);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }

    std::string tableName = it->second.tableName_;
    std::string newTableName = it->second.tableName_ + "_new";
    std::string createNewSql;
    CreateNewPermissionRecordTable(newTableName, createNewSql);

    BeginTransaction();

    int32_t createNewRes = ExecuteSql(createNewSql); // 1、create new table with new primary key
    if (createNewRes != 0) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Create new table failed, errCode is %{public}d, errMsg is %{public}s.",
            createNewRes, SpitError().c_str());
        return FAILURE;
    }

    std::string copyDataSql = "insert into " + newTableName + " select * from " + tableName;
    int32_t copyDataRes = ExecuteSql(copyDataSql); // 2、copy data from old table to new table
    if (copyDataRes != 0) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Copy data from old table failed, errCode is %{public}d, errMsg is %{public}s.",
            copyDataRes, SpitError().c_str());
        RollbackTransaction();
        return FAILURE;
    }

    std::string dropOldSql = "drop table " + tableName;
    int32_t dropOldRes = ExecuteSql(dropOldSql); // 3、drop old table
    if (dropOldRes != 0) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Drop old table failed, errCode is %{public}d, errMsg is %{public}s.",
            dropOldRes, SpitError().c_str());
        RollbackTransaction();
        return FAILURE;
    }

    std::string renameSql = "alter table " + newTableName + " rename to " + tableName;
    int32_t renameRes = ExecuteSql(renameSql); // 4、rename new table to old
    if (renameRes != 0) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Rename table failed, errCode is %{public}d, errMsg is %{public}s.",
            renameRes, SpitError().c_str());
        RollbackTransaction();
        return FAILURE;
    }

    CommitTransaction();

    return SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
