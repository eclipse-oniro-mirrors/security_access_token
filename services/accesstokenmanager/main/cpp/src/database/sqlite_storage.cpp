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

#include "sqlite_storage.h"

#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "SqliteStorage"};
static const std::string INTEGER_STR = " integer not null,";
static const std::string TEXT_STR = " text not null,";
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
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called.", __func__);
    CreateHapTokenInfoTable();
    CreateNativeTokenInfoTable();
    CreatePermissionDefinitionTable();
    CreatePermissionStateTable();
}

void SqliteStorage::OnUpdate()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "%{public}s called.", __func__);
}

SqliteStorage::SqliteStorage() : SqliteHelper(DATABASE_NAME, DATABASE_PATH, DATABASE_VERSION)
{
    SqliteTable hapTokenInfoTable;
    hapTokenInfoTable.tableName_ = HAP_TOKEN_INFO_TABLE;
    hapTokenInfoTable.tableColumnNames_ = {
        TokenFiledConst::FIELD_TOKEN_ID, TokenFiledConst::FIELD_USER_ID,
        TokenFiledConst::FIELD_BUNDLE_NAME, TokenFiledConst::FIELD_INST_INDEX, TokenFiledConst::FIELD_DLP_TYPE,
        TokenFiledConst::FIELD_APP_ID, TokenFiledConst::FIELD_DEVICE_ID,
        TokenFiledConst::FIELD_APL, TokenFiledConst::FIELD_TOKEN_VERSION,
        TokenFiledConst::FIELD_TOKEN_ATTR, TokenFiledConst::FIELD_API_VERSION
    };

    SqliteTable NativeTokenInfoTable;
    NativeTokenInfoTable.tableName_ = NATIVE_TOKEN_INFO_TABLE;
    NativeTokenInfoTable.tableColumnNames_ = {
        TokenFiledConst::FIELD_TOKEN_ID, TokenFiledConst::FIELD_PROCESS_NAME,
        TokenFiledConst::FIELD_TOKEN_VERSION, TokenFiledConst::FIELD_TOKEN_ATTR,
        TokenFiledConst::FIELD_DCAP, TokenFiledConst::FIELD_NATIVE_ACLS, TokenFiledConst::FIELD_APL
    };

    SqliteTable permissionDefTable;
    permissionDefTable.tableName_ = PERMISSION_DEF_TABLE;
    permissionDefTable.tableColumnNames_ = {
        TokenFiledConst::FIELD_TOKEN_ID, TokenFiledConst::FIELD_PERMISSION_NAME,
        TokenFiledConst::FIELD_BUNDLE_NAME, TokenFiledConst::FIELD_GRANT_MODE,
        TokenFiledConst::FIELD_AVAILABLE_LEVEL, TokenFiledConst::FIELD_PROVISION_ENABLE,
        TokenFiledConst::FIELD_DISTRIBUTED_SCENE_ENABLE, TokenFiledConst::FIELD_LABEL,
        TokenFiledConst::FIELD_LABEL_ID, TokenFiledConst::FIELD_DESCRIPTION,
        TokenFiledConst::FIELD_DESCRIPTION_ID
    };

    SqliteTable permissionStateTable;
    permissionStateTable.tableName_ = PERMISSION_STATE_TABLE;
    permissionStateTable.tableColumnNames_ = {
        TokenFiledConst::FIELD_TOKEN_ID, TokenFiledConst::FIELD_PERMISSION_NAME,
        TokenFiledConst::FIELD_DEVICE_ID, TokenFiledConst::FIELD_GRANT_IS_GENERAL,
        TokenFiledConst::FIELD_GRANT_STATE, TokenFiledConst::FIELD_GRANT_FLAG
    };

    dataTypeToSqlTable_ = {
        {ACCESSTOKEN_HAP_INFO, hapTokenInfoTable},
        {ACCESSTOKEN_NATIVE_INFO, NativeTokenInfoTable},
        {ACCESSTOKEN_PERMISSION_DEF, permissionDefTable},
        {ACCESSTOKEN_PERMISSION_STATE, permissionStateTable},
    };

    Open();
}

int SqliteStorage::Add(const DataType type, const std::vector<GenericValues>& values)
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
        int ret = statement.Step();
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
    ACCESSTOKEN_LOG_INFO(LABEL, "commit transaction.");
    CommitTransaction();
    return SUCCESS;
}

int SqliteStorage::Remove(const DataType type, const GenericValues& conditions)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::vector<std::string> columnNames = conditions.GetAllKeys();
    std::string prepareSql = CreateDeletePrepareSqlCmd(type, columnNames);
    auto statement = Prepare(prepareSql);
    for (const auto& columnName : columnNames) {
        statement.Bind(columnName, conditions.Get(columnName));
    }
    int ret = statement.Step();
    return (ret == Statement::State::DONE) ? SUCCESS : FAILURE;
}

int SqliteStorage::Modify(const DataType type, const GenericValues& modifyValues, const GenericValues& conditions)
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
    int ret = statement.Step();
    return (ret == Statement::State::DONE) ? SUCCESS : FAILURE;
}

int SqliteStorage::Find(const DataType type, std::vector<GenericValues>& results)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::string prepareSql = CreateSelectPrepareSqlCmd(type);
    auto statement = Prepare(prepareSql);
    while (statement.Step() == Statement::State::ROW) {
        int columnCount = statement.GetColumnCount();
        GenericValues value;
        for (int i = 0; i < columnCount; i++) {
            value.Put(statement.GetColumnName(i), statement.GetValue(i, false));
        }
        results.emplace_back(value);
    }
    return SUCCESS;
}

int SqliteStorage::RefreshAll(const DataType type, const std::vector<GenericValues>& values)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
    std::string deleteSql = CreateDeletePrepareSqlCmd(type);
    std::string insertSql = CreateInsertPrepareSqlCmd(type);
    auto deleteStatement = Prepare(deleteSql);
    auto insertStatement = Prepare(insertSql);
    BeginTransaction();
    bool canCommit = deleteStatement.Step() == Statement::State::DONE;
    for (const auto& value : values) {
        std::vector<std::string> columnNames = value.GetAllKeys();
        for (const auto& columnName : columnNames) {
            insertStatement.Bind(columnName, value.Get(columnName));
        }
        int ret = insertStatement.Step();
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
    int i = 1;
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

std::string SqliteStorage::CreateDeletePrepareSqlCmd(
    const DataType type, const std::vector<std::string>& columnNames) const
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
    int i = 1;
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

std::string SqliteStorage::CreateSelectPrepareSqlCmd(const DataType type) const
{
    auto it = dataTypeToSqlTable_.find(type);
    if (it == dataTypeToSqlTable_.end()) {
        return std::string();
    }
    std::string sql = "select * from " + it->second.tableName_;
    return sql;
}

int SqliteStorage::CreateHapTokenInfoTable() const
{
    auto it = dataTypeToSqlTable_.find(DataType::ACCESSTOKEN_HAP_INFO);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }
    std::string sql = "create table if not exists ";
    sql.append(it->second.tableName_ + " (")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_USER_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_BUNDLE_NAME)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_INST_INDEX)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_DLP_TYPE)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_APP_ID)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_DEVICE_ID)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_APL)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_TOKEN_VERSION)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_TOKEN_ATTR)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_API_VERSION)
        .append(INTEGER_STR)
        .append("primary key(")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append("))");
    return ExecuteSql(sql);
}

int SqliteStorage::CreateNativeTokenInfoTable() const
{
    auto it = dataTypeToSqlTable_.find(DataType::ACCESSTOKEN_NATIVE_INFO);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }
    std::string sql = "create table if not exists ";
    sql.append(it->second.tableName_ + " (")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_PROCESS_NAME)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_TOKEN_VERSION)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_TOKEN_ATTR)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_DCAP)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_NATIVE_ACLS)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_APL)
        .append(INTEGER_STR)
        .append("primary key(")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append("))");
    return ExecuteSql(sql);
}

int SqliteStorage::CreatePermissionDefinitionTable() const
{
    auto it = dataTypeToSqlTable_.find(DataType::ACCESSTOKEN_PERMISSION_DEF);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }
    std::string sql = "create table if not exists ";
    sql.append(it->second.tableName_ + " (")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_PERMISSION_NAME)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_BUNDLE_NAME)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_GRANT_MODE)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_AVAILABLE_LEVEL)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_PROVISION_ENABLE)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_DISTRIBUTED_SCENE_ENABLE)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_LABEL)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_LABEL_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_DESCRIPTION)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_DESCRIPTION_ID)
        .append(INTEGER_STR)
        .append("primary key(")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(",")
        .append(TokenFiledConst::FIELD_PERMISSION_NAME)
        .append("))");
    return ExecuteSql(sql);
}

int SqliteStorage::CreatePermissionStateTable() const
{
    auto it = dataTypeToSqlTable_.find(DataType::ACCESSTOKEN_PERMISSION_STATE);
    if (it == dataTypeToSqlTable_.end()) {
        return FAILURE;
    }
    std::string sql = "create table if not exists ";
    sql.append(it->second.tableName_ + " (")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_PERMISSION_NAME)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_DEVICE_ID)
        .append(TEXT_STR)
        .append(TokenFiledConst::FIELD_GRANT_IS_GENERAL)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_GRANT_STATE)
        .append(INTEGER_STR)
        .append(TokenFiledConst::FIELD_GRANT_FLAG)
        .append(INTEGER_STR)
        .append("primary key(")
        .append(TokenFiledConst::FIELD_TOKEN_ID)
        .append(",")
        .append(TokenFiledConst::FIELD_PERMISSION_NAME)
        .append(",")
        .append(TokenFiledConst::FIELD_DEVICE_ID)
        .append("))");
    return ExecuteSql(sql);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
