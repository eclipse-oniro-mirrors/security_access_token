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

#include "remote_permission_used_record_db.h"

#include <cinttypes>
#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <sstream>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "accesstoken_common_log.h"
#include "active_change_response_info.h"
#include "constant.h"
#include "data_usage_dfx.h"
#include "permission_used_type.h"
#include "privacy_error.h"
#include "privacy_field_const.h"
#include "time_util.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* FIELD_COUNT_NUMBER = "count";
constexpr const char* INTEGER_STR = " integer not null,";
constexpr const char* TEXT_STR = " text not null,";
constexpr const char* CREATE_TABLE_STR = "create table if not exists ";
constexpr const char* WHERE_1_STR = " where 1 = 1";

const std::string REMOTE_PERMISSION_RECORD_TABLE = "remote_permission_record";
constexpr const char* DATABASE_NAME = "remote_permission_used_record.db";
constexpr const char* DATABASE_PATH_BASE = "/data/service/el2/";
constexpr const char* DATABASE_PATH_INNER = "/access_token/";
std::set<int32_t> g_dfxSet;

std::vector<std::string> g_tableColumnNames = {
    PrivacyFiledConst::FIELD_DEVICE_ID,
    PrivacyFiledConst::FIELD_DEVICE_NAME,
    PrivacyFiledConst::FIELD_OP_CODE,
    PrivacyFiledConst::FIELD_TIMESTAMP,
    PrivacyFiledConst::FIELD_ACCESS_COUNT,
    PrivacyFiledConst::FIELD_REJECT_COUNT
};

std::recursive_mutex g_instanceMutex;
}

RemotePermUsedRecordDbManager& RemotePermUsedRecordDbManager::GetInstance()
{
    static RemotePermUsedRecordDbManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            RemotePermUsedRecordDbManager* tmp = new (std::nothrow) RemotePermUsedRecordDbManager();
            instance = std::move(tmp);
        }
    }
    return *instance;
}

RemotePermUsedRecordDbManager::RemotePermUsedRecordDbManager()
{}

static bool IsDirExist(std::string& dirPath)
{
    struct stat fstat = {};
    if (stat(dirPath.c_str(), &fstat) != 0) {
        LOGD(PRI_DOMAIN, PRI_TAG, "Path: %{public}s is invalid, errorNo: %{public}d.", dirPath.c_str(), errno);
        return false;
    }

    if (!S_ISDIR(fstat.st_mode)) {
        LOGD(PRI_DOMAIN, PRI_TAG, "Path: %{public}s is not a directory.", dirPath.c_str());
        return false;
    }
    return true;
}

static bool IsDbFileExist(uint32_t userId)
{
    std::string fileName = DATABASE_PATH_BASE + std::to_string(userId) + DATABASE_PATH_INNER + DATABASE_NAME;
    struct stat fstat = {};
    int32_t res = stat(fileName.c_str(), &fstat);
    if (res != 0) {
        LOGD(PRI_DOMAIN, PRI_TAG, "File: %{public}s is invalid, errorNo: %{public}d.", fileName.c_str(), errno);
        return false;
    }
    return true;
}

std::shared_ptr<RemotePermissionUsedRecordDb> RemotePermUsedRecordDbManager::GetDatabase(
    const int32_t userId, const bool needCreate)
{
    std::shared_ptr<RemotePermissionUsedRecordDb> db = nullptr;

    std::string dirPath = DATABASE_PATH_BASE + std::to_string(userId) + DATABASE_PATH_INNER;
    // dir not exist
    if (!IsDirExist(dirPath)) {
        LOGE(PRI_DOMAIN, PRI_TAG, "User=%{public}d dir not exist", userId);
        return nullptr;
    }

    if (!needCreate) {
        // get record only open db, don't create, if not exist return nullptr
        if (IsDbFileExist(userId)) {
            db = std::make_shared<RemotePermissionUsedRecordDb>(dirPath, DATABASE_NAME);
        }
        return db;
    }

    db = std::make_shared<RemotePermissionUsedRecordDb>(dirPath, DATABASE_NAME);

    return db;
}

int32_t RemotePermUsedRecordDbManager::Add(const int32_t userId, const std::vector<GenericValues>& values)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    auto db = GetDatabase(userId, true);
    if (db == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Get db failed, userId=%{public}d", userId);
        return PrivacyError::ERR_FILE_OPERATE_FAILED;
    }
    int32_t res = db->Add(values);
    if (res == Constant::SUCCESS && g_dfxSet.count(userId) == 0) {
        g_dfxSet.insert(userId);
        std::string dirPath = DATABASE_PATH_BASE + std::to_string(userId) + DATABASE_PATH_INNER;
        std::thread reportUserData(ReportPrivacyUserData, dirPath);
        reportUserData.detach();
    }
    return res;
}

int32_t RemotePermUsedRecordDbManager::Remove(const int32_t userId, const GenericValues& conditions)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    auto db = GetDatabase(userId, false);
    if (db == nullptr) {
        LOGD(PRI_DOMAIN, PRI_TAG, "Db not exist or unlock, userId=%{public}d", userId);
        return Constant::SUCCESS;
    }
    return db->Remove(conditions);
}

int32_t RemotePermUsedRecordDbManager::FindByConditions(const int32_t userId, const std::set<int32_t>& opCodeList,
    const GenericValues& andConditions, std::vector<GenericValues>& results, int32_t databaseQueryCount)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    auto db = GetDatabase(userId, false);
    if (db == nullptr) {
        LOGI(PRI_DOMAIN, PRI_TAG, "Db not exist or unlock, userId=%{public}d", userId);
        return Constant::SUCCESS;
    }
    return db->FindByConditions(opCodeList, andConditions, results, databaseQueryCount);
}

int32_t RemotePermUsedRecordDbManager::Count(const int32_t userId)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    auto db = GetDatabase(userId, false);
    if (db == nullptr) {
        LOGD(PRI_DOMAIN, PRI_TAG, "Db not exist or unlock, userId=%{public}d", userId);
        return 0;
    }
    return db->Count();
}

int32_t RemotePermUsedRecordDbManager::DeleteExpireRecords(const int32_t userId, const GenericValues& andConditions)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    auto db = GetDatabase(userId, false);
    if (db == nullptr) {
        LOGD(PRI_DOMAIN, PRI_TAG, "Db not exist or unlock, userId=%{public}d", userId);
        return Constant::SUCCESS;
    }
    return db->DeleteExpireRecords(andConditions);
}

int32_t RemotePermUsedRecordDbManager::DeleteExcessiveRecords(const int32_t userId, uint32_t excessiveSize)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    auto db = GetDatabase(userId, false);
    if (db == nullptr) {
        LOGD(PRI_DOMAIN, PRI_TAG, "Db not exist or unlock, userId=%{public}d", userId);
        return Constant::SUCCESS;
    }
    return db->DeleteExcessiveRecords(excessiveSize);
}

int32_t RemotePermUsedRecordDbManager::Update(
    const int32_t userId, const GenericValues& modifyValue, const GenericValues& conditionValue)
{
    std::lock_guard<std::mutex> lock(dbMutex_);
    auto db = GetDatabase(userId, true);
    if (db == nullptr) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Get db failed, userId=%{public}d", userId);
        return PrivacyError::ERR_FILE_OPERATE_FAILED;
    }
    return db->Update(modifyValue, conditionValue);
}

RemotePermissionUsedRecordDb::~RemotePermissionUsedRecordDb()
{
    Close();
}

void RemotePermissionUsedRecordDb::OnCreate()
{
    LOGI(PRI_DOMAIN, PRI_TAG, "Entry");
    CreateRemotePermissionRecordTable();
}

void RemotePermissionUsedRecordDb::OnUpdate(int32_t version)
{
    LOGI(PRI_DOMAIN, PRI_TAG, "Entry");
}

RemotePermissionUsedRecordDb::RemotePermissionUsedRecordDb(const std::string& dbPath, const std::string& dbName)
    : SqliteHelper(dbName, dbPath, DATABASE_VERSION)
{
    Open();
}

int32_t RemotePermissionUsedRecordDb::Add(const std::vector<GenericValues>& values)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::unique_lock<std::shared_mutex> lock(this->rwLock_);
    std::string prepareSql = CreateInsertPrepareSqlCmd();
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
        return PrivacyError::ERR_DATABASE_OPERATE_FAILED;
    }
    LOGD(PRI_DOMAIN, PRI_TAG, "Commit transaction.");
    CommitTransaction();

    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(PRI_DOMAIN, PRI_TAG, "Add cost %{public}" PRId64 ".", endTime - beginTime);

    return SUCCESS;
}

int32_t RemotePermissionUsedRecordDb::Remove(const GenericValues& conditions)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::unique_lock<std::shared_mutex> lock(this->rwLock_);
    std::vector<std::string> columnNames = conditions.GetAllKeys();
    std::string prepareSql = CreateDeletePrepareSqlCmd(columnNames);
    LOGD(PRI_DOMAIN, PRI_TAG, "Remove sql is %{public}s.", prepareSql.c_str());

    auto statement = Prepare(prepareSql);
    for (const auto& columnName : columnNames) {
        statement.Bind(columnName, conditions.Get(columnName));
    }
    int32_t ret = statement.Step();
    
    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(PRI_DOMAIN, PRI_TAG, "Remove cost %{public}" PRId64 ".", endTime - beginTime);

    return (ret == Statement::State::DONE) ? SUCCESS : PrivacyError::ERR_DATABASE_OPERATE_FAILED;
}

int32_t RemotePermissionUsedRecordDb::FindByConditions(const std::set<int32_t>& opCodeList,
    const GenericValues& andConditions, std::vector<GenericValues>& results, int32_t databaseQueryCount)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::shared_lock<std::shared_mutex> lock(this->rwLock_);
    std::vector<std::string> andColumns = andConditions.GetAllKeys();

    std::string prepareSql = CreateSelectByConditionPrepareSqlCmd(opCodeList, andColumns, databaseQueryCount);
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

int32_t RemotePermissionUsedRecordDb::Count()
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::shared_lock<std::shared_mutex> lock(this->rwLock_);
    GenericValues countValue;
    std::string countSql = CreateCountPrepareSqlCmd();
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

int32_t RemotePermissionUsedRecordDb::DeleteExpireRecords(const GenericValues& andConditions)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::unique_lock<std::shared_mutex> lock(this->rwLock_);
    std::vector<std::string> andColumns = andConditions.GetAllKeys();
    if (!andColumns.empty()) {
        std::string deleteExpireSql = CreateDeleteExpireRecordsPrepareSqlCmd(andColumns);
        LOGD(PRI_DOMAIN, PRI_TAG, "DeleteExpireRecords sql is %{public}s.", deleteExpireSql.c_str());
        auto deleteExpireStatement = Prepare(deleteExpireSql);
        for (const auto& columnName : andColumns) {
            deleteExpireStatement.Bind(columnName, andConditions.Get(columnName));
        }
        if (deleteExpireStatement.Step() != Statement::State::DONE) {
            LOGE(PRI_DOMAIN, PRI_TAG, "Step failed, errMsg is %{public}s.", SpitError().c_str());
            return PrivacyError::ERR_DATABASE_OPERATE_FAILED;
        }
    }
    
    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(PRI_DOMAIN, PRI_TAG, "DeleteExpireRecords cost %{public}" PRId64 ".", endTime - beginTime);

    return SUCCESS;
}

int32_t RemotePermissionUsedRecordDb::DeleteExcessiveRecords(uint32_t excessiveSize)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::unique_lock<std::shared_mutex> lock(this->rwLock_);
    std::string deleteExcessiveSql = CreateDeleteExcessiveRecordsPrepareSqlCmd(excessiveSize);
    LOGD(PRI_DOMAIN, PRI_TAG, "DeleteExcessiveRecords sql is %{public}s.", deleteExcessiveSql.c_str());
    auto deleteExcessiveStatement = Prepare(deleteExcessiveSql);
    if (deleteExcessiveStatement.Step() != Statement::State::DONE) {
        LOGE(PRI_DOMAIN, PRI_TAG, "Step failed, errMsg is %{public}s.", SpitError().c_str());
        return PrivacyError::ERR_DATABASE_OPERATE_FAILED;
    }

    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(PRI_DOMAIN, PRI_TAG, "DeleteExcessiveRecords cost %{public}" PRId64 ".", endTime - beginTime);

    return SUCCESS;
}

int32_t RemotePermissionUsedRecordDb::Update(const GenericValues& modifyValue,
    const GenericValues& conditionValue)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    std::vector<std::string> modifyNames = modifyValue.GetAllKeys();
    std::vector<std::string> conditionNames = conditionValue.GetAllKeys();

    std::unique_lock<std::shared_mutex> lock(this->rwLock_);
    std::string prepareSql = CreateUpdatePrepareSqlCmd(modifyNames, conditionNames);
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
            "Update table failed, errCode is %{public}d, errMsg is %{public}s.", ret, SpitError().c_str());
        return PrivacyError::ERR_DATABASE_OPERATE_FAILED;
    }

    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(PRI_DOMAIN, PRI_TAG, "Update cost %{public}" PRId64 ".", endTime - beginTime);

    return SUCCESS;
}

std::string RemotePermissionUsedRecordDb::CreateInsertPrepareSqlCmd() const
{
    std::string sql = "insert into " + REMOTE_PERMISSION_RECORD_TABLE + " values(";
    int32_t i = 1;
    for (const auto& name : g_tableColumnNames) {
        sql.append(":" + name);
        if (i < static_cast<int32_t>(g_tableColumnNames.size())) {
            sql.append(",");
        }
        i += 1;
    }
    sql.append(")");
    return sql;
}

std::string RemotePermissionUsedRecordDb::CreateDeletePrepareSqlCmd(const std::vector<std::string>& columnNames) const
{
    std::string sql = "delete from " + REMOTE_PERMISSION_RECORD_TABLE + WHERE_1_STR;
    for (const auto& name : columnNames) {
        sql.append(" and ");
        sql.append(name + "=:" + name);
    }
    return sql;
}

std::string RemotePermissionUsedRecordDb::CreateUpdatePrepareSqlCmd(
    const std::vector<std::string>& modifyColumns, const std::vector<std::string>& conditionColumns) const
{
    if (modifyColumns.empty()) {
        return std::string();
    }

    std::string sql = "update " + REMOTE_PERMISSION_RECORD_TABLE + " set ";
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

std::string RemotePermissionUsedRecordDb::CreateSelectByConditionPrepareSqlCmd(
    const std::set<int32_t>& opCodeList, const std::vector<std::string>& andColumns, int32_t databaseQueryCount) const
{
    std::string sql = "select * from " + REMOTE_PERMISSION_RECORD_TABLE + WHERE_1_STR;

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

std::string RemotePermissionUsedRecordDb::CreateCountPrepareSqlCmd() const
{
    std::string sql = "select count(*) from " + REMOTE_PERMISSION_RECORD_TABLE;
    return sql;
}

std::string RemotePermissionUsedRecordDb::CreateDeleteExpireRecordsPrepareSqlCmd(
    const std::vector<std::string>& andColumns) const
{
    std::string sql = "delete from " + REMOTE_PERMISSION_RECORD_TABLE + " where ";
    sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
    sql.append(" in (select ");
    sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
    sql.append(" from " + REMOTE_PERMISSION_RECORD_TABLE + WHERE_1_STR);
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

std::string RemotePermissionUsedRecordDb::CreateDeleteExcessiveRecordsPrepareSqlCmd(uint32_t excessiveSize) const
{
    std::string sql = "delete from " + REMOTE_PERMISSION_RECORD_TABLE + " where ";
    sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
    sql.append(" in (select ");
    sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
    sql.append(" from " + REMOTE_PERMISSION_RECORD_TABLE + " order by ");
    sql.append(PrivacyFiledConst::FIELD_TIMESTAMP);
    sql.append(" limit ");
    sql.append(std::to_string(excessiveSize) + " )");
    return sql;
}

int32_t RemotePermissionUsedRecordDb::CreateRemotePermissionRecordTable() const
{
    std::string sql = CREATE_TABLE_STR;
    sql.append(REMOTE_PERMISSION_RECORD_TABLE + " (")
        .append(PrivacyFiledConst::FIELD_DEVICE_ID)
        .append(TEXT_STR)
        .append(PrivacyFiledConst::FIELD_DEVICE_NAME)
        .append(TEXT_STR)
        .append(PrivacyFiledConst::FIELD_OP_CODE)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_TIMESTAMP)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_ACCESS_COUNT)
        .append(INTEGER_STR)
        .append(PrivacyFiledConst::FIELD_REJECT_COUNT)
        .append(INTEGER_STR)
        .append("primary key(")
        .append(PrivacyFiledConst::FIELD_DEVICE_ID)
        .append(",")
        .append(PrivacyFiledConst::FIELD_DEVICE_NAME)
        .append(",")
        .append(PrivacyFiledConst::FIELD_OP_CODE)
        .append(",")
        .append(PrivacyFiledConst::FIELD_TIMESTAMP)
        .append("))");
    return ExecuteSql(sql);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
