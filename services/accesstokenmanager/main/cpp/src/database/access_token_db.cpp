/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "access_token_db.h"

#include <algorithm>
#include <cinttypes>
#include <mutex>

#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "access_token_open_callback.h"
#include "hisysevent_adapter.h"
#include "rdb_helper.h"
#include "time_util.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* DATABASE_NAME = "access_token.db";
static constexpr int32_t ACCESSTOKEN_CLEAR_MEMORY_SIZE = 4;
}

AccessTokenDb::AccessTokenDb()
{
    InitRdb();
}

AccessTokenDb::~AccessTokenDb()
{
    db_ = nullptr;
    LOGI(ATM_DOMAIN, ATM_TAG, "~AccessTokenDb");
}

void AccessTokenDb::InitRdb()
{
    std::string dbPath = std::string(DATABASE_PATH) + std::string(DATABASE_NAME);
    NativeRdb::RdbStoreConfig config(dbPath);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S3);
    config.SetAllowRebuild(true);
    config.SetHaMode(NativeRdb::HAMode::MAIN_REPLICA); // Real-time dual-write backup database
    config.SetClearMemorySize(ACCESSTOKEN_CLEAR_MEMORY_SIZE);
    AccessTokenOpenCallback callback;
    int32_t res = NativeRdb::E_OK;
    // pragma user_version will done by rdb, they store path and db_ as pair in RdbStoreManager
    db_ = NativeRdb::RdbHelper::GetRdbStore(config, DATABASE_VERSION_6, callback, res);
    if ((res != NativeRdb::E_OK) || (db_ == nullptr)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to init rdb, res is %{public}d.", res);
    }
}

std::shared_ptr<NativeRdb::RdbStore> AccessTokenDb::GetRdb()
{
    std::lock_guard<std::mutex> lock(dbLock_);
    if (db_ == nullptr) {
        InitRdb();
    }
    return db_;
}

int32_t AccessTokenDb::RestoreAndUpdateIfCorrupt(const int32_t resultCode, int32_t& changedRows,
    const NativeRdb::ValuesBucket& bucket, const NativeRdb::RdbPredicates& predicates,
    const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    if (resultCode != NativeRdb::E_SQLITE_CORRUPT) {
        return resultCode;
    }

    LOGW(ATM_DOMAIN, ATM_TAG, "Detech database corrupt, restore from backup!");
    int32_t res = db->Restore("");
    if (res != NativeRdb::E_OK) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Db restore failed, res is %{public}d.", res);
        return res;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Database restore success, try update again!");

    res = db->Update(changedRows, bucket, predicates);
    if (res != NativeRdb::E_OK) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Failed to update record from table %{public}s again, res is %{public}d.",
            predicates.GetTableName().c_str(), res);
        return res;
    }

    return 0;
}

int32_t AccessTokenDb::Modify(const AtmDataType type, const GenericValues& modifyValue,
    const GenericValues& conditionValue)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(type, tableName);
    if (tableName.empty()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Get table name failed, type=%{public}d!", static_cast<int32_t>(type));
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    NativeRdb::ValuesBucket bucket;

    AccessTokenDbUtil::ToRdbValueBucket(modifyValue, bucket);
    if (bucket.IsEmpty()) {
        LOGC(ATM_DOMAIN, ATM_TAG, "To rdb value bucket failed!");
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    NativeRdb::RdbPredicates predicates(tableName);
    AccessTokenDbUtil::ToRdbPredicates(conditionValue, predicates);

    int32_t changedRows = 0;
    {
        std::unique_lock<std::shared_mutex> lock(this->rwLock_);
        auto db = GetRdb();
        if (db == nullptr) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Db is nullptr.");
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }

        int32_t res = db->Update(changedRows, bucket, predicates);
        if (res != NativeRdb::E_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to update record from table %{public}s, res is %{public}d.",
                tableName.c_str(), res);
            ReportSysEventDbException(AccessTokenDbSceneCode::AT_DB_UPDATE_RESTORE, res, tableName);
            int32_t result = RestoreAndUpdateIfCorrupt(res, changedRows, bucket, predicates, db);
            if (result != NativeRdb::E_OK) {
                LOGC(ATM_DOMAIN, ATM_TAG, "Failed to restore and update, result is %{public}d.", result);
                return result;
            }
        }
    }

    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(ATM_DOMAIN, ATM_TAG, "Modify cost %{public}" PRId64
        ", update %{public}d records from table %{public}s.", endTime - beginTime, changedRows, tableName.c_str());

    return 0;
}

int32_t AccessTokenDb::RestoreAndQueryIfCorrupt(const NativeRdb::RdbPredicates& predicates,
    const std::vector<std::string>& columns, std::shared_ptr<NativeRdb::AbsSharedResultSet>& queryResultSet,
    const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    int32_t count = 0;
    int32_t res = queryResultSet->GetRowCount(count);
    if (res != NativeRdb::E_OK) {
        if (res == NativeRdb::E_SQLITE_CORRUPT) {
            queryResultSet->Close();
            queryResultSet = nullptr;

            LOGW(ATM_DOMAIN, ATM_TAG, "Detech database corrupt, restore from backup!");
            ReportSysEventDbException(AccessTokenDbSceneCode::AT_DB_QUERY_RESTORE, res, predicates.GetTableName());
            res = db->Restore("");
            if (res != NativeRdb::E_OK) {
                LOGC(ATM_DOMAIN, ATM_TAG, "Db restore failed, res is %{public}d.", res);
                return res;
            }
            LOGI(ATM_DOMAIN, ATM_TAG, "Database restore success, try query again!");

            queryResultSet = db->Query(predicates, columns);
            if (queryResultSet == nullptr) {
                LOGC(ATM_DOMAIN, ATM_TAG, "Failed to find records from table %{public}s again.",
                    predicates.GetTableName().c_str());
                return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
            }
        } else {
            LOGC(ATM_DOMAIN, ATM_TAG, "Failed to get result count.");
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }
    }

    return 0;
}

int32_t AccessTokenDb::Find(AtmDataType type, const GenericValues& conditionValue,
    std::vector<GenericValues>& results)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(type, tableName);
    if (tableName.empty()) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    NativeRdb::RdbPredicates predicates(tableName);
    AccessTokenDbUtil::ToRdbPredicates(conditionValue, predicates);

    std::vector<std::string> columns; // empty columns means query all columns
    int count = 0;
    {
        std::shared_lock<std::shared_mutex> lock(this->rwLock_);
        auto db = GetRdb();
        if (db == nullptr) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Db is nullptr.");
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }

        auto queryResultSet = db->Query(predicates, columns);
        if (queryResultSet == nullptr) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Failed to find records from table %{public}s.",
                tableName.c_str());
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }

        int32_t res = RestoreAndQueryIfCorrupt(predicates, columns, queryResultSet, db);
        if (res != 0) {
            LOGC(ATM_DOMAIN, ATM_TAG, "Restore and query failed!");
            return res;
        }

        while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
            GenericValues value;
            AccessTokenDbUtil::ResultToGenericValues(queryResultSet, value);
            if (value.GetAllKeys().empty()) {
                continue;
            }

            results.emplace_back(value);
            count++;
        }
    }

    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(ATM_DOMAIN, ATM_TAG, "Find cost %{public}" PRId64
        ", query %{public}d records from table %{public}s.", endTime - beginTime, count, tableName.c_str());

    return 0;
}

int32_t AccessTokenDb::DeleteAndInsertValues(const std::vector<DelInfo>& delInfoVec,
    const std::vector<AddInfo>& addInfoVec)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();
    int res = 0;
    {
        std::unique_lock<std::shared_mutex> lock(this->rwLock_);
        res = DeleteAndInsertValuesInner(delInfoVec, addInfoVec);
        if (res != NativeRdb::E_OK) {
            RestoreDatabase(res);
            res = DeleteAndInsertValuesInner(delInfoVec, addInfoVec);
        }
    }
    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    LOGI(ATM_DOMAIN, ATM_TAG, "DeleteAndInsertValues cost %{public}" PRId64 ".", endTime - beginTime);
    return res;
}

int32_t AccessTokenDb::DeleteAndInsertValuesInner(const std::vector<DelInfo>& delInfoVec,
    const std::vector<AddInfo>& addInfoVec)
{
    std::shared_ptr<NativeRdb::RdbStore> db = GetRdb();
    if (db == nullptr) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Db is nullptr.");
        return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
    }

    auto [errcode, transaction] = db->CreateTransaction(OHOS::NativeRdb::Transaction::DEFERRED);
    if (errcode != NativeRdb::E_OK || transaction == nullptr) {
        LOGC(ATM_DOMAIN, ATM_TAG, "CreateTransaction failed, error:0x%{public}x", errcode);
        return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
    }

    int32_t res = RemoveValues(delInfoVec, transaction);
    if (res != NativeRdb::E_OK) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Remove values failed, res is 0x%{public}x.", res);
        transaction->Rollback();
        return res;
    }

    res = AddValues(addInfoVec, transaction);
    if (res != NativeRdb::E_OK) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Add values failed, res is 0x%{public}x.", res);
        transaction->Rollback();
        return res;
    }

    res = transaction->Commit();
    if (res != NativeRdb::E_OK) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Transaction commit failed, res is 0x%{public}x.", res);
        ReportSysEventDbException(AccessTokenDbSceneCode::AT_DB_COMMIT_RESTORE, res, "");
        transaction->Rollback();
        return res;
    }

    return 0;
}

int32_t AccessTokenDb::AddValues(const std::vector<AddInfo>& addInfoVec,
    const std::shared_ptr<OHOS::NativeRdb::Transaction>& transaction)
{
    size_t count = addInfoVec.size();
    for (size_t i = 0; i < count; ++i) {
        std::string tableName;
        AccessTokenDbUtil::GetTableNameByType(addInfoVec[i].addType, tableName);
        if (tableName.empty()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Table name is empty.");
            return AccessTokenError::ERR_PARAM_INVALID;
        }

        // if nothing to insert, no need to call BatchInsert
        if (addInfoVec[i].addValues.empty()) {
            continue;
        }

        // fill buckets with addInfoVec[i].addValues
        std::vector<NativeRdb::ValuesBucket> buckets;
        AccessTokenDbUtil::ToRdbValueBuckets(addInfoVec[i].addValues, buckets);

        // outInsertNum: int64_t
        auto [errCode, outInsertNum] = transaction->BatchInsert(tableName, buckets);
        if (errCode != NativeRdb::E_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to batch insert into table %{public}s, errCode is 0x%{public}x.",
                tableName.c_str(), errCode);
            ReportSysEventDbException(AccessTokenDbSceneCode::AT_DB_INSERT_RESTORE, errCode, tableName);
            return errCode;
        }

        if (outInsertNum <= 0) { // rdb bug, adapt it
            LOGC(ATM_DOMAIN, ATM_TAG, "Insert count %{public}" PRId64 " abnormal.", outInsertNum);
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }

        LOGI(ATM_DOMAIN, ATM_TAG, "Batch insert %{public}" PRId64 " records to table %{public}s.", outInsertNum,
            tableName.c_str());
    }
    return 0;
}

int32_t AccessTokenDb::RemoveValues(const std::vector<DelInfo>& delInfoVec,
    const std::shared_ptr<OHOS::NativeRdb::Transaction>& transaction)
{
    size_t count = delInfoVec.size();
    for (size_t i = 0; i < count; ++i) {
        std::string tableName;
        AccessTokenDbUtil::GetTableNameByType(delInfoVec[i].delType, tableName);
        if (tableName.empty()) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Table name is empty.");
            return AccessTokenError::ERR_PARAM_INVALID;
        }

        NativeRdb::RdbPredicates predicates(tableName);
        AccessTokenDbUtil::ToRdbPredicates(delInfoVec[i].delValue, predicates);

        auto [errCode, deletedRows] = transaction->Delete(predicates);
        if (errCode != NativeRdb::E_OK) {
            LOGE(ATM_DOMAIN, ATM_TAG, "Failed to delete record from table %{public}s, errCode is 0x%{public}x.",
                tableName.c_str(), errCode);
            ReportSysEventDbException(AccessTokenDbSceneCode::AT_DB_DELETE_RESTORE, errCode, tableName);
            return errCode;
        }

        LOGI(ATM_DOMAIN, ATM_TAG, "Delete %{public}d records from table %{public}s.", deletedRows, tableName.c_str());
    }
    return 0;
}

void AccessTokenDb::RestoreDatabase(int32_t errCode)
{
    if (errCode != NativeRdb::E_SQLITE_CORRUPT) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Not sqlite corrupt, can't restore!");
        return;
    }

    LOGW(ATM_DOMAIN, ATM_TAG, "Detech database corrupt, restore from backup!");
    std::shared_ptr<NativeRdb::RdbStore> db = GetRdb();
    if (db == nullptr) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Db is nullptr.");
        return;
    }

    int32_t res = db->Restore("");
    if (res != NativeRdb::E_OK) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Db restore failed, res is 0x%{public}x.", res);
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
