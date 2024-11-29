/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "accesstoken_log.h"
#include "access_token_error.h"
#include "access_token_open_callback.h"
#include "rdb_helper.h"
#include "time_util.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenDb"};

constexpr const char* DATABASE_NAME = "access_token.db";
constexpr const char* ACCESSTOKEN_SERVICE_NAME = "accesstoken_service";
std::recursive_mutex g_instanceMutex;
}

AccessTokenDb& AccessTokenDb::GetInstance()
{
    static AccessTokenDb* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(g_instanceMutex);
        if (instance == nullptr) {
            instance = new AccessTokenDb();
        }
    }
    return *instance;
}

AccessTokenDb::AccessTokenDb()
{
    InitRdb();
}

int32_t AccessTokenDb::RestoreAndInsertIfCorrupt(const int32_t resultCode, int64_t& outInsertNum,
    const std::string& tableName, const std::vector<NativeRdb::ValuesBucket>& buckets,
    const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    if (resultCode != NativeRdb::E_SQLITE_CORRUPT) {
        return resultCode;
    }

    ACCESSTOKEN_LOG_WARN(LABEL, "Detech database corrupt, restore from backup!");
    int32_t res = db->Restore("");
    if (res != NativeRdb::E_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Db restore failed, res is %{public}d.", res);
        return res;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Database restore success, try insert again!");

    res = db->BatchInsert(outInsertNum, tableName, buckets);
    if (res != NativeRdb::E_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to batch insert into table %{public}s again, res is %{public}d.",
            tableName.c_str(), res);
        return res;
    }

    return 0;
}

void AccessTokenDb::InitRdb()
{
    std::string dbPath = std::string(DATABASE_PATH) + std::string(DATABASE_NAME);
    NativeRdb::RdbStoreConfig config(dbPath);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S3);
    config.SetAllowRebuild(true);
    config.SetHaMode(NativeRdb::HAMode::MAIN_REPLICA); // Real-time dual-write backup database
    config.SetServiceName(std::string(ACCESSTOKEN_SERVICE_NAME));
    AccessTokenOpenCallback callback;
    int32_t res = NativeRdb::E_OK;
    // pragma user_version will done by rdb, they store path and db_ as pair in RdbStoreManager
    db_ = NativeRdb::RdbHelper::GetRdbStore(config, DATABASE_VERSION_4, callback, res);
    if ((res != NativeRdb::E_OK) || (db_ == nullptr)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to init rdb, res is %{public}d.", res);
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

int32_t AccessTokenDb::Add(const AtmDataType type, const std::vector<GenericValues>& values)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(type, tableName);
    if (tableName.empty()) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    size_t addSize = values.size();
    if (addSize == 0) {
        return 0;
    }

    std::vector<NativeRdb::ValuesBucket> buckets;
    AccessTokenDbUtil::ToRdbValueBuckets(values, buckets);

    int64_t outInsertNum = 0;
    {
        OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
        auto db = GetRdb();
        if (db == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "db is nullptr.");
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }
        int32_t res = db->BatchInsert(outInsertNum, tableName, buckets);
        if (res != NativeRdb::E_OK) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to batch insert into table %{public}s, res is %{public}d.",
                tableName.c_str(), res);
            int32_t result = RestoreAndInsertIfCorrupt(res, outInsertNum, tableName, buckets, db);
            if (result != NativeRdb::E_OK) {
                return result;
            }
        }
    }

    if (outInsertNum <= 0) { // this is rdb bug, adapt it
        ACCESSTOKEN_LOG_ERROR(LABEL, "Insert count %{public}" PRId64 " abnormal.", outInsertNum);
        return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
    }

    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    ACCESSTOKEN_LOG_INFO(LABEL, "Add cost %{public}" PRId64 ", batch insert %{public}" PRId64
        " records to table %{public}s.", endTime - beginTime, outInsertNum, tableName.c_str());

    return 0;
}

int32_t AccessTokenDb::RestoreAndDeleteIfCorrupt(const int32_t resultCode, int32_t& deletedRows,
    const NativeRdb::RdbPredicates& predicates, const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    if (resultCode != NativeRdb::E_SQLITE_CORRUPT) {
        return resultCode;
    }

    ACCESSTOKEN_LOG_WARN(LABEL, "Detech database corrupt, restore from backup!");
    int32_t res = db->Restore("");
    if (res != NativeRdb::E_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Db restore failed, res is %{public}d.", res);
        return res;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Database restore success, try delete again!");

    res = db->Delete(deletedRows, predicates);
    if (res != NativeRdb::E_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to delete record from table %{public}s again, res is %{public}d.",
            predicates.GetTableName().c_str(), res);
        return res;
    }

    return 0;
}

int32_t AccessTokenDb::Remove(const AtmDataType type, const GenericValues& conditionValue)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();
    std::string tableName;
    AccessTokenDbUtil::GetTableNameByType(type, tableName);
    if (tableName.empty()) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    NativeRdb::RdbPredicates predicates(tableName);
    AccessTokenDbUtil::ToRdbPredicates(conditionValue, predicates);

    int32_t deletedRows = 0;
    {
        OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
        auto db = GetRdb();
        if (db == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "db is nullptr.");
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }

        int32_t res = db->Delete(deletedRows, predicates);
        if (res != NativeRdb::E_OK) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to delete record from table %{public}s, res is %{public}d.",
                tableName.c_str(), res);
            int32_t result = RestoreAndDeleteIfCorrupt(res, deletedRows, predicates, db);
            if (result != NativeRdb::E_OK) {
                return result;
            }
        }
    }

    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    ACCESSTOKEN_LOG_INFO(LABEL, "Remove cost %{public}" PRId64
        ", delete %{public}d records from table %{public}s.", endTime - beginTime, deletedRows, tableName.c_str());

    return 0;
}

int32_t AccessTokenDb::RestoreAndUpdateIfCorrupt(const int32_t resultCode, int32_t& changedRows,
    const NativeRdb::ValuesBucket& bucket, const NativeRdb::RdbPredicates& predicates,
    const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    if (resultCode != NativeRdb::E_SQLITE_CORRUPT) {
        return resultCode;
    }

    ACCESSTOKEN_LOG_WARN(LABEL, "Detech database corrupt, restore from backup!");
    int32_t res = db->Restore("");
    if (res != NativeRdb::E_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Db restore failed, res is %{public}d.", res);
        return res;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Database restore success, try update again!");

    res = db->Update(changedRows, bucket, predicates);
    if (res != NativeRdb::E_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to update record from table %{public}s again, res is %{public}d.",
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
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    NativeRdb::ValuesBucket bucket;

    AccessTokenDbUtil::ToRdbValueBucket(modifyValue, bucket);
    if (bucket.IsEmpty()) {
        return AccessTokenError::ERR_PARAM_INVALID;
    }

    NativeRdb::RdbPredicates predicates(tableName);
    AccessTokenDbUtil::ToRdbPredicates(conditionValue, predicates);

    int32_t changedRows = 0;
    {
        OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
        auto db = GetRdb();
        if (db == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "db is nullptr.");
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }

        int32_t res = db->Update(changedRows, bucket, predicates);
        if (res != NativeRdb::E_OK) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to update record from table %{public}s, res is %{public}d.",
                tableName.c_str(), res);
            int32_t result = RestoreAndUpdateIfCorrupt(res, changedRows, bucket, predicates, db);
            if (result != NativeRdb::E_OK) {
                return result;
            }
        }
    }

    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    ACCESSTOKEN_LOG_INFO(LABEL, "Modify cost %{public}" PRId64
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

            ACCESSTOKEN_LOG_WARN(LABEL, "Detech database corrupt, restore from backup!");
            res = db->Restore("");
            if (res != NativeRdb::E_OK) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Db restore failed, res is %{public}d.", res);
                return res;
            }
            ACCESSTOKEN_LOG_INFO(LABEL, "Database restore success, try query again!");

            queryResultSet = db->Query(predicates, columns);
            if (queryResultSet == nullptr) {
                ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to find records from table %{public}s again.",
                    predicates.GetTableName().c_str());
                return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
            }
        } else {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to get result count.");
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
        OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
        auto db = GetRdb();
        if (db == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "db is nullptr.");
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }

        auto queryResultSet = db->Query(predicates, columns);
        if (queryResultSet == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to find records from table %{public}s.",
                tableName.c_str());
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }

        int32_t res = RestoreAndQueryIfCorrupt(predicates, columns, queryResultSet, db);
        if (res != 0) {
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
    ACCESSTOKEN_LOG_INFO(LABEL, "Find cost %{public}" PRId64
        ", query %{public}d records from table %{public}s.", endTime - beginTime, count, tableName.c_str());

    return 0;
}

int32_t AccessTokenDb::DeleteAndAddSingleTable(const GenericValues delCondition, const std::string& tableName,
    const std::vector<GenericValues>& addValues, const std::shared_ptr<NativeRdb::RdbStore>& db)
{
    NativeRdb::RdbPredicates predicates(tableName);
    AccessTokenDbUtil::ToRdbPredicates(delCondition, predicates); // fill predicates with delCondition
    int32_t deletedRows = 0;
    int32_t res = db->Delete(deletedRows, predicates);
    if (res != NativeRdb::E_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to delete record from table %{public}s, res is %{public}d.",
            tableName.c_str(), res);
        int32_t result = RestoreAndDeleteIfCorrupt(res, deletedRows, predicates, db);
        if (result != NativeRdb::E_OK) {
            return result;
        }
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Delete %{public}d record from table %{public}s", deletedRows, tableName.c_str());

    // if nothing to insert, no need to BatchInsert
    if (addValues.empty()) {
        return 0;
    }

    std::vector<NativeRdb::ValuesBucket> buckets;
    AccessTokenDbUtil::ToRdbValueBuckets(addValues, buckets); // fill buckets with addValues
    int64_t outInsertNum = 0;
    res = db->BatchInsert(outInsertNum, tableName, buckets);
    if (res != NativeRdb::E_OK) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Failed to batch insert into table %{public}s, res is %{public}d.",
            tableName.c_str(), res);
        int32_t result = RestoreAndInsertIfCorrupt(res, outInsertNum, tableName, buckets, db);
        if (result != NativeRdb::E_OK) {
            return result;
        }
    }
    if (outInsertNum <= 0) { // rdb bug, adapt it
        ACCESSTOKEN_LOG_ERROR(LABEL, "Insert count %{public}" PRId64 " abnormal.", outInsertNum);
        return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Batch insert %{public}" PRId64 " records to table %{public}s.", outInsertNum,
        tableName.c_str());

    return 0;
}

int32_t AccessTokenDb::DeleteAndAddRecord(AccessTokenID tokenId, const std::vector<GenericValues>& hapInfoValues,
    const std::vector<GenericValues>& permDefValues, const std::vector<GenericValues>& permStateValues)
{
    GenericValues conditionValue;
    conditionValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));

    std::string hapTableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_HAP_INFO, hapTableName);
    auto db = GetRdb();
    if (db == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "db is nullptr.");
        return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
    }
    int32_t res = DeleteAndAddSingleTable(conditionValue, hapTableName, hapInfoValues, db);
    if (res != NativeRdb::E_OK) {
        return res;
    }

    std::string defTableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_PERMISSION_DEF, defTableName);
    res = DeleteAndAddSingleTable(conditionValue, defTableName, permDefValues, db);
    if (res != NativeRdb::E_OK) {
        return res;
    }

    std::string stateTableName;
    AccessTokenDbUtil::GetTableNameByType(AtmDataType::ACCESSTOKEN_PERMISSION_STATE, stateTableName);
    return DeleteAndAddSingleTable(conditionValue, stateTableName, permStateValues, db);
}

int32_t AccessTokenDb::DeleteAndInsertHap(AccessTokenID tokenId, const std::vector<GenericValues>& hapInfoValues,
    const std::vector<GenericValues>& permDefValues, const std::vector<GenericValues>& permStateValues)
{
    int64_t beginTime = TimeUtil::GetCurrentTimestamp();

    {
        OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> lock(this->rwLock_);
        auto db = GetRdb();
        if (db == nullptr) {
            ACCESSTOKEN_LOG_ERROR(LABEL, "db is nullptr.");
            return AccessTokenError::ERR_DATABASE_OPERATE_FAILED;
        }

        db->BeginTransaction();

        int32_t res = DeleteAndAddRecord(tokenId, hapInfoValues, permDefValues, permStateValues);
        if (res != NativeRdb::E_OK) {
            db->RollBack();
            return res;
        }

        db->Commit();
    }

    int64_t endTime = TimeUtil::GetCurrentTimestamp();
    ACCESSTOKEN_LOG_ERROR(LABEL, "DeleteAndInsertHap cost %{public}" PRId64 ".", endTime - beginTime);

    return 0;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
