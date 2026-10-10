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

#ifndef ACCESS_TOKEN_RDB_STORE_H
#define ACCESS_TOKEN_RDB_STORE_H

#include <memory>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

#include "access_token.h"

#include "rdb_predicates.h"
#include "result_set.h"
#include "transaction.h"
#include "values_bucket.h"

namespace OHOS {
namespace NativeRdb {
enum SecurityLevel {
    S3 = 3,
};

enum HAMode {
    MAIN_REPLICA = 0,
};

enum RdbErrorCode {
    E_OK = 0,
    E_SQLITE_CORRUPT = 1,
};

enum ColumnType {
    TYPE_INTEGER,
    TYPE_STRING,
    TYPE_BLOB,
};

class ValueObject {
public:
    enum TypeId {
        TYPE_INT,
        TYPE_STRING,
        TYPE_BLOB,
    };

    ValueObject() = default;
    explicit ValueObject(int32_t val) : type_(TYPE_INT), intVal_(static_cast<int64_t>(val)) {}
    explicit ValueObject(int64_t val) : type_(TYPE_INT), intVal_(val) {}
    explicit ValueObject(std::string val) : type_(TYPE_STRING), strVal_(std::move(val)) {}
    explicit ValueObject(const std::vector<uint8_t>& blob) : type_(TYPE_BLOB), blobVal_(blob) {}
    TypeId GetType() const { return type_; }
    int GetInt(int32_t& val) const
    {
        if (type_ != TYPE_INT) {
            return 1;
        }
        val = static_cast<int32_t>(intVal_);
        return 0;
    }
    int GetLong(int64_t& val) const
    {
        if (type_ != TYPE_INT) {
            return 1;
        }
        val = intVal_;
        return 0;
    }
    int GetString(std::string& val) const
    {
        if (type_ != TYPE_STRING) {
            return 1;
        }
        val = strVal_;
        return 0;
    }
    int GetBlob(std::vector<uint8_t>& val) const
    {
        if (type_ != TYPE_BLOB) {
            return 1;
        }
        val = blobVal_;
        return 0;
    }

private:
    TypeId type_ = TYPE_INT;
    int64_t intVal_ = 0;
    std::string strVal_;
    std::vector<uint8_t> blobVal_;
};

class ValuesBucket {
public:
    bool IsEmpty();
    void PutString(std::string a, std::string b);
    void PutInt(std::string a, int32_t b);
    void PutLong(std::string a, int64_t b);
    void PutBlob(std::string a, std::vector<uint8_t> b);

private:
    bool isEmpty_ = true;
};

class ResultSet {
public:
    int32_t GetRowCount(int32_t a);
    void Close();
    int32_t GoToNextRow();
    void GetAllColumnNames(std::vector<std::string>& a);
    void GetColumnIndex(std::string a, int32_t& b);
    void GetColumnType(int32_t a, NativeRdb::ColumnType& b);
    void GetInt(int32_t a, int32_t& b);
    void GetLong(int32_t a, int64_t& b);
    void GetString(int32_t a, std::string& b);
    void GetBlob(int32_t a, std::vector<uint8_t>& b);
    std::pair<int32_t, std::vector<std::string>> GetWholeColumnNames();
    std::pair<int32_t, std::vector<std::vector<NativeRdb::ValueObject>>> GetRowsData(int32_t maxCount,
        int32_t position);

    std::vector<std::string> columnNames_;
    NativeRdb::ColumnType columnType_ = TYPE_INTEGER;
    std::vector<uint8_t> blobData_;
    std::vector<std::vector<std::string>> rowData_;
    size_t currentRowIndex_ = 0;
    std::vector<std::vector<NativeRdb::ValueObject>> rowsData_;
    size_t rowsIndex_ = 0;
    int32_t rowsDataErr_ = 0;
    int32_t columnNamesErr_ = 0;
};

typedef ResultSet AbsSharedResultSet;

class RdbPredicates {
public:
    RdbPredicates();
    explicit RdbPredicates(std::string a);
    std::string GetTableName() const;
    void EqualTo(std::string a, std::string b);
    void EqualTo(std::string a, int32_t b);
    void In(std::string a, const std::vector<std::string>& b);
    void In(std::string a, const std::vector<ValueObject>& b);
    void In(std::string a, const std::vector<int32_t>& b);
    void And();
    void Or();
    void BeginWrap();
    void EndWrap();
};

class Transaction {
public:
    enum TransactionOperationResult {
        OPERATION_FAIL = 1,
    };
    enum TransactionType {
        DEFERRED,
    };
    int32_t Rollback();
    int32_t Commit();
    std::pair<int32_t, int64_t> BatchInsert(const std::string& a, const std::vector<NativeRdb::ValuesBucket>& b);
    std::pair<int32_t, int32_t> Delete(const NativeRdb::RdbPredicates& a);
    int32_t commitFlag_ = 0;
    int32_t insertFlag_ = 0;
    int32_t deleteFlag_ = 0;
    uint32_t rollbackCount_ = 0;
    int64_t insertRows_ = 1;
};

class RdbStoreConfig {
public:
    RdbStoreConfig();
    explicit RdbStoreConfig(std::string path);
    int SetBundleName(const std::string& bundleName);
    void SetLocalOnly(bool isLocalOnly);
    void SetSecurityLevel(NativeRdb::SecurityLevel level);
    void SetAllowRebuild(bool allow);
    void SetHaMode(NativeRdb::HAMode mode);
    void SetClearMemorySize(int32_t size);
};

class RdbStore {
public:
    enum RdbStoreOperationResult {
        RESULT_FAIL = 1,
        TRANSACTION_NULL = 2,
    };
    RdbStore();
    explicit RdbStore(NativeRdb::RdbStoreConfig& config);
    int32_t Restore(std::string a);
    int32_t Update(int32_t a, const NativeRdb::ValuesBucket& b, const NativeRdb::RdbPredicates& c);
    std::shared_ptr<ResultSet> Query(const NativeRdb::RdbPredicates& a, const std::vector<std::string>& b);
    std::shared_ptr<ResultSet> QueryByStep(const NativeRdb::RdbPredicates& a, const std::vector<std::string>& b,
        bool preCount);
    std::pair<int32_t, std::shared_ptr<OHOS::NativeRdb::Transaction>> CreateTransaction(
        OHOS::NativeRdb::Transaction::TransactionType type);
    int32_t ExecuteSql(const std::string& a);
    std::shared_ptr<ResultSet> QuerySql(const std::string& sql, const std::vector<std::string>& args = {});

    RdbStoreConfig config_;
    int32_t createTransFlag_ = 0;
    int32_t restoreFlag_ = 0;
    int32_t updateFlag_ = 0;
    int32_t queryFlag_ = 0;
    std::vector<int32_t> executeSqlResults_;
    size_t executeSqlIndex_ = 0;
    std::vector<std::string> executedSqls_;
    std::shared_ptr<OHOS::NativeRdb::Transaction> transaction_;
    std::vector<std::string> queryColumnNames_;
    NativeRdb::ColumnType queryColumnType_ = TYPE_INTEGER;
    std::vector<uint8_t> queryBlobData_;
    std::vector<std::vector<std::vector<std::string>>> querySqlResults_;
    size_t querySqlIndex_ = 0;
    std::vector<std::vector<NativeRdb::ValueObject>> queryByStepRowsData_;
    int32_t queryByStepRowsDataErr_ = 0;
    int32_t queryByStepRowsDataErrOnce_ = 0;
    int32_t queryByStepColumnNamesErr_ = 0;
};

class RdbOpenCallback {
public:
    virtual int32_t OnCreate(NativeRdb::RdbStore& rdbStore);
    virtual int32_t OnUpgrade(NativeRdb::RdbStore& rdbStore, int32_t currentVersion, int32_t targetVersion);
};

class RdbHelper {
public:
    static std::shared_ptr<NativeRdb::RdbStore> GetRdbStore(
        NativeRdb::RdbStoreConfig& config, int32_t a, RdbOpenCallback callback, int32_t& res);
};
} // namespace NativeRdb
} // namespace OHOS

#endif // ACCESS_TOKEN_RDB_STORE_H
