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

#include "rdb_store.h"

namespace OHOS {
namespace NativeRdb {
namespace {
static constexpr int32_t INT_ZERO = 0;
static constexpr int32_t INT_ONE = 1;
}

bool ValuesBucket::IsEmpty()
{
    return isEmpty_;
}

void ValuesBucket::PutString(std::string a, std::string b)
{
    isEmpty_ = false;
}

void ValuesBucket::PutInt(std::string a, int32_t b)
{
    isEmpty_ = false;
}

void ValuesBucket::PutLong(std::string a, int64_t b)
{
    isEmpty_ = false;
}

void ValuesBucket::PutBlob(std::string a, std::vector<uint8_t> b)
{
    isEmpty_ = false;
}

int32_t ResultSet::GetRowCount(int32_t a)
{
    return NativeRdb::E_OK;
}

void ResultSet::Close()
{}

int32_t ResultSet::GoToNextRow()
{
    if (currentRowIndex_ < rowData_.size()) {
        currentRowIndex_++;
        return NativeRdb::E_OK;
    }
    return NativeRdb::E_SQLITE_CORRUPT;
}

void ResultSet::GetAllColumnNames(std::vector<std::string>& a)
{
    a = columnNames_;
}

void ResultSet::GetColumnIndex(std::string a, int32_t& b)
{}

void ResultSet::GetColumnType(int32_t a, NativeRdb::ColumnType& b)
{
    b = columnType_;
}

void ResultSet::GetInt(int32_t a, int32_t& b)
{}

void ResultSet::GetLong(int32_t a, int64_t& b)
{}

void ResultSet::GetString(int32_t a, std::string& b)
{
    if (currentRowIndex_ > 0 && currentRowIndex_ <= rowData_.size() &&
        a < static_cast<int32_t>(rowData_[currentRowIndex_ - 1].size())) {
        b = rowData_[currentRowIndex_ - 1][a];
    }
}

void ResultSet::GetBlob(int32_t a, std::vector<uint8_t>& b)
{
    b = blobData_;
}

RdbPredicates::RdbPredicates()
{}

RdbPredicates::RdbPredicates(std::string a)
{}

std::string RdbPredicates::GetTableName() const
{
    return "123";
}

void RdbPredicates::EqualTo(std::string a, std::string b)
{}

void RdbPredicates::EqualTo(std::string a, int32_t b)
{}

void RdbPredicates::In(std::string a, const std::vector<std::string>& b)
{}

void RdbPredicates::In(std::string a, const std::vector<ValueObject>& b)
{}

void RdbPredicates::In(std::string a, const std::vector<int32_t>& b)
{}

void RdbPredicates::And()
{}

void RdbPredicates::Or()
{}

void RdbPredicates::BeginWrap()
{}

void RdbPredicates::EndWrap()
{}

int32_t Transaction::Rollback()
{
    return NativeRdb::E_OK;
}

int32_t Transaction::Commit()
{
    if (commitFlag_ == Transaction::TransactionOperationResult::OPERATION_FAIL) {
        return NativeRdb::E_SQLITE_CORRUPT;
    }
    return NativeRdb::E_OK;
}

std::pair<int32_t, int64_t> Transaction::BatchInsert(
    const std::string& a, const std::vector<NativeRdb::ValuesBucket>& b)
{
    if (insertFlag_ == Transaction::TransactionOperationResult::OPERATION_FAIL) {
        return std::make_pair(NativeRdb::E_SQLITE_CORRUPT, INT_ZERO);
    }
    return std::make_pair(NativeRdb::E_OK, insertRows_);
}

std::pair<int32_t, int32_t> Transaction::Delete(const NativeRdb::RdbPredicates& a)
{
    if (deleteFlag_ == Transaction::TransactionOperationResult::OPERATION_FAIL) {
        return std::make_pair(NativeRdb::E_SQLITE_CORRUPT, INT_ZERO);
    }
    return std::make_pair(NativeRdb::E_OK, INT_ONE);
}

std::pair<int32_t, int32_t> Transaction::Update(
    const NativeRdb::ValuesBucket& row, const NativeRdb::RdbPredicates& predicates)
{
    if (updateFlag_ == Transaction::TransactionOperationResult::OPERATION_FAIL) {
        return std::make_pair(NativeRdb::E_SQLITE_CORRUPT, INT_ZERO);
    }
    return std::make_pair(NativeRdb::E_OK, INT_ONE);
}

RdbStoreConfig::RdbStoreConfig()
{}

RdbStoreConfig::RdbStoreConfig(std::string path)
{}

void RdbStoreConfig::SetSecurityLevel(NativeRdb::SecurityLevel level)
{}

void RdbStoreConfig::SetAllowRebuild(bool allow)
{}

void RdbStoreConfig::SetHaMode(NativeRdb::HAMode mode)
{}

void RdbStoreConfig::SetClearMemorySize(int32_t size)
{}

RdbStore::RdbStore()
{}

RdbStore::RdbStore(NativeRdb::RdbStoreConfig& config)
{
    config_ = config;
}

int32_t RdbStore::Restore(std::string a)
{
    if (restoreFlag_ == RdbStore::RdbStoreOperationResult::RESULT_FAIL) {
        return NativeRdb::E_SQLITE_CORRUPT;
    }
    return NativeRdb::E_OK;
}

int32_t RdbStore::Update(int32_t a, const NativeRdb::ValuesBucket& b, const NativeRdb::RdbPredicates& c)
{
    if (updateFlag_ == RdbStore::RdbStoreOperationResult::RESULT_FAIL) {
        return NativeRdb::E_SQLITE_CORRUPT;
    }
    return NativeRdb::E_OK;
}

std::shared_ptr<ResultSet> RdbStore::Query(const NativeRdb::RdbPredicates& a, const std::vector<std::string>& b)
{
    if (queryFlag_ == RdbStore::RdbStoreOperationResult::RESULT_FAIL) {
        return nullptr;
    }
    auto rs = std::make_shared<ResultSet>();
    return rs;
}

std::pair<int32_t, std::shared_ptr<OHOS::NativeRdb::Transaction>> RdbStore::CreateTransaction(
    OHOS::NativeRdb::Transaction::TransactionType type)
{
    if (createTransFlag_ == RdbStore::RdbStoreOperationResult::RESULT_FAIL) {
        return std::make_pair(NativeRdb::E_SQLITE_CORRUPT, nullptr);
    }
    if (createTransFlag_ == RdbStore::RdbStoreOperationResult::TRANSACTION_NULL) {
        return std::make_pair(NativeRdb::E_OK, nullptr);
    }
    if (transaction_ == nullptr) {
        transaction_ = std::make_shared<OHOS::NativeRdb::Transaction>();
    }
    return std::make_pair(NativeRdb::E_OK, transaction_);
}

int32_t RdbStore::ExecuteSql(const std::string& a)
{
    if (executeSqlIndex_ < executeSqlResults_.size()) {
        return executeSqlResults_[executeSqlIndex_++];
    }
    return NativeRdb::E_OK;
}

std::shared_ptr<ResultSet> RdbStore::QuerySql(const std::string& sql, const std::vector<std::string>& args)
{
    if (queryFlag_ == RdbStore::RdbStoreOperationResult::RESULT_FAIL) {
        return nullptr;
    }
    auto rs = std::make_shared<ResultSet>();
    rs->columnNames_ = queryColumnNames_;
    rs->columnType_ = queryColumnType_;
    rs->blobData_ = queryBlobData_;
    if (querySqlIndex_ < querySqlResults_.size()) {
        rs->rowData_ = querySqlResults_[querySqlIndex_++];
    }
    return rs;
}

int32_t RdbOpenCallback::OnCreate(NativeRdb::RdbStore& rdbStore)
{
    return NativeRdb::E_OK;
}

int32_t RdbOpenCallback::OnUpgrade(NativeRdb::RdbStore& rdbStore, int32_t currentVersion, int32_t targetVersion)
{
    return NativeRdb::E_OK;
}

std::shared_ptr<NativeRdb::RdbStore> RdbHelper::GetRdbStore(
    NativeRdb::RdbStoreConfig& config, int32_t a, RdbOpenCallback callback, int32_t& res)
{
    res = NativeRdb::E_OK;
#ifdef GET_RDB_NULLPTR
    return nullptr;
#else
    return std::make_shared<NativeRdb::RdbStore>(config);
#endif
}
} // namespace NativeRdb
} // namespace OHOS
