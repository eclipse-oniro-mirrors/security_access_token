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

#include "sqlite_helper.h"

#include <chrono>
#include <cstdio>
#include <sys/types.h>
#include <thread>

#include "accesstoken_common_log.h"
#include "access_token.h"
#include "data_usage_dfx.h"
#include "sqlite3ext.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t SLEEP_RETRY_MS = 300;
constexpr int32_t MAX_RETRY_COUNT = 1;
}

SqliteHelper::SqliteHelper(const std::string& dbName, const std::string& dbPath, int32_t version)
    : dbName_(dbName), dbPath_(dbPath), currentVersion_(version), db_(nullptr)
{}

SqliteHelper::~SqliteHelper()
{}

int32_t SqliteHelper::ExecuteWithRetry(int32_t sceneCode, const std::function<int32_t()>& action,
    int32_t targetVersion)
{
    for (int32_t attempt = 0; attempt <= MAX_RETRY_COUNT; ++attempt) {
        int32_t ret = BeginTransaction();
        if (ret == RET_SUCCESS) {
            ret = action();
        }
        if (ret == RET_SUCCESS) {
            ret = SetVersion(targetVersion);
        }
        if (ret == RET_SUCCESS) {
            ret = CommitTransaction();
        }
        if (ret == RET_SUCCESS) {
            return RET_SUCCESS;
        }
        int32_t errCode = sqlite3_errcode(db_);
        LOGE(ATM_DOMAIN, ATM_TAG, "Sql execute failed, errCode=%{public}d, errMsg: %{public}s", errCode,
            sqlite3_errmsg(db_));
        ReportDbException(sceneCode, errCode, dbPath_ + dbName_);
        (void)RollbackTransaction();
        if (!IsRetryableError(errCode) || attempt == MAX_RETRY_COUNT) {
            return GENERAL_ERROR;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_RETRY_MS));
    }
    return GENERAL_ERROR;
}

void SqliteHelper::TryOnCreate()
{
    ExecuteWithRetry(DB_CREATE_FAILED, [this]() { return OnCreate(); }, currentVersion_);
}

void SqliteHelper::TryOnUpdate(int32_t version)
{
    for (int32_t v = version; v < currentVersion_; ++v) {
        if (ExecuteWithRetry(DB_UPDATE_FAILED, [this, v]() { return OnUpdate(v); }, v + 1)
            != RET_SUCCESS) {
            break;
        }
    }
}

void SqliteHelper::Open(bool skipCheck) __attribute__((no_sanitize("cfi")))
{
    LOGE(ATM_DOMAIN, ATM_TAG, "Open db enter.");
    if (db_ != nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Db s already open");
        return;
    }
    if (dbName_.empty() || dbPath_.empty() || currentVersion_ < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Param invalid, dbName: %{public}s, dbPath: %{public}s, currentVersion: %{public}d",
            dbName_.c_str(), dbPath_.c_str(), currentVersion_);
        return;
    }
    // set soft heap limit as 10KB
    const int32_t heapLimit = 10 * 1024;
    sqlite3_soft_heap_limit64(heapLimit);
    std::string fileName = dbPath_ + dbName_;
    const uint32_t flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    int32_t res = sqlite3_open_v2(fileName.c_str(), &db_, flags, NULL);
    if (res != SQLITE_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to open db res=%{public}d, msg: %{public}s", res,
            db_ != nullptr ? sqlite3_errmsg(db_) : "null");
        if (db_ != nullptr) {
            sqlite3_close_v2(db_);
            db_ = nullptr;
        }
        if (!skipCheck && IsCorruptCode(res)) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Open failed with corrupt code=%{public}d, rebuild", res);
            (void)Rebuild();
        }
        return;
    }
    sqlite3_busy_timeout(db_, SLEEP_RETRY_MS);
    SetWal();

    if (!skipCheck && NeedRebuild(true)) {
        LOGW(ATM_DOMAIN, ATM_TAG, "integrity_check failed, rebuild!");
        (void)Rebuild();
        return;
    }

    int32_t version = GetVersion();
    if (version == currentVersion_) {
        return;
    }

    if (version == DataBaseVersion::VERISION_0) {
        TryOnCreate();
    } else if (version < currentVersion_) {
        TryOnUpdate(version);
    }
    if (!skipCheck && NeedRebuild(true)) {
        LOGW(ATM_DOMAIN, ATM_TAG, "integrity_check failed after open, rebuild!");
        (void)Rebuild();
    }
}

void SqliteHelper::Close()
{
    if (db_ == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Do open data base first!");
        return;
    }
    int32_t ret = sqlite3_close(db_);
    if (ret != SQLITE_OK) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Sqlite3_close error, ret=%{public}d", ret);
        return;
    }
    db_ = nullptr;
}

int32_t SqliteHelper::BeginTransaction() const
{
    if (db_ == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Do open data base first!");
        return GENERAL_ERROR;
    }
    char* errorMessage = nullptr;
    int32_t result = 0;
    int32_t ret = sqlite3_exec(db_, "BEGIN;", nullptr, nullptr, &errorMessage);
    if (ret != SQLITE_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed, ret=%{public}d errorMsg: %{public}s", ret, errorMessage);
        result = GENERAL_ERROR;
    }
    sqlite3_free(errorMessage);
    return result;
}

int32_t SqliteHelper::CommitTransaction() const
{
    if (db_ == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Do open data base first!");
        return GENERAL_ERROR;
    }
    char* errorMessage = nullptr;
    int32_t result = 0;
    int32_t ret = sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &errorMessage);
    if (ret != SQLITE_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed, ret=%{public}d errorMsg: %{public}s", ret, errorMessage);
        sqlite3_free(errorMessage);
        return GENERAL_ERROR;
    }
    sqlite3_free(errorMessage);
    sqlite3_db_cacheflush(db_);
    return result;
}

int32_t SqliteHelper::RollbackTransaction() const
{
    if (db_ == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Do open data base first!");
        return GENERAL_ERROR;
    }
    int32_t result = 0;
    char* errorMessage = nullptr;
    int32_t ret = sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, &errorMessage);
    if (ret != SQLITE_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed, ret=%{public}d errorMsg: %{public}s", ret, errorMessage);
        result = GENERAL_ERROR;
    }
    sqlite3_free(errorMessage);
    return result;
}

Statement SqliteHelper::Prepare(const std::string& sql) const
{
    return Statement(db_, sql);
}

int32_t SqliteHelper::ExecuteSql(const std::string& sql) const
{
    if (db_ == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Do open data base first!");
        return GENERAL_ERROR;
    }
    char* errorMessage = nullptr;
    int32_t result = 0;
    int32_t res = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errorMessage);
    if (res != SQLITE_OK) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed, res=%{public}d errorMsg: %{public}s", res, errorMessage);
        result = GENERAL_ERROR;
    }
    sqlite3_free(errorMessage);
    return result;
}

void SqliteHelper::SetWal() const
{
    if (db_ == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Do open data base first!");
        return;
    }
    auto statement = Prepare(PRAGMA_WAL_COMMAND);
    if (statement.Step() != Statement::State::ROW) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Set wal mode failed, errorMsg: %{public}s.", SpitError().c_str());
    } else {
        LOGI(ATM_DOMAIN, ATM_TAG, "Set wal mode success!");
    }
}

int32_t SqliteHelper::GetVersion() const __attribute__((no_sanitize("cfi")))
{
    if (db_ == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Do open data base first!");
        return GENERAL_ERROR;
    }
    auto statement = Prepare(PRAGMA_VERSION_COMMAND);
    int32_t version = 0;
    while (statement.Step() == Statement::State::ROW) {
        version = statement.GetColumnInt(0);
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Version: %{public}d", version);
    return version;
}

int32_t SqliteHelper::SetVersion(int32_t version) const
{
    if (db_ == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Do open data base first!");
        return GENERAL_ERROR;
    }
    auto statement = Prepare(PRAGMA_VERSION_COMMAND + " = " + std::to_string(version));
    auto stepRet = statement.Step();
    if (stepRet != Statement::State::DONE) {
        LOGE(ATM_DOMAIN, ATM_TAG, "SetVersion step failed, ret=%{public}d", static_cast<int32_t>(stepRet));
        return GENERAL_ERROR;
    }
    return RET_SUCCESS;
}

std::string SqliteHelper::SpitError() const
{
    if (db_ == nullptr) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Do open data base first!");
        return "";
    }
    return sqlite3_errmsg(db_);
}

bool SqliteHelper::IsCorruptCode(int32_t code) const
{
    return code == SQLITE_CORRUPT || code == SQLITE_NOTADB;
}

bool SqliteHelper::IsRetryableError(int32_t code) const
{
    return code == SQLITE_BUSY || code == SQLITE_LOCKED;
}

bool SqliteHelper::NeedRebuild(bool fullCheck) const
{
    if (db_ == nullptr) {
        return false;
    }
    int32_t code = sqlite3_errcode(db_);
    if (IsCorruptCode(code)) {
        LOGW(ATM_DOMAIN, ATM_TAG, "Corrupt detected by errcode=%{public}d, msg=%{public}s", code,
            sqlite3_errmsg(db_));
        return true;
    }
    if (!fullCheck) {
        return false;
    }
    auto statement = Prepare("PRAGMA integrity_check;");
    Statement::State state = statement.Step();
    int32_t checkCode = sqlite3_errcode(db_);
    if (state != Statement::State::ROW) {
        ReportDbException(DB_INTEGRITY_CHECK_FAILED, checkCode, dbPath_ + dbName_);
        bool corrupt = IsCorruptCode(checkCode);
        if (corrupt) {
            LOGW(ATM_DOMAIN, ATM_TAG, "integrity_check exec failed, code=%{public}d, msg=%{public}s", checkCode,
                sqlite3_errmsg(db_));
        }
        return corrupt;
    }
    std::string result = statement.GetColumnString(0);
    if (result != "ok") {
        LOGW(ATM_DOMAIN, ATM_TAG, "integrity_check not ok");
        return true;
    }
    return false;
}

int32_t SqliteHelper::Rebuild()
{
    int32_t result = 0;
    if (db_ != nullptr) {
        // Use close_v2 to always return SQLITE_OK instead of BUSY when statements remain.
        sqlite3_close_v2(db_);
        db_ = nullptr;
    }
    std::string f = dbPath_ + dbName_;
    (void)remove(f.c_str());
    (void)remove((f + "-wal").c_str());
    (void)remove((f + "-shm").c_str());
    Open(true);
    if (db_ == nullptr) {
        result = GENERAL_ERROR;
        LOGE(ATM_DOMAIN, ATM_TAG, "Rebuild failed, reopen db failed");
    } else {
        LOGI(ATM_DOMAIN, ATM_TAG, "Rebuild succeeded, db recreated");
    }
    ReportDbException(DB_REBUILD, result, dbPath_ + dbName_);
    return result;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
