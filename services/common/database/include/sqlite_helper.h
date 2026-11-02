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

#ifndef SQLITE_HELPER_H
#define SQLITE_HELPER_H

#include <functional>
#include <string>

#include "statement.h"

#include "sqlite3sym.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class SqliteHelper {
public:
    explicit SqliteHelper(const std::string& dbName, const std::string& dbPath, int32_t version);
    virtual ~SqliteHelper();
    enum DataBaseVersion {
        VERISION_0 = 0,
        VERISION_1,
        VERISION_2,
        VERISION_3,
        VERISION_4,
        VERISION_5,
        VERISION_6
    };

    void Open(bool skipCheck = false);
    void Close();

    int32_t BeginTransaction() const;
    int32_t CommitTransaction() const;
    int32_t RollbackTransaction() const;

    Statement Prepare(const std::string& sql) const;
    int32_t ExecuteSql(const std::string& sql) const;
    std::string SpitError() const;

    bool NeedRebuild(bool fullCheck = false) const;
    int32_t Rebuild();

    virtual int32_t OnCreate() = 0;
    virtual int32_t OnUpdate(int32_t version) = 0;

protected:
    int32_t GetDbErrCode() const { return sqlite3_errcode(db_); }

private:
    inline static const std::string PRAGMA_VERSION_COMMAND = "PRAGMA user_version";
    inline static const std::string PRAGMA_WAL_COMMAND = "PRAGMA journal_mode=WAL";
    static const int32_t GENERAL_ERROR = -1;

    const std::string dbName_;
    const std::string dbPath_;
    int32_t currentVersion_;
    sqlite3* db_;

    bool IsCorruptCode(int32_t code) const;
    bool IsRetryableError(int32_t code) const;
    int32_t ExecuteWithRetry(int32_t sceneCode, const std::function<int32_t()>& action,
        int32_t targetVersion);
    void TryOnCreate();
    void TryOnUpdate(int32_t version);
    void SetWal() const;
    int32_t GetVersion() const;
    int32_t SetVersion(int32_t version) const;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // SQLITE_HELPER_H
