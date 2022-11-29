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

#ifndef SQLITE_STORAGE_H
#define SQLITE_STORAGE_H

#include "data_storage.h"
#include "nocopyable.h"
#include "rwlock.h"
#include "sqlite_helper.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class SqliteStorage : public DataStorage, public SqliteHelper {
public:
    enum ExecuteResult { FAILURE = -1, SUCCESS };

    struct SqliteTable {
    public:
        std::string tableName_;
        std::vector<std::string> tableColumnNames_;
    };

    static SqliteStorage& GetInstance();

    ~SqliteStorage() override;

    int Add(const DataType type, const std::vector<GenericValues>& values) override;

    int Remove(const DataType type, const GenericValues& conditions) override;

    int Modify(const DataType type, const GenericValues& modifyValues, const GenericValues& conditions) override;

    int Find(const DataType type, std::vector<GenericValues>& results) override;

    int RefreshAll(const DataType type, const std::vector<GenericValues>& values) override;

    void OnCreate() override;
    void OnUpdate() override;

private:
    SqliteStorage();
    DISALLOW_COPY_AND_MOVE(SqliteStorage);

    std::map<DataType, SqliteTable> dataTypeToSqlTable_;
    OHOS::Utils::RWLock rwLock_;

    int CreateHapTokenInfoTable() const;
    int CreateNativeTokenInfoTable() const;
    int CreatePermissionDefinitionTable() const;
    int CreatePermissionStateTable() const;

    std::string CreateInsertPrepareSqlCmd(const DataType type) const;
    std::string CreateDeletePrepareSqlCmd(
        const DataType type, const std::vector<std::string>& columnNames = std::vector<std::string>()) const;
    std::string CreateUpdatePrepareSqlCmd(const DataType type, const std::vector<std::string>& modifyColumns,
        const std::vector<std::string>& conditionColumns) const;
    std::string CreateSelectPrepareSqlCmd(const DataType type) const;

private:
    inline static const std::string HAP_TOKEN_INFO_TABLE = "hap_token_info_table";
    inline static const std::string NATIVE_TOKEN_INFO_TABLE = "native_token_info_table";
    inline static const std::string PERMISSION_DEF_TABLE = "permission_definition_table";
    inline static const std::string PERMISSION_STATE_TABLE = "permission_state_table";
    inline static const std::string DATABASE_NAME = "access_token.db";
    inline static const std::string DATABASE_PATH = "/data/service/el1/public/access_token/";
    static const int DATABASE_VERSION = 1;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // SQLITE_STORAGE_H
