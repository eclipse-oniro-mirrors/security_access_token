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

#ifndef PERMISSION_USED_RECORD_DB_H
#define PERMISSION_USED_RECORD_DB_H

#include "generic_values.h"
#include "sqlite_helper.h"

#include "nocopyable.h"
#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct SqliteTable {
public:
    std::string tableName_;
    std::vector<std::string> tableColumnNames_;
};
class PermissionUsedRecordDb : public SqliteHelper {
public:
    enum DataType {
        PERMISSION_VISITOR = 0,
        PERMISSION_RECORD,
    };
    enum ExecuteResult { FAILURE = -1, SUCCESS };
    static PermissionUsedRecordDb& GetInstance();

    ~PermissionUsedRecordDb() override;

    int32_t Add(const DataType type, const std::vector<GenericValues>& values);
    int32_t Remove(const DataType type, const GenericValues& conditions);
    int32_t Find(const DataType type, std::vector<GenericValues>& results);
    int32_t FindByConditions(const DataType type, const GenericValues& andConditions,
        const GenericValues& orConditions, std::vector<GenericValues>& results);
    int32_t Modify(const DataType type, const GenericValues& modifyValues, const GenericValues& conditions);
    int32_t RefreshAll(const DataType type, const std::vector<GenericValues>& values);

    void OnCreate() override;
    void OnUpdate() override;

private:
    PermissionUsedRecordDb();
    DISALLOW_COPY_AND_MOVE(PermissionUsedRecordDb);

    std::map<DataType, SqliteTable> dataTypeToSqlTable_;
    OHOS::Utils::RWLock rwLock_;

    int32_t CreatePermissionVisitorTable() const;
    int32_t CreatePermissionRecordTable() const;

    std::string CreateInsertPrepareSqlCmd(const DataType type) const;
    std::string CreateDeletePrepareSqlCmd(
        const DataType type, const std::vector<std::string>& columnNames = std::vector<std::string>()) const;
    std::string CreateSelectPrepareSqlCmd(const DataType type) const;
    std::string CreateSelectByConditionPrepareSqlCmd(const DataType type,
        const std::vector<std::string>& andColumns, const std::vector<std::string>& orColumns) const;
    std::string CreateUpdatePrepareSqlCmd(const DataType type, const std::vector<std::string>& modifyColumns,
        const std::vector<std::string>& conditionColumns) const;

private:
    inline static const std::string PERMISSION_VISITOR_TABLE = "permission_visitor_table";
    inline static const std::string PERMISSION_RECORD_TABLE = "permission_record_table";
    inline static const std::string DATABASE_NAME = "permission_used_record.db";
    inline static const std::string DATABASE_PATH = "/data/service/el1/public/access_token/";
    static const int32_t DATABASE_VERSION = 1;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // PERMISSION_USED_RECORD_DB_H